#!/usr/bin/env python3
"""Local web UI for inspecting and cleaning document metadata."""

from __future__ import annotations

import argparse
import html
import json
import mimetypes
import shutil
import uuid
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, unquote, urlparse

from anonimizar_documentos import Redactor, process_one
from inspect_document_metadata import inspect_document

DEFAULT_CACHE_DIR = Path(".web_cache")


@dataclass(frozen=True)
class CachePaths:
    root: Path
    uploads: Path
    processed: Path


@dataclass(frozen=True)
class WebAppConfig:
    cache_dir: Path = DEFAULT_CACHE_DIR
    host: str = "127.0.0.1"
    port: int = 8000

    def to_json(self) -> str:
        return json.dumps({"cache_dir": str(self.cache_dir), "host": self.host, "port": self.port})


def cache_paths(cache_dir: Path) -> CachePaths:
    root = cache_dir.resolve()
    return CachePaths(root=root, uploads=root / "uploads", processed=root / "processed")


def ensure_cache(cache_dir: Path) -> CachePaths:
    paths = cache_paths(cache_dir)
    paths.uploads.mkdir(parents=True, exist_ok=True)
    paths.processed.mkdir(parents=True, exist_ok=True)
    return paths


def sanitize_original_filename(filename: str) -> str:
    normalized = filename.replace("\\", "/").split("/")[-1].strip()
    if not normalized:
        return "document"
    safe = "".join(ch if ch.isalnum() or ch in ".-_ " else "_" for ch in normalized)
    safe = safe.strip(" .")
    return safe or "document"


def _resolve_cached_file(cache_dir: Path, file_id: str) -> Path:
    paths = ensure_cache(cache_dir)
    name = sanitize_original_filename(unquote(file_id))
    candidate = (paths.uploads / name).resolve()
    if candidate.parent != paths.uploads:
        raise ValueError("Invalid cached file id")
    if not candidate.is_file():
        raise FileNotFoundError(name)
    return candidate


def save_upload(cache_dir: Path, original_filename: str, content: bytes) -> Path:
    paths = ensure_cache(cache_dir)
    safe_name = sanitize_original_filename(original_filename)
    stored = paths.uploads / f"{uuid.uuid4().hex}_{safe_name}"
    stored.write_bytes(content)
    return stored


def analyze_cached_file(cache_dir: Path, file_id: str) -> dict:
    return inspect_document(_resolve_cached_file(cache_dir, file_id))


def _process_args() -> SimpleNamespace:
    return SimpleNamespace(
        randomize_names=False,
        overwrite=True,
        pdf_mode="raster",
        pdf_dpi=180,
        keep_external_links=False,
        keep_hidden_excel=False,
        keep_sheet_names=False,
        keep_formulas=False,
    )


def sanitize_uploaded_file(cache_dir: Path, file_id: str) -> tuple[Path, dict]:
    paths = ensure_cache(cache_dir)
    source = _resolve_cached_file(cache_dir, file_id)
    report = process_one(source, paths.processed, _process_args(), Redactor([], False), {})
    output = Path(report.output)
    return output, inspect_document(output)


def _processed_matches(cache_dir: Path, uploaded: Path) -> list[Path]:
    paths = ensure_cache(cache_dir)
    expected = paths.processed / f"{uploaded.stem}_anon{uploaded.suffix.lower()}"
    matches = [expected] if expected.exists() else []
    report = paths.processed / "_LOCAL_ONLY_anonymization_report.json"
    if report.exists():
        matches.append(report)
    return matches


def delete_cached_file(cache_dir: Path, file_id: str) -> None:
    uploaded = _resolve_cached_file(cache_dir, file_id)
    for path in _processed_matches(cache_dir, uploaded):
        path.unlink(missing_ok=True)
    uploaded.unlink(missing_ok=True)


def clear_cache(cache_dir: Path) -> None:
    paths = cache_paths(cache_dir)
    if paths.root.exists():
        shutil.rmtree(paths.root)
    ensure_cache(cache_dir)


def list_cached_files(cache_dir: Path) -> list[Path]:
    paths = ensure_cache(cache_dir)
    return sorted((p for p in paths.uploads.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)


def _html_page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; color: #17202a; }}
    main {{ max-width: 980px; margin: auto; }}
    .card {{ border: 1px solid #d7dde5; border-radius: 12px; padding: 1rem; margin: 1rem 0; background: #fbfcfe; }}
    .actions {{ display: flex; gap: .5rem; flex-wrap: wrap; margin-top: .75rem; }}
    button, input[type=file] {{ font: inherit; }}
    button, .button {{ background: #0f766e; color: white; border: 0; padding: .55rem .8rem; border-radius: 8px; text-decoration: none; cursor: pointer; }}
    button.danger {{ background: #b91c1c; }}
    pre {{ overflow: auto; background: #111827; color: #e5e7eb; padding: 1rem; border-radius: 8px; }}
    .muted {{ color: #667085; }}
    .error {{ color: #b91c1c; font-weight: 600; }}
  </style>
</head>
<body><main>{body}</main></body>
</html>""".encode("utf-8")


def _render_home(cache_dir: Path, message: str = "") -> bytes:
    files = list_cached_files(cache_dir)
    rows = []
    for path in files:
        quoted = quote(path.name)
        rows.append(f"""
        <div class="card">
          <strong>{html.escape(path.name)}</strong><br>
          <span class="muted">{path.stat().st_size} bytes</span>
          <div class="actions">
            <a class="button" href="/file/{quoted}">Inspect</a>
            <a class="button" href="/download/original/{quoted}">Download original</a>
            <form method="post" action="/file/{quoted}/delete"><button class="danger" type="submit">Delete</button></form>
          </div>
        </div>""")
    listing = "".join(rows) or "<p class='muted'>No cached files.</p>"
    notice = f"<p class='error'>{html.escape(message)}</p>" if message else ""
    body = f"""
    <h1>Document Metadata Inspector</h1>
    <p>Upload a PDF, Office document or image to inspect metadata, optionally create a sanitized copy, and delete cached files when finished.</p>
    {notice}
    <div class="card">
      <form method="post" action="/upload" enctype="multipart/form-data">
        <input type="file" name="document" required>
        <button type="submit">Upload and inspect</button>
      </form>
    </div>
    <div class="actions">
      <form method="post" action="/cache/clear"><button class="danger" type="submit">Clear all cache</button></form>
    </div>
    <h2>Cached files</h2>
    {listing}
    """
    return _html_page("Document Metadata Inspector", body)


def _render_file(cache_dir: Path, file_id: str, sanitized_report: dict | None = None, error: str = "") -> bytes:
    uploaded = _resolve_cached_file(cache_dir, file_id)
    report = inspect_document(uploaded)
    quoted = quote(uploaded.name)
    paths = ensure_cache(cache_dir)
    sanitized_path = paths.processed / f"{uploaded.stem}_anon{uploaded.suffix.lower()}"
    sanitized_block = ""
    if sanitized_report:
        sanitized_block = f"""
        <h2>Sanitized copy metadata</h2>
        <p><a class="button" href="/download/processed/{quote(sanitized_path.name)}">Download sanitized copy</a></p>
        <pre>{html.escape(json.dumps(sanitized_report, ensure_ascii=False, indent=2, sort_keys=True))}</pre>
        """
    elif sanitized_path.exists():
        sanitized_block = f"<p><a class='button' href='/download/processed/{quote(sanitized_path.name)}'>Download existing sanitized copy</a></p>"
    notice = f"<p class='error'>{html.escape(error)}</p>" if error else ""
    body = f"""
    <p><a href="/">← Back</a></p>
    <h1>{html.escape(uploaded.name)}</h1>
    {notice}
    <div class="actions">
      <form method="post" action="/file/{quoted}/sanitize"><button type="submit">Create sanitized copy</button></form>
      <a class="button" href="/download/original/{quoted}">Download original</a>
      <form method="post" action="/file/{quoted}/delete"><button class="danger" type="submit">Delete this file from cache</button></form>
      <form method="post" action="/cache/clear"><button class="danger" type="submit">Clear all cache</button></form>
    </div>
    <h2>Original metadata</h2>
    <pre>{html.escape(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))}</pre>
    {sanitized_block}
    """
    return _html_page(uploaded.name, body)


class MetadataRequestHandler(BaseHTTPRequestHandler):
    cache_dir: Path = DEFAULT_CACHE_DIR

    def _send_html(self, content: bytes, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def _send_error_page(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        self._send_html(_render_home(self.cache_dir, message), status)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                self._send_html(_render_home(self.cache_dir))
                return
            if parsed.path.startswith("/file/"):
                file_id = parsed.path.removeprefix("/file/")
                self._send_html(_render_file(self.cache_dir, file_id))
                return
            if parsed.path.startswith("/download/"):
                self._send_download(parsed.path)
                return
            self._send_error_page("Not found", HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_error_page(str(exc))

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/upload":
                self._handle_upload()
                return
            if parsed.path == "/cache/clear":
                clear_cache(self.cache_dir)
                self._redirect("/")
                return
            if parsed.path.startswith("/file/") and parsed.path.endswith("/sanitize"):
                file_id = parsed.path.removeprefix("/file/").removesuffix("/sanitize")
                self._handle_sanitize(file_id)
                return
            if parsed.path.startswith("/file/") and parsed.path.endswith("/delete"):
                file_id = parsed.path.removeprefix("/file/").removesuffix("/delete")
                delete_cached_file(self.cache_dir, file_id)
                self._redirect("/")
                return
            self._send_error_page("Not found", HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_error_page(str(exc))

    def _handle_upload(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_error_page("Expected multipart form upload")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_error_page("Invalid upload length")
            return
        body = self.rfile.read(length)
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + content_type.encode("utf-8") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
        )
        filename = ""
        content = b""
        for part in message.iter_parts():
            if part.get_param("name", header="content-disposition") != "document":
                continue
            filename = part.get_filename() or ""
            payload = part.get_payload(decode=True)
            content = payload if isinstance(payload, bytes) else b""
            break
        if not filename:
            self._send_error_page("No file was uploaded")
            return
        if not content:
            self._send_error_page("Uploaded file is empty")
            return
        stored = save_upload(self.cache_dir, filename, content)
        self._redirect(f"/file/{quote(stored.name)}")

    def _handle_sanitize(self, file_id: str) -> None:
        _path, report = sanitize_uploaded_file(self.cache_dir, file_id)
        self._send_html(_render_file(self.cache_dir, file_id, sanitized_report=report))

    def _send_download(self, path: str) -> None:
        parts = path.strip("/").split("/", 2)
        if len(parts) != 3:
            self._send_error_page("Invalid download URL", HTTPStatus.NOT_FOUND)
            return
        _, area, raw_name = parts
        paths = ensure_cache(self.cache_dir)
        base = paths.uploads if area == "original" else paths.processed if area == "processed" else None
        if base is None:
            self._send_error_page("Invalid download area", HTTPStatus.NOT_FOUND)
            return
        name = sanitize_original_filename(unquote(raw_name))
        target = (base / name).resolve()
        if target.parent != base or not target.is_file():
            self._send_error_page("File not found", HTTPStatus.NOT_FOUND)
            return
        data = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
        self.end_headers()
        self.wfile.write(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Start a local web UI to inspect and sanitize document metadata.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8000, help="Bind port")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR, help="Directory used for uploaded and processed files")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = WebAppConfig(cache_dir=args.cache_dir, host=args.host, port=args.port)
    ensure_cache(config.cache_dir)

    class Handler(MetadataRequestHandler):
        cache_dir = config.cache_dir

    server = ThreadingHTTPServer((config.host, config.port), Handler)
    print(f"Metadata web UI running at http://{config.host}:{config.port}")
    print(f"Cache directory: {config.cache_dir.resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping metadata web UI")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
