#!/usr/bin/env python3
"""Inspect document metadata for privacy review and anonymization checks."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

import pymupdf as fitz
from lxml import etree
from PIL import Image

OFFICE_EXTS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"}
PDF_EXTS = {".pdf"}
SENSITIVE_KEYS = {
    "author",
    "creator",
    "producer",
    "subject",
    "title",
    "keywords",
    "company",
    "manager",
    "lastmodifiedby",
    "created",
    "modified",
    "creationdate",
    "moddate",
    "software",
    "make",
    "model",
    "gpsinfo",
    "artist",
    "copyright",
}


def detect_document_kind(path: Path) -> str | None:
    """Detect supported document kind from extension, then file signature."""
    suffix = path.suffix.lower()
    if suffix in PDF_EXTS:
        return "pdf"
    if suffix in IMAGE_EXTS:
        return "image"
    if suffix in OFFICE_EXTS:
        return "office"

    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError:
        return None

    if header.startswith(b"%PDF-"):
        return "pdf"
    if header.startswith(b"PK\x03\x04") and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
        except zipfile.BadZipFile:
            return None
        if "[Content_Types].xml" in names and any(
            name.startswith(("word/", "xl/", "ppt/")) for name in names
        ):
            return "office"
    try:
        with Image.open(path) as image:
            image.verify()
        return "image"
    except Exception:
        return None


def _localname(tag: str) -> str:
    try:
        return etree.QName(tag).localname
    except Exception:
        return tag


def _non_empty(value: Any) -> bool:
    return value not in (None, "", {}, [])


def _stringify(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def inspect_pdf(path: Path) -> dict[str, Any]:
    doc = fitz.open(path)
    metadata = {key: value for key, value in doc.metadata.items() if _non_empty(value)}
    has_xml_metadata = False
    try:
        has_xml_metadata = bool(doc.get_xml_metadata())
    except Exception:
        pass
    embedded_files = []
    try:
        embedded_files = [doc.embfile_info(i).get("filename", f"embedded_{i}") for i in range(doc.embfile_count())]
    except Exception:
        pass
    pages = doc.page_count
    doc.close()
    return {
        "kind": "pdf",
        "path": str(path),
        "pages": pages,
        "metadata": metadata,
        "embedded_files": embedded_files,
        "has_xml_metadata": has_xml_metadata,
    }


def inspect_image(path: Path) -> dict[str, Any]:
    with Image.open(path) as image:
        metadata = {key: _stringify(value) for key, value in image.info.items() if _non_empty(value)}
        exif = image.getexif()
        if exif:
            for key, value in exif.items():
                metadata[f"EXIF:{key}"] = _stringify(value)
        return {
            "kind": "image",
            "path": str(path),
            "format": image.format,
            "size": list(image.size),
            "mode": image.mode,
            "metadata": metadata,
        }


def _xml_metadata(data: bytes) -> dict[str, str]:
    parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
    root = etree.fromstring(data, parser)
    out: dict[str, str] = {}
    for element in root.iter():
        text = (element.text or "").strip()
        if text:
            out[_localname(element.tag)] = text
        for attr, value in element.attrib.items():
            if value:
                out[f"{_localname(element.tag)}@{_localname(attr)}"] = value
    return out


def inspect_office(path: Path) -> dict[str, Any]:
    metadata: dict[str, dict[str, str]] = {}
    notable_parts: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        for name in names:
            lower = name.lower()
            if lower.startswith("docprops/") and lower.endswith(".xml"):
                metadata[name] = _xml_metadata(zf.read(name))
            if any(token in lower for token in (
                "vbaproject.bin",
                "customxml/",
                "comments",
                "threadedcomments",
                "person",
                "externallinks/",
                "embeddings/",
                "_xmlsignatures/",
            )):
                notable_parts.append(name)
    return {
        "kind": "office",
        "path": str(path),
        "metadata": metadata,
        "notable_parts": notable_parts,
    }


def privacy_findings(report: dict[str, Any]) -> list[str]:
    findings: list[str] = []

    def visit(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                low = key.lower().replace(" ", "")
                if _non_empty(child) and (low in SENSITIVE_KEYS or any(token in low for token in SENSITIVE_KEYS)):
                    findings.append(f"{prefix}{key}: {child}")
                visit(f"{prefix}{key}.", child)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(f"{prefix}{index}.", child)

    visit("", report.get("metadata", {}))
    if report.get("embedded_files"):
        findings.append(f"embedded_files: {report['embedded_files']}")
    if report.get("has_xml_metadata"):
        findings.append("PDF XML metadata stream is present")
    if report.get("notable_parts"):
        findings.append(f"notable Office parts: {report['notable_parts']}")
    return findings


def inspect_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise IsADirectoryError(path)

    kind = detect_document_kind(path)
    if kind == "pdf":
        report = inspect_pdf(path)
    elif kind == "image":
        report = inspect_image(path)
    elif kind == "office":
        report = inspect_office(path)
    else:
        suffix = path.suffix.lower()
        detail = suffix or "no extension and unknown file signature"
        raise ValueError(f"Unsupported file type: {detail}")
    report["privacy_findings"] = privacy_findings(report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect PDF, Office and image metadata before or after anonymization.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("document", type=Path, help="Document to inspect")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    return parser


def print_text(report: dict[str, Any]) -> None:
    print(f"File: {report['path']}")
    print(f"Type: {report['kind']}")
    metadata = report.get("metadata") or {}
    if metadata:
        print("\nMetadata:")
        print(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("\nMetadata: none detected")
    if report.get("embedded_files"):
        print(f"\nEmbedded files: {', '.join(report['embedded_files'])}")
    if report.get("notable_parts"):
        print("\nNotable Office parts:")
        for part in report["notable_parts"]:
            print(f"- {part}")
    findings = report.get("privacy_findings") or []
    if findings:
        print("\nPrivacy findings:")
        for finding in findings:
            print(f"- {finding}")
    else:
        print("\nPrivacy findings: none detected")


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = inspect_document(args.document)
    except FileNotFoundError:
        print(f"Error: Document not found: {args.document}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"Error: Expected a document file, got a directory: {args.document}", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"Error: Permission denied while reading: {args.document}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except (fitz.FileDataError, zipfile.BadZipFile, OSError) as exc:
        print(f"Error: Could not inspect document: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print_text(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
