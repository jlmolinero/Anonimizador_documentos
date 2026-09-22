import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pymupdf as fitz
from PIL import Image, PngImagePlugin

ROOT = Path(__file__).resolve().parents[1]
INSPECTOR = ROOT / "inspect_document_metadata.py"


def run_inspector(path: Path):
    result = subprocess.run(
        [sys.executable, str(INSPECTOR), str(path), "--json"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def test_missing_document_returns_clean_error(tmp_path):
    missing = tmp_path / "missing.pdf"

    result = subprocess.run(
        [sys.executable, str(INSPECTOR), "--json", str(missing)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Document not found" in result.stderr
    assert str(missing) in result.stderr
    assert "Traceback" not in result.stderr


def test_reports_pdf_metadata(tmp_path):
    sample = tmp_path / "sample.pdf"
    doc = fitz.open()
    doc.new_page().insert_text((72, 72), "hello")
    doc.set_metadata({"author": "Alice", "title": "Secret title"})
    doc.save(sample)
    doc.close()

    report = run_inspector(sample)

    assert report["kind"] == "pdf"
    assert report["metadata"]["author"] == "Alice"
    assert report["metadata"]["title"] == "Secret title"
    assert report["privacy_findings"]


def test_reports_extensionless_pdf_metadata(tmp_path):
    sample = tmp_path / "sample_without_extension"
    doc = fitz.open()
    doc.new_page().insert_text((72, 72), "hello")
    doc.set_metadata({"author": "Alice", "title": "Secret title"})
    doc.save(sample)
    doc.close()

    report = run_inspector(sample)

    assert report["kind"] == "pdf"
    assert report["metadata"]["author"] == "Alice"
    assert report["metadata"]["title"] == "Secret title"


def test_reports_image_metadata(tmp_path):
    sample = tmp_path / "sample.png"
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "Alice")
    Image.new("RGB", (10, 10), "white").save(sample, pnginfo=meta)

    report = run_inspector(sample)

    assert report["kind"] == "image"
    assert report["metadata"]["Author"] == "Alice"
    assert report["privacy_findings"]


def test_reports_extensionless_image_metadata(tmp_path):
    sample = tmp_path / "png_without_extension"
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "Alice")
    Image.new("RGB", (10, 10), "white").save(sample, format="PNG", pnginfo=meta)

    report = run_inspector(sample)

    assert report["kind"] == "image"
    assert report["metadata"]["Author"] == "Alice"


def test_reports_office_metadata(tmp_path):
    sample = tmp_path / "sample.docx"
    with zipfile.ZipFile(sample, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>")
        zf.writestr("docProps/core.xml", """
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
              xmlns:dc="http://purl.org/dc/elements/1.1/">
              <dc:title>Secret document</dc:title><dc:creator>Alice</dc:creator>
            </cp:coreProperties>
        """)
        zf.writestr("word/document.xml", "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'/>")

    report = run_inspector(sample)

    assert report["kind"] == "office"
    assert report["metadata"]["docProps/core.xml"]["creator"] == "Alice"
    assert report["metadata"]["docProps/core.xml"]["title"] == "Secret document"
    assert report["privacy_findings"]


def test_reports_extensionless_office_metadata(tmp_path):
    sample = tmp_path / "office_without_extension"
    with zipfile.ZipFile(sample, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>")
        zf.writestr("docProps/core.xml", """
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
              xmlns:dc="http://purl.org/dc/elements/1.1/">
              <dc:title>Secret document</dc:title><dc:creator>Alice</dc:creator>
            </cp:coreProperties>
        """)
        zf.writestr("word/document.xml", "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'/>")

    report = run_inspector(sample)

    assert report["kind"] == "office"
    assert report["metadata"]["docProps/core.xml"]["creator"] == "Alice"
