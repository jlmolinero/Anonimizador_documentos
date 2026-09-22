from pathlib import Path

from PIL import Image, PngImagePlugin

from anonimizar_documentos import Redactor, process_one
from inspect_document_metadata import inspect_document


class Args:
    randomize_names = False
    overwrite = False
    pdf_mode = "raster"
    pdf_dpi = 120
    keep_external_links = False
    keep_hidden_excel = False
    keep_sheet_names = False
    keep_formulas = False


def test_image_sanitization_removes_png_metadata(tmp_path):
    source = tmp_path / "source.png"
    output_dir = tmp_path / "out"
    png_info = PngImagePlugin.PngInfo()
    png_info.add_text("Author", "Alice")
    png_info.add_text("Comment", "Sensitive note")
    Image.new("RGB", (10, 10), "white").save(source, pnginfo=png_info)

    report = process_one(source, output_dir, Args(), Redactor([], False), {})
    inspected = inspect_document(Path(report.output))

    assert inspected["metadata"] == {}
    assert inspected["privacy_findings"] == []
    assert Path(report.output).name == "source_anon.png"
