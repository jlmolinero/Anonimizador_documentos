import json
from pathlib import Path

from PIL import Image, PngImagePlugin

from web_metadata_app import (
    WebAppConfig,
    analyze_cached_file,
    build_parser,
    cache_paths,
    clear_cache,
    delete_cached_file,
    display_url,
    network_hint,
    render_home,
    save_upload,
    sanitize_original_filename,
    sanitize_uploaded_file,
)


def test_sanitize_original_filename_blocks_paths_and_empty_names():
    assert sanitize_original_filename("../../secret.pdf") == "secret.pdf"
    assert sanitize_original_filename("C:\\Users\\Alice\\secret.pdf") == "secret.pdf"
    assert sanitize_original_filename("   ") == "document"


def test_upload_analyze_sanitize_and_delete_workflow(tmp_path):
    cache = tmp_path / "cache"
    source = tmp_path / "source.png"
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Author", "Alice")
    Image.new("RGB", (10, 10), "white").save(source, pnginfo=metadata)

    stored = save_upload(cache, "../source.png", source.read_bytes())
    original_report = analyze_cached_file(cache, stored.name)

    assert original_report["kind"] == "image"
    assert original_report["metadata"]["Author"] == "Alice"

    sanitized, sanitized_report = sanitize_uploaded_file(cache, stored.name)

    assert sanitized.exists()
    assert sanitized_report["metadata"] == {}
    assert sanitized_report["privacy_findings"] == []

    delete_cached_file(cache, stored.name)

    assert not stored.exists()
    assert not sanitized.exists()


def test_clear_cache_removes_uploads_and_processed_files(tmp_path):
    cache = tmp_path / "cache"
    paths = cache_paths(cache)
    paths.uploads.mkdir(parents=True)
    paths.processed.mkdir(parents=True)
    (paths.uploads / "a.txt").write_text("x", encoding="utf-8")
    (paths.processed / "b.txt").write_text("y", encoding="utf-8")

    clear_cache(cache)

    assert paths.root.exists()
    assert paths.uploads.exists()
    assert paths.processed.exists()
    assert list(paths.uploads.iterdir()) == []
    assert list(paths.processed.iterdir()) == []


def test_config_can_be_serialized_for_template(tmp_path):
    config = WebAppConfig(cache_dir=tmp_path / "cache", host="0.0.0.0", port=8765)

    data = json.loads(config.to_json())

    assert data["cache_dir"] == str(tmp_path / "cache")
    assert data["host"] == "0.0.0.0"
    assert data["port"] == 8765


def test_default_web_host_is_lan_accessible():
    args = build_parser().parse_args([])

    assert args.host == "0.0.0.0"
    assert display_url("0.0.0.0", 8000) == "http://127.0.0.1:8000"
    assert "other computers" in network_hint("0.0.0.0", 8000).lower()


def test_home_page_has_polished_layout_and_security_copy(tmp_path):
    page = render_home(tmp_path / "cache").decode("utf-8")

    assert "Document Metadata Workbench" in page
    assert "hero" in page
    assert "LAN-ready" in page
    assert "Clear all cache" in page
