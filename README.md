# Document Anonymizer

A local-first Python tool for sanitizing documents before sharing them. It creates new anonymized copies of PDF, Office and image files while removing metadata and common hidden data that can leak identity, file paths, comments, revisions, formulas or embedded objects.

> No automated anonymization process is perfect. Always inspect the output and visually review sensitive documents before publishing or sending them.

## Supported formats

| Family | Extensions | Main cleanup actions |
| --- | --- | --- |
| PDF | `.pdf` | Metadata, XML metadata, JavaScript, attachments, links, annotations, forms, hidden text, optional visible PII redaction, optional rasterization |
| Office Open XML | `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`, `.pptm` | Core/app/custom properties, macros, comments, revisions, hidden content, external links, embedded media metadata, Excel formulas/sheet names by default |
| Images | `.jpg`, `.jpeg`, `.png`, `.tif`, `.tiff`, `.webp` | EXIF/XMP/ICC/text chunks, optional manual black masks |

Macro-enabled Office files are written back without macro payloads by default.

## Install

Use a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements_anonimizador.txt
```

For development and tests:

```bash
pip install -r requirements-dev.txt
```

## Basic usage

Sanitize one file into an output directory:

```bash
python anonimizar_documentos.py input.pdf sanitized/
```

Sanitize every supported file in a directory:

```bash
python anonimizar_documentos.py documents/ sanitized/ --recursive
```

Overwrite existing output files:

```bash
python anonimizar_documentos.py documents/ sanitized/ --recursive --overwrite
```

Randomize output file names so the original name is not leaked:

```bash
python anonimizar_documentos.py documents/ sanitized/ --recursive --randomize-names
```

The tool writes a local JSON report to the output directory by default:

```text
_LOCAL_ONLY_anonymization_report.json
```

Do not share that report publicly: it contains original file names and paths.

## Redacting visible PII

Automatic PII redaction can find common patterns such as email addresses, URLs, IPv4 addresses, IBANs, Spanish DNI/NIE values, filesystem paths and phone numbers:

```bash
python anonimizar_documentos.py input.pdf sanitized/ --auto-pii
```

You can also provide explicit terms, one per line:

```bash
python anonimizar_documentos.py documents/ sanitized/ --recursive --terms sensitive_terms.txt
```

Example `sensitive_terms.txt`:

```text
Jane Smith
ACME Internal Project
customer-12345
```

For images and scanned PDFs, visible personal data is pixels, not metadata. Use manual masks and review the result visually.

## Manual masks

Masks are supplied as JSON. Image masks use `[x1, y1, x2, y2]`. PDF masks use `[page, x1, y1, x2, y2]` with 1-based page numbers.

```json
{
  "scan.png": [[10, 20, 220, 70]],
  "contract.pdf": [[1, 72, 120, 300, 150]]
}
```

Run with:

```bash
python anonimizar_documentos.py documents/ sanitized/ --recursive --masks masks.json
```

## PDF modes

Default mode is `raster`, which is the safest structural option because it renders pages to pixels and rebuilds a new PDF:

```bash
python anonimizar_documentos.py input.pdf sanitized/ --pdf-mode raster --pdf-dpi 180
```

Use `scrub` only when you need to keep vector/text structure. It is more convenient but weaker from a privacy perspective:

```bash
python anonimizar_documentos.py input.pdf sanitized/ --pdf-mode scrub
```

## Office options

By default the tool removes privacy-sensitive Office features aggressively. You can opt back into specific behavior when needed:

```bash
# Keep Office external links/relationships
python anonimizar_documentos.py file.docx sanitized/ --keep-external-links

# Keep hidden Excel sheets, rows and columns
python anonimizar_documentos.py workbook.xlsx sanitized/ --keep-hidden-excel

# Keep original Excel sheet names
python anonimizar_documentos.py workbook.xlsx sanitized/ --keep-sheet-names

# Keep Excel formulas and defined names
python anonimizar_documentos.py workbook.xlsx sanitized/ --keep-formulas
```

## Inspecting metadata

Use the metadata inspector before and after anonymization to see what a document exposes:

```bash
python inspect_document_metadata.py original.pdf
python inspect_document_metadata.py sanitized/original_anon.pdf
```

Machine-readable JSON output:

```bash
python inspect_document_metadata.py sanitized/original_anon.pdf --json
```

The inspector supports PDF, Office Open XML and image files. It reports direct metadata, embedded PDF files, XML metadata streams and notable Office parts such as comments, custom XML, external links, embedded objects, signatures and macro payloads.

## Recommended verification workflow

1. Inspect the original document:

   ```bash
   python inspect_document_metadata.py documents/report.docx
   ```

2. Sanitize it:

   ```bash
   python anonimizar_documentos.py documents/report.docx sanitized/ --auto-pii --randomize-names
   ```

3. Inspect the output:

   ```bash
   python inspect_document_metadata.py sanitized/anon_XXXXXXXXXXXX.docx
   ```

4. Open the sanitized document and visually review all pages/slides/sheets.

5. Keep the local report private.

## Tests

Install development dependencies and run the test suite:

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

The tests cover metadata inspection for PDF, images and Office files, plus a sanitization smoke test that verifies PNG metadata is removed.

## Limitations

- Automatic PII redaction is heuristic and can miss values or redact false positives.
- Images, screenshots and scanned PDFs may contain sensitive text as pixels; use manual masks.
- Vector PDF scrubbing is weaker than rasterization.
- EMF/WMF embedded Office graphics are preserved because Pillow cannot safely rewrite them.
- You should always review the output manually before sharing it.

## License

MIT License. See [`LICENSE`](LICENSE).
