#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Document anonymizer/sanitizer.

Formats:
  PDF
  DOCX / XLSX / PPTX
  DOCM / XLSM / PPTM (se eliminan macros por defecto)
  JPG / JPEG / PNG / TIFF / WEBP

Dependencies:
  pip install pymupdf pillow lxml

IMPORTANT:
- Structural sanitization removes metadata and many hidden contents.
- Automatic PII redaction is heuristic and can have false positives or negatives.
- Sensitive text inside images requires manual masks (--masks) or visual review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from io import BytesIO
import os
import posixpath
import re
import shutil
import sys
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional

import pymupdf as fitz  # PyMuPDF
from lxml import etree
from PIL import Image, ImageDraw, ImageSequence, ImageOps


OFFICE_EXTS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"}
SUPPORTED_EXTS = {".pdf"} | OFFICE_EXTS | IMAGE_EXTS

FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
REDACTION = "[REDACTADO]"

REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

NS = {"rel": REL_NS, "ct": CT_NS, "r": R_NS, "w": W_NS, "p": P_NS, "a": A_NS, "s": S_NS}


@dataclass
class Report:
    source: str
    output: str
    kind: str
    removed: list[str] = field(default_factory=list)
    redactions: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    sha256: Optional[str] = None

    def bump(self, key: str, n: int = 1):
        self.redactions[key] = self.redactions.get(key, 0) + n


class Redactor:
    def __init__(self, terms: list[str], auto_pii: bool):
        self.patterns: list[tuple[str, re.Pattern[str]]] = []
        for term in terms:
            term = term.strip()
            if term:
                self.patterns.append((f"term:{term}", re.compile(re.escape(term), re.IGNORECASE)))

        if auto_pii:
            # Deliberately conservative; it is not a replacement for human review.
            defs = {
                "email": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                "url": r"\bhttps?://[^\s<>\"]+",
                "ipv4": r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b",
                "iban": r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b",
                "dni_nie_es": r"\b(?:\d{8}[A-HJ-NP-TV-Z]|[XYZ]\d{7}[A-HJ-NP-TV-Z])\b",
                "user_path": r"(?:[A-Z]:\\Users\\[^\\\s]+|/Users/[^/\s]+|/home/[^/\s]+)",
                "phone": r"(?<!\w)(?:\+?\d[\d .()/-]{7,}\d)(?!\w)",
            }
            for name, rx in defs.items():
                self.patterns.append((name, re.compile(rx, re.IGNORECASE)))

    def redact_text(self, text: str, report: Report) -> str:
        if not text or not self.patterns:
            return text
        out = text
        for name, pat in self.patterns:
            out, n = pat.subn(REDACTION, out)
            if n:
                report.bump(name, n)
        return out

    def find_literals(self, text: str, report: Report) -> list[str]:
        """Devuelve cadenas concretas a buscar/redactar en PDF."""
        found: list[str] = []
        if not text:
            return found
        seen = set()
        for name, pat in self.patterns:
            for m in pat.finditer(text):
                value = m.group(0)
                if value and value not in seen:
                    seen.add(value)
                    found.append(value)
                    report.bump(name, 1)
        return found


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_output_name(src: Path, randomize: bool) -> str:
    if randomize:
        return f"anon_{uuid.uuid4().hex[:12]}{src.suffix.lower()}"
    return f"{src.stem}_anon{src.suffix.lower()}"


def load_terms(path: Optional[Path]) -> list[str]:
    if not path:
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def load_masks(path: Optional[Path]) -> dict[str, list[list[int]]]:
    if not path:
        return {}
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("The masks file must be a JSON object.")
    return obj


def copy_zipinfo(original: zipfile.ZipInfo) -> zipfile.ZipInfo:
    z = zipfile.ZipInfo(original.filename, FIXED_ZIP_TIME)
    z.compress_type = zipfile.ZIP_DEFLATED
    z.create_system = 3
    z.external_attr = 0o600 << 16
    z.flag_bits = 0
    z.extra = b""
    z.comment = b""
    return z


def xml_parse(data: bytes):
    parser = etree.XMLParser(remove_blank_text=False, recover=True, resolve_entities=False, no_network=True)
    return etree.fromstring(data, parser)


def xml_bytes(root) -> bytes:
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=None)


def localname(tag: str) -> str:
    try:
        return etree.QName(tag).localname
    except Exception:
        return tag


def normalize_part(path: str) -> str:
    return path.lstrip("/")


def rels_source_part(rels_path: str) -> str:
    p = PurePosixPath(rels_path)
    if rels_path == "_rels/.rels":
        return ""
    name = p.name
    if not name.endswith(".rels"):
        return ""
    source_name = name[:-5]
    base = p.parent.parent
    return str(base / source_name)


def rels_path_for_part(part: str) -> str:
    if not part:
        return "_rels/.rels"
    p = PurePosixPath(part)
    return str(p.parent / "_rels" / f"{p.name}.rels")


def remove_relationship_ids(parts: dict[str, bytes], source_part: str, rids: set[str], report: Report):
    if not rids:
        return
    rel_name = rels_path_for_part(source_part)
    if rel_name not in parts:
        return
    try:
        root = xml_parse(parts[rel_name])
    except Exception:
        return
    changed = False
    for rel in list(root):
        if localname(rel.tag) == "Relationship" and rel.get("Id") in rids:
            report.removed.append(f"Office internal relationship removed: {source_part} -> {rel.get('Target','')}")
            root.remove(rel)
            changed = True
    if changed:
        parts[rel_name] = xml_bytes(root)

def resolve_rel_target(rels_path: str, target: str) -> str:
    if target.startswith("/"):
        return normalize_part(target)
    source = rels_source_part(rels_path)
    base_dir = posixpath.dirname(source)
    return normalize_part(posixpath.normpath(posixpath.join(base_dir, target)))


def target_matches_removed(target: str, removed: set[str]) -> bool:
    t = normalize_part(target)
    if t in removed:
        return True
    prefix = t.rstrip("/") + "/"
    return any(x.startswith(prefix) for x in removed)


def strip_relationships(parts: dict[str, bytes], removed: set[str], remove_external: bool, report: Report):
    for name in list(parts):
        if not name.endswith(".rels"):
            continue
        try:
            root = xml_parse(parts[name])
        except Exception:
            continue
        changed = False
        for rel in list(root):
            if localname(rel.tag) != "Relationship":
                continue
            target = rel.get("Target", "")
            mode = rel.get("TargetMode", "")
            remove = False
            if remove_external and mode.lower() == "external":
                remove = True
                report.removed.append(f"external relationship: {target}")
            elif mode.lower() != "external":
                resolved = resolve_rel_target(name, target)
                if target_matches_removed(resolved, removed):
                    remove = True
            if remove:
                root.remove(rel)
                changed = True
        if changed:
            parts[name] = xml_bytes(root)


def strip_content_types(parts: dict[str, bytes], removed: set[str]):
    name = "[Content_Types].xml"
    if name not in parts:
        return
    try:
        root = xml_parse(parts[name])
    except Exception:
        return
    changed = False
    for child in list(root):
        if localname(child.tag) != "Override":
            continue
        part_name = normalize_part(child.get("PartName", ""))
        if target_matches_removed(part_name, removed):
            root.remove(child)
            changed = True
    if changed:
        parts[name] = xml_bytes(root)


def office_removed_parts(names: Iterable[str], ext: str) -> set[str]:
    removed = set()
    for n in names:
        low = n.lower()
        # Propiedades y datos personalizados.
        if low.startswith("docprops/") or low.startswith("customxml/"):
            removed.add(n)
            continue
        # Macros, controles, OLE, adjuntos/embebidos y firmas.
        if any(seg in low for seg in (
            "vbaproject.bin", "vbadata.xml", "/activex/", "/embeddings/", "/ctrlprops/", "_xmlsignatures/"
        )):
            removed.add(n)
            continue

        if ext in {".docx", ".docm"}:
            if (
                low.startswith("word/comments")
                or low == "word/people.xml"
                or low.startswith("word/glossary/")
            ):
                removed.add(n)
        elif ext in {".pptx", ".pptm"}:
            if (
                low.startswith("ppt/comments/")
                or low == "ppt/commentauthors.xml"
                or low.startswith("ppt/threadedcomments/")
                or low.startswith("ppt/persons/")
                or low.startswith("ppt/notesslides/")
                or low.startswith("ppt/notesmasters/")
                or low.startswith("ppt/tags/")
            ):
                removed.add(n)
        elif ext in {".xlsx", ".xlsm"}:
            if (
                low.startswith("xl/comments")
                or low.startswith("xl/threadedcomments/")
                or low.startswith("xl/persons/")
                or low.startswith("xl/externallinks/")
                or low == "xl/connections.xml"
                or low.startswith("xl/pivotcache/")
                or low.startswith("xl/pivottables/")
                or low.startswith("xl/slicercaches/")
                or low.startswith("xl/slicers/")
                or low.startswith("xl/model/")
                or low.startswith("xl/customdata/")
                or low.startswith("xl/querytables/")
            ):
                removed.add(n)
    return removed


def accept_word_revisions(root, report: Report):
    # Elimina comentarios/marcadores y acepta inserciones/movimientos a destino.
    remove_names = {
        "commentRangeStart", "commentRangeEnd", "commentReference",
        "permStart", "permEnd", "proofErr", "bookmarkStart", "bookmarkEnd",
    }
    for elem in list(root.iter()):
        ln = localname(elem.tag)
        parent = elem.getparent()
        if parent is None:
            continue
        if ln in remove_names:
            parent.remove(elem)
            report.removed.append(f"Word: {ln}")
        elif ln in {"del", "moveFrom"}:
            parent.remove(elem)
            report.removed.append(f"Word: revision removed ({ln})")
        elif ln in {"ins", "moveTo"}:
            idx = parent.index(elem)
            for child in list(elem):
                parent.insert(idx, child)
                idx += 1
            parent.remove(elem)
            report.removed.append(f"Word: revision accepted ({ln})")

    # Remove author/revision attributes and rsid values.
    for elem in root.iter():
        for attr in list(elem.attrib):
            ln = localname(attr)
            if ln in {"author", "date", "initials"} or ln.startswith("rsid"):
                del elem.attrib[attr]


def clean_word_settings(root, report: Report):
    for elem in list(root.iter()):
        if localname(elem.tag) in {"docVars", "rsids", "trackRevisions", "attachedTemplate"}:
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
                report.removed.append(f"Word settings: {localname(elem.tag)}")


def remove_hidden_ppt_slides(parts: dict[str, bytes], removed: set[str], report: Report):
    pres_name = "ppt/presentation.xml"
    rel_name = "ppt/_rels/presentation.xml.rels"
    if pres_name not in parts or rel_name not in parts:
        return
    try:
        pres = xml_parse(parts[pres_name])
        rels = xml_parse(parts[rel_name])
    except Exception:
        return
    rel_map = {r.get("Id"): r for r in rels if localname(r.tag) == "Relationship"}
    changed = False
    for sld_id in list(pres.xpath(".//p:sldIdLst/p:sldId", namespaces=NS)):
        rid = sld_id.get(f"{{{R_NS}}}id")
        rel = rel_map.get(rid)
        if rel is None:
            continue
        target = resolve_rel_target(rel_name, rel.get("Target", ""))
        data = parts.get(target)
        if not data:
            continue
        try:
            slide_root = xml_parse(data)
        except Exception:
            continue
        show = (slide_root.get("show") or "true").strip().lower()
        if show not in {"0", "false", "off", "no"}:
            continue
        removed.add(target)
        sr = rels_path_for_part(target)
        if sr in parts:
            removed.add(sr)
        sld_id.getparent().remove(sld_id)
        rels.remove(rel)
        # Also remove references to the same rId in custom shows.
        for e in list(pres.xpath(f".//*[@r:id='{rid}']", namespaces=NS)):
            if e.getparent() is not None:
                e.getparent().remove(e)
        report.removed.append(f"PowerPoint: hidden slide removed ({target})")
        changed = True
    if changed:
        parts[pres_name] = xml_bytes(pres)
        parts[rel_name] = xml_bytes(rels)


def remove_hidden_ppt_shapes(root, part_name: str, parts: dict[str, bytes], report: Report):
    rids = set()
    for c in list(root.iter()):
        if localname(c.tag) != "cNvPr":
            continue
        hidden = (c.get("hidden") or "false").strip().lower()
        if hidden not in {"1", "true", "on", "yes"}:
            continue
        obj = c
        while obj.getparent() is not None and localname(obj.tag) not in {"sp", "pic", "graphicFrame", "cxnSp", "grpSp", "contentPart"}:
            obj = obj.getparent()
        parent = obj.getparent()
        if parent is None:
            continue
        for e in obj.iter():
            for attr, val in e.attrib.items():
                try:
                    if etree.QName(attr).namespace == R_NS:
                        rids.add(val)
                except Exception:
                    pass
        parent.remove(obj)
        report.removed.append(f"PowerPoint: hidden object removed in {part_name}")
    remove_relationship_ids(parts, part_name, rids, report)


def remove_hidden_word_runs(root, part_name: str, parts: dict[str, bytes], report: Report):
    rids = set()
    for run in list(root.iter()):
        if localname(run.tag) != "r":
            continue
        hidden = any(localname(x.tag) in {"vanish", "webHidden"} for x in run.iter())
        if not hidden:
            continue
        for e in run.iter():
            for attr, val in e.attrib.items():
                try:
                    if etree.QName(attr).namespace == R_NS:
                        rids.add(val)
                except Exception:
                    pass
        parent = run.getparent()
        if parent is not None:
            parent.remove(run)
            report.removed.append(f"Word: hidden run removed in {part_name}")
    remove_relationship_ids(parts, part_name, rids, report)


def strip_word_field_codes(root, report: Report):
    n = 0
    for elem in root.iter():
        if localname(elem.tag) == "instrText" and elem.text:
            elem.text = ""
            n += 1
        if localname(elem.tag) == "fldSimple":
            for attr in list(elem.attrib):
                if localname(attr) == "instr":
                    del elem.attrib[attr]
                    n += 1
    if n:
        report.removed.append(f"Word: {n} hidden field code(s) removed")


def prune_orphan_parts(parts: dict[str, bytes], report: Report) -> set[str]:
    """Remove OOXML parts that are no longer reachable from root relationships."""
    reachable: set[str] = set()
    keep_rels: set[str] = {"_rels/.rels"}
    queue = [""]
    seen_sources = set()
    while queue:
        source = queue.pop()
        if source in seen_sources:
            continue
        seen_sources.add(source)
        rel_name = rels_path_for_part(source)
        if rel_name not in parts:
            continue
        keep_rels.add(rel_name)
        try:
            root = xml_parse(parts[rel_name])
        except Exception:
            continue
        for rel in root:
            if localname(rel.tag) != "Relationship" or (rel.get("TargetMode", "").lower() == "external"):
                continue
            target = resolve_rel_target(rel_name, rel.get("Target", ""))
            if target in parts and target not in reachable:
                reachable.add(target)
                queue.append(target)
    keep = reachable | keep_rels | {"[Content_Types].xml"}
    orphan = {n for n in parts if n not in keep}
    for n in orphan:
        parts.pop(n, None)
    if orphan:
        report.removed.append(f"Office: {len(orphan)} orphan part(s) removed")
    return orphan

def remove_hidden_excel_sheets(parts: dict[str, bytes], removed: set[str], report: Report):
    wb_name = "xl/workbook.xml"
    rel_name = "xl/_rels/workbook.xml.rels"
    if wb_name not in parts or rel_name not in parts:
        return
    try:
        wb = xml_parse(parts[wb_name])
        rels = xml_parse(parts[rel_name])
    except Exception:
        return

    rel_map = {r.get("Id"): r for r in rels if localname(r.tag) == "Relationship"}
    changed = False
    for sheet in wb.xpath(".//s:sheets/s:sheet", namespaces=NS):
        state = (sheet.get("state") or "visible").lower()
        if state not in {"hidden", "veryhidden"}:
            continue
        rid = sheet.get(f"{{{R_NS}}}id")
        rel = rel_map.get(rid)
        if rel is None:
            continue
        target = resolve_rel_target(rel_name, rel.get("Target", ""))
        removed.add(target)
        # worksheet relationships may contain drawings/comments/etc.
        tp = PurePosixPath(target)
        target_rels = str(tp.parent / "_rels" / f"{tp.name}.rels")
        if target_rels in parts:
            removed.add(target_rels)
        parent = sheet.getparent()
        parent.remove(sheet)
        rels.remove(rel)
        report.removed.append(f"Excel: hidden sheet removed ({sheet.get('name', '')})")
        changed = True

    if changed:
        parts[wb_name] = xml_bytes(wb)
        parts[rel_name] = xml_bytes(rels)


def scrub_hidden_excel_rows_cols(root, report: Report):
    removed_cells = 0
    # Hidden rows: remove cells but keep a minimal structure.
    for row in root.xpath(".//s:sheetData/s:row[@hidden='1' or @hidden='true']", namespaces=NS):
        for c in list(row):
            row.remove(c)
            removed_cells += 1
        row.attrib.pop("hidden", None)

    # Hidden columns: remove cell contents whose column index falls in those ranges.
    hidden_ranges = []
    for col in root.xpath(".//s:cols/s:col[@hidden='1' or @hidden='true']", namespaces=NS):
        try:
            hidden_ranges.append((int(col.get("min")), int(col.get("max"))))
            col.attrib.pop("hidden", None)
        except Exception:
            pass

    if hidden_ranges:
        def col_index(cell_ref: str) -> int:
            m = re.match(r"([A-Z]+)", cell_ref.upper())
            if not m:
                return 0
            n = 0
            for ch in m.group(1):
                n = n * 26 + (ord(ch) - 64)
            return n

        for c in root.xpath(".//s:sheetData/s:row/s:c", namespaces=NS):
            idx = col_index(c.get("r", ""))
            if any(lo <= idx <= hi for lo, hi in hidden_ranges):
                for child in list(c):
                    c.remove(child)
                removed_cells += 1

    if removed_cells:
        report.removed.append(f"Excel: {removed_cells} hidden cells emptied")


def redact_container_text(root, container_names: set[str], text_names: set[str], redactor: Redactor, report: Report):
    # Detect terms split across several runs; formatting is collapsed
    # only when redaction occurs inside that container.
    for container in root.iter():
        if localname(container.tag) not in container_names:
            continue
        nodes = [n for n in container.iter() if localname(n.tag) in text_names and n.text]
        if not nodes:
            continue
        combined = "".join(n.text or "" for n in nodes)
        redacted = redactor.redact_text(combined, report)
        if redacted != combined:
            nodes[0].text = redacted
            for n in nodes[1:]:
                n.text = ""


def redact_xml(root, redactor: Redactor, report: Report, family: str):
    # Nombres internos de objetos/dibujos pueden contener nombres de personas.
    for elem in root.iter():
        if localname(elem.tag) in {"cNvPr", "docPr"} and "name" in elem.attrib:
            elem.attrib["name"] = f"Object_{elem.get('id', '0')}"

    if family == "word":
        redact_container_text(root, {"p"}, {"t", "instrText"}, redactor, report)
    elif family == "ppt":
        redact_container_text(root, {"p"}, {"t"}, redactor, report)
    elif family == "xlsx":
        redact_container_text(root, {"si", "is"}, {"t"}, redactor, report)

    # Segunda pasada para nodos sueltos y atributos descriptivos.
    attr_allow = {"title", "descr", "alt", "author", "userName", "company", "manager"}
    for elem in root.iter():
        ln = localname(elem.tag)
        if ln in {"t", "instrText", "f"} and elem.text:
            elem.text = redactor.redact_text(elem.text, report)
        for attr in list(elem.attrib):
            if localname(attr) in attr_allow:
                elem.attrib[attr] = redactor.redact_text(elem.attrib[attr], report)


def strip_excel_formulas_and_names(root, part_name: str, report: Report):
    n = 0
    # Cell formulas: keep the cached <v> value when present.
    if part_name.startswith("xl/worksheets/"):
        for f in list(root.iter()):
            if localname(f.tag) == "f" and f.getparent() is not None:
                f.getparent().remove(f)
                n += 1
    # Defined names may contain paths, sheet names, or hidden expressions.
    if part_name == "xl/workbook.xml":
        for d in list(root.iter()):
            if localname(d.tag) == "definedNames" and d.getparent() is not None:
                d.getparent().remove(d)
                n += 1
    if n:
        report.removed.append(f"Excel: {n} formula(s)/defined name(s) removed in {part_name}")


def compact_excel_shared_strings(parts: dict[str, bytes], report: Report):
    sst_name = "xl/sharedStrings.xml"
    if sst_name not in parts:
        return
    try:
        sst = xml_parse(parts[sst_name])
    except Exception:
        return
    items = [x for x in sst if localname(x.tag) == "si"]
    used = []
    refs = 0
    worksheets = {}
    for name in list(parts):
        if not name.startswith("xl/worksheets/") or not name.endswith(".xml"):
            continue
        try:
            root = xml_parse(parts[name])
        except Exception:
            continue
        worksheets[name] = root
        for c in root.xpath(".//s:c[@t='s']", namespaces=NS):
            v = next((x for x in c if localname(x.tag) == "v"), None)
            if v is None or not v.text:
                continue
            try:
                idx = int(v.text)
            except Exception:
                continue
            if 0 <= idx < len(items):
                used.append(idx)
                refs += 1
    order = []
    seen = set()
    for idx in used:
        if idx not in seen:
            seen.add(idx)
            order.append(idx)
    mapping = {old: new for new, old in enumerate(order)}
    for name, root in worksheets.items():
        changed = False
        for c in root.xpath(".//s:c[@t='s']", namespaces=NS):
            v = next((x for x in c if localname(x.tag) == "v"), None)
            if v is None or not v.text:
                continue
            try:
                old = int(v.text)
            except Exception:
                continue
            if old in mapping:
                nv = str(mapping[old])
                if nv != v.text:
                    v.text = nv
                    changed = True
        if changed:
            parts[name] = xml_bytes(root)
    for child in list(sst):
        sst.remove(child)
    for old in order:
        sst.append(items[old])
    sst.set("count", str(refs))
    sst.set("uniqueCount", str(len(order)))
    parts[sst_name] = xml_bytes(sst)
    removed_count = len(items) - len(order)
    if removed_count:
        report.removed.append(f"Excel: {removed_count} unused shared string(s) removed")


def scrub_chart_caches(parts: dict[str, bytes], report: Report):
    removed = 0
    for name in list(parts):
        if "/charts/" not in name.lower() or not name.lower().endswith(".xml"):
            continue
        try:
            root = xml_parse(parts[name])
        except Exception:
            continue
        changed = False
        for elem in list(root.iter()):
            if localname(elem.tag) in {"numCache", "strCache", "multiLvlStrCache"} and elem.getparent() is not None:
                elem.getparent().remove(elem)
                removed += 1
                changed = True
        if changed:
            parts[name] = xml_bytes(root)
    if removed:
        report.removed.append(f"Office: {removed} chart cache(s) removed")

def anonymize_excel_sheet_names(parts: dict[str, bytes], report: Report):
    """Rename visible sheets so tab names do not leak identity."""
    wb_name = "xl/workbook.xml"
    if wb_name not in parts:
        return
    try:
        wb = xml_parse(parts[wb_name])
    except Exception:
        return
    mapping = {}
    i = 1
    for sheet in wb.xpath(".//s:sheets/s:sheet", namespaces=NS):
        old = sheet.get("name", "")
        new = f"Sheet_{i:03d}"
        i += 1
        if old and old != new:
            mapping[old] = new
            sheet.set("name", new)
            report.removed.append(f"Excel: sheet name anonymized ({old!r} -> {new})")
    parts[wb_name] = xml_bytes(wb)
    if not mapping:
        return

    def repl(text: str) -> str:
        out = text
        for old, new in mapping.items():
            qold = old.replace("'", "''")
            out = out.replace(f"'{qold}'!", f"'{new}'!")
            # Simple names may appear unquoted in formulas.
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", old):
                out = re.sub(rf"(?<![A-Za-z0-9_.]){re.escape(old)}!", new + "!", out)
        return out

    for name in list(parts):
        if not name.startswith("xl/") or not name.lower().endswith(".xml"):
            continue
        try:
            root = xml_parse(parts[name])
        except Exception:
            continue
        changed = False
        for elem in root.iter():
            if elem.text:
                new_text = repl(elem.text)
                if new_text != elem.text:
                    elem.text = new_text
                    changed = True
            for attr in list(elem.attrib):
                new_val = repl(elem.attrib[attr])
                if new_val != elem.attrib[attr]:
                    elem.attrib[attr] = new_val
                    changed = True
        if changed:
            parts[name] = xml_bytes(root)

def sanitize_embedded_media(parts: dict[str, bytes], redactor: Redactor, report: Report):
    """Remove metadata from Office embedded images and clean basic SVG files."""
    unsupported = set()
    for name in list(parts):
        low = name.lower()
        if "/media/" not in low:
            continue
        ext = PurePosixPath(name).suffix.lower()
        if ext in IMAGE_EXTS:
            try:
                bio = BytesIO(parts[name])
                out = BytesIO()
                with Image.open(bio) as im:
                    frames, durations = [], []
                    for frame in ImageSequence.Iterator(im):
                        visual = ImageOps.exif_transpose(frame.copy())
                        raw = Image.frombytes(visual.mode, visual.size, visual.tobytes())
                        frames.append(raw)
                        durations.append(frame.info.get("duration", im.info.get("duration", 0)))
                    if ext in {".jpg", ".jpeg"}:
                        f = frames[0]
                        if f.mode not in {"RGB", "L"}:
                            f = f.convert("RGB")
                        f.save(out, format="JPEG", quality=95, optimize=True)
                    elif ext == ".png":
                        frames[0].save(out, format="PNG", optimize=True)
                    elif ext in {".tif", ".tiff"}:
                        frames[0].save(out, format="TIFF", save_all=len(frames) > 1, append_images=frames[1:])
                    elif ext == ".webp":
                        kw = {"format": "WEBP", "lossless": True}
                        if len(frames) > 1:
                            kw.update(save_all=True, append_images=frames[1:], duration=durations)
                        frames[0].save(out, **kw)
                parts[name] = out.getvalue()
                report.removed.append(f"Office media: metadata removed from {name}")
            except Exception as exc:
                report.warnings.append(f"Could not rewrite embedded image {name}: {exc}")
        elif ext == ".svg":
            try:
                root = xml_parse(parts[name])
                for elem in list(root.iter()):
                    ln = localname(elem.tag).lower()
                    parent = elem.getparent()
                    if parent is not None and ln in {"metadata", "script"}:
                        parent.remove(elem)
                        continue
                    if elem.text:
                        elem.text = redactor.redact_text(elem.text, report)
                    for attr in list(elem.attrib):
                        aln = localname(attr).lower()
                        if aln in {"href", "title", "desc", "id"}:
                            value = elem.attrib[attr]
                            if aln == "href" and (value.startswith("http://") or value.startswith("https://") or value.startswith("file:")):
                                del elem.attrib[attr]
                            else:
                                elem.attrib[attr] = redactor.redact_text(value, report)
                parts[name] = xml_bytes(root)
                report.removed.append(f"Office media: SVG sanitized {name}")
            except Exception as exc:
                report.warnings.append(f"Could not sanitize embedded SVG {name}: {exc}")
        elif ext in {".emf", ".wmf"}:
            unsupported.add(ext)
    if unsupported:
        report.warnings.append("Office contains EMF/WMF graphics; they are kept because Pillow cannot safely rewrite them.")

def clean_office(src: Path, dst: Path, redactor: Redactor, remove_external: bool, remove_hidden_excel: bool, anonymize_sheet_names: bool, strip_formulas: bool, report: Report):
    ext = src.suffix.lower()
    with zipfile.ZipFile(src, "r") as zin:
        parts = {zi.filename: zin.read(zi.filename) for zi in zin.infolist() if not zi.is_dir()}

    removed = office_removed_parts(parts.keys(), ext)
    if strip_formulas and ext in {".xlsx", ".xlsm"} and "xl/calcChain.xml" in parts:
        removed.add("xl/calcChain.xml")
    if removed:
        report.removed.append(f"Office: {len(removed)} internal parts removed")

    if remove_hidden_excel and ext in {".xlsx", ".xlsm"}:
        remove_hidden_excel_sheets(parts, removed, report)
    if anonymize_sheet_names and ext in {".xlsx", ".xlsm"}:
        anonymize_excel_sheet_names(parts, report)
    if ext in {".pptx", ".pptm"}:
        remove_hidden_ppt_slides(parts, removed, report)

    # Eliminar partes antes de limpiar relaciones.
    for n in list(removed):
        parts.pop(n, None)

    strip_relationships(parts, removed, remove_external, report)
    strip_content_types(parts, removed)

    # Format-specific XML cleanup plus text redaction.
    for name in list(parts):
        if not name.lower().endswith((".xml", ".rels")):
            continue
        try:
            root = xml_parse(parts[name])
        except Exception:
            continue

        family = "other"
        if name.startswith("word/"):
            family = "word"
            if name in {"word/document.xml", "word/footnotes.xml", "word/endnotes.xml"} or name.startswith("word/header") or name.startswith("word/footer"):
                accept_word_revisions(root, report)
                remove_hidden_word_runs(root, name, parts, report)
                strip_word_field_codes(root, report)
            if name == "word/settings.xml":
                clean_word_settings(root, report)
        elif name.startswith("ppt/"):
            family = "ppt"
            remove_hidden_ppt_shapes(root, name, parts, report)
        elif name.startswith("xl/"):
            family = "xlsx"
            if remove_hidden_excel and name.startswith("xl/worksheets/") and name.endswith(".xml"):
                scrub_hidden_excel_rows_cols(root, report)
            if strip_formulas:
                strip_excel_formulas_and_names(root, name, report)

        if redactor.patterns and family != "other":
            redact_xml(root, redactor, report, family)

        parts[name] = xml_bytes(root)

    if strip_formulas and ext in {".xlsx", ".xlsm"}:
        compact_excel_shared_strings(parts, report)
    scrub_chart_caches(parts, report)

    # Second pass: relationships that still point to dynamically removed parts.
    strip_relationships(parts, removed, remove_external, report)
    removed |= prune_orphan_parts(parts, report)
    strip_content_types(parts, removed)
    sanitize_embedded_media(parts, redactor, report)

    dst.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
        zout.comment = b""
        for name in sorted(parts):
            zi = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3
            zi.external_attr = 0o600 << 16
            zi.extra = b""
            zi.comment = b""
            zout.writestr(zi, parts[name])


def redact_pdf_visible(src: Path, tmp_out: Path, redactor: Redactor, report: Report, masks: list[list[int]]):
    doc = fitz.open(src)
    for page_no, page in enumerate(doc, start=1):
        text = page.get_text("text") or ""
        literals = redactor.find_literals(text, report)
        rectangles = []
        for value in literals:
            try:
                rectangles.extend(page.search_for(value))
            except Exception:
                pass

        # Manual PDF masks: [page, x1, y1, x2, y2], 1-based page.
        for item in masks:
            if len(item) == 5 and int(item[0]) == page_no:
                rectangles.append(fitz.Rect(*map(float, item[1:])))

        unique, seen = [], set()
        for r in rectangles:
            key = tuple(round(float(x), 2) for x in (r.x0, r.y0, r.x1, r.y1))
            if key not in seen:
                seen.add(key)
                unique.append(r)
        for r in unique:
            page.add_redact_annot(r, fill=(0, 0, 0), cross_out=False)
        if unique:
            page.apply_redactions()
    doc.set_metadata({})
    try:
        doc.del_xml_metadata()
    except Exception:
        pass
    doc.save(tmp_out, garbage=4, clean=True, deflate=True)
    doc.close()


def rasterize_pdf(src: Path, dst: Path, dpi: int, report: Report):
    source = fitz.open(src)
    out = fitz.open()
    zoom = dpi / 72.0
    matrix = fitz.Matrix(zoom, zoom)
    for page in source:
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        width = pix.width * 72.0 / dpi
        height = pix.height * 72.0 / dpi
        p = out.new_page(width=width, height=height)
        p.insert_image(fitz.Rect(0, 0, width, height), pixmap=pix)
    out.set_metadata({})
    try:
        out.del_xml_metadata()
    except Exception:
        pass
    out.save(dst, garbage=4, clean=True, deflate=True)
    out.close()
    source.close()
    report.removed.append(f"PDF rasterizado a {dpi} DPI: se descartan texto/capas/formularios/adjuntos originales")


def scrub_pdf_vector(src: Path, dst: Path, report: Report):
    doc = fitz.open(src)
    # PyMuPDF scrubber removes metadata, XML, JavaScript, attachments,
    # hidden text, links, thumbnails, and other sensitive elements.
    doc.scrub(
        attached_files=True,
        clean_pages=True,
        embedded_files=True,
        hidden_text=True,
        javascript=True,
        metadata=True,
        redactions=True,
        redact_images=1,
        remove_links=True,
        reset_fields=True,
        reset_responses=True,
        thumbnails=True,
        xml_metadata=True,
    )
    # For strong anonymization, also remove annotations and widgets/forms.
    for page in doc:
        annots = list(page.annots() or [])
        for annot in annots:
            try:
                page.delete_annot(annot)
            except Exception:
                pass
        widgets = list(page.widgets() or [])
        for widget in widgets:
            try:
                page.delete_widget(widget)
            except Exception:
                pass
    try:
        doc.set_toc([])
    except Exception:
        pass
    doc.set_metadata({})
    try:
        doc.del_xml_metadata()
    except Exception:
        pass
    doc.save(dst, garbage=4, clean=True, deflate=True)
    doc.close()
    report.removed.append("PDF: metadata, XML, attachments, JavaScript, links, annotations, forms, and hidden text cleaned")


def clean_pdf(src: Path, dst: Path, redactor: Redactor, pdf_mode: str, dpi: int, report: Report, masks: list[list[int]]):
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="anon_pdf_") as td:
        td = Path(td)
        redacted = td / "redacted.pdf"
        if redactor.patterns or masks:
            redact_pdf_visible(src, redacted, redactor, report, masks)
            base = redacted
        else:
            base = src

        if pdf_mode == "raster":
            rasterize_pdf(base, dst, dpi, report)
        else:
            scrub_pdf_vector(base, dst, report)
            report.warnings.append("Vector PDF mode is weaker than rasterization. For maximum privacy use --pdf-mode raster.")

def clean_image(src: Path, dst: Path, masks: list[list[int]], report: Report):
    dst.parent.mkdir(parents=True, exist_ok=True)
    with Image.open(src) as im:
        frames = []
        durations = []
        for frame in ImageSequence.Iterator(im):
            frame.load()
            # Recreate from pixels to remove EXIF/XMP/ICC/comments/text chunks.
            visual = ImageOps.exif_transpose(frame.copy())
            raw = Image.frombytes(visual.mode, visual.size, visual.tobytes())
            if masks:
                draw = ImageDraw.Draw(raw)
                for box in masks:
                    if len(box) != 4:
                        continue
                    draw.rectangle(tuple(map(int, box)), fill=0 if raw.mode in {"1", "L", "I", "F"} else "black")
                report.removed.append(f"Image: {len(masks)} mask(s) applied")
            frames.append(raw)
            durations.append(frame.info.get("duration", im.info.get("duration", 0)))

        save_kwargs = {}
        ext = src.suffix.lower()
        if ext in {".jpg", ".jpeg"}:
            f = frames[0]
            if f.mode not in {"RGB", "L"}:
                f = f.convert("RGB")
            f.save(dst, format="JPEG", quality=95, optimize=True)
        elif ext == ".png":
            frames[0].save(dst, format="PNG", optimize=True)
        elif ext in {".tif", ".tiff"}:
            frames[0].save(dst, format="TIFF", save_all=len(frames) > 1, append_images=frames[1:])
        elif ext == ".webp":
            kw = {"format": "WEBP", "lossless": True}
            if len(frames) > 1:
                kw.update(save_all=True, append_images=frames[1:], duration=durations)
            frames[0].save(dst, **kw)
        else:
            raise ValueError(f"Unsupported image format: {ext}")

    report.removed.append("Image: EXIF/XMP/ICC/auxiliary text metadata removed")
    if not masks:
        report.warnings.append("The image may contain visible PII in its pixels. Add manual masks with --masks and visually review the result.")


def process_one(src: Path, out_dir: Path, args, redactor: Redactor, masks: dict[str, list[list[int]]]) -> Report:
    ext = src.suffix.lower()
    if ext not in SUPPORTED_EXTS:
        raise ValueError(f"Unsupported format: {ext}")

    out_name = safe_output_name(src, args.randomize_names)
    dst = out_dir / out_name
    if dst.exists() and not args.overwrite:
        raise FileExistsError(f"Already exists: {dst}. Use --overwrite to replace it.")

    kind = "pdf" if ext == ".pdf" else "office" if ext in OFFICE_EXTS else "image"
    report = Report(source=str(src), output=str(dst), kind=kind)

    if ext == ".pdf":
        clean_pdf(src, dst, redactor, args.pdf_mode, args.pdf_dpi, report, masks.get(src.name, masks.get(str(src), [])))
    elif ext in OFFICE_EXTS:
        clean_office(src, dst, redactor, not args.keep_external_links, not args.keep_hidden_excel, not args.keep_sheet_names, not args.keep_formulas, report)
        report.warnings.append("Office: visually review names, addresses, or other sensitive data that may be inside images/SmartArt/diagrams.")
        if ext in {".xlsx", ".xlsm"} and not args.keep_formulas:
            report.warnings.append("Excel: formulas are removed for privacy; if a cell had no cached value it may become empty. Use --keep-formulas if you need to keep them.")
    else:
        file_masks = masks.get(src.name, masks.get(str(src), []))
        clean_image(src, dst, file_masks, report)

    # Minimal permissions and normalized filesystem timestamp (best effort).
    try:
        os.chmod(dst, 0o600)
        os.utime(dst, (315532800, 315532800))  # 1980-01-01 UTC aprox.
    except Exception:
        pass

    report.sha256 = sha256_file(dst)
    return report


def iter_inputs(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise FileNotFoundError(path)
    globber = path.rglob("*") if recursive else path.glob("*")
    return sorted(p for p in globber if p.is_file() and p.suffix.lower() in SUPPORTED_EXTS)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Anonymize/sanitize PDF, Office, and image files by creating new copies.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("input", type=Path, help="Input file or directory")
    p.add_argument("output_dir", type=Path, help="Output directory")
    p.add_argument("--recursive", action="store_true", help="Scan subdirectories")
    p.add_argument("--terms", type=Path, help="TXT file with one sensitive term per line")
    p.add_argument("--auto-pii", action="store_true", help="Redact common patterns: email, URL, IP, IBAN, Spanish DNI/NIE, paths, and phone numbers")
    p.add_argument("--pdf-mode", choices=["raster", "scrub"], default="raster", help="raster = strongest structural cleanup; scrub = keep vectors/text")
    p.add_argument("--pdf-dpi", type=int, default=180, help="Resolution used when rasterizing PDFs")
    p.add_argument("--masks", type=Path, help="JSON: images [x1,y1,x2,y2]; PDF [page,x1,y1,x2,y2]")
    p.add_argument("--randomize-names", action="store_true", help="Do not keep the original name in the output file")
    p.add_argument("--keep-external-links", action="store_true", help="Keep Office external links/relationships")
    p.add_argument("--keep-hidden-excel", action="store_true", help="Keep hidden Excel sheets, rows, and columns")
    p.add_argument("--keep-sheet-names", action="store_true", help="Keep original Excel sheet names")
    p.add_argument("--keep-formulas", action="store_true", help="Keep Excel formulas and defined names")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing outputs")
    p.add_argument("--report", type=Path, help="JSON report path; defaults to output_dir/_LOCAL_ONLY_anonymization_report.json")
    return p


def main() -> int:
    args = build_parser().parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    terms = load_terms(args.terms)
    masks = load_masks(args.masks)
    redactor = Redactor(terms, args.auto_pii)

    files = iter_inputs(args.input, args.recursive)
    out_resolved = args.output_dir.resolve()
    filtered = []
    for f in files:
        try:
            if f.resolve().is_relative_to(out_resolved):
                continue
        except AttributeError:
            try:
                f.resolve().relative_to(out_resolved)
                continue
            except ValueError:
                pass
        filtered.append(f)
    files = filtered
    if not files:
        print("No supported files were found.", file=sys.stderr)
        return 2

    reports = []
    failures = []
    for src in files:
        try:
            rep = process_one(src, args.output_dir, args, redactor, masks)
            reports.append(rep.__dict__)
            print(f"OK  {src} -> {rep.output}")
        except Exception as exc:
            failures.append({"source": str(src), "error": f"{type(exc).__name__}: {exc}"})
            print(f"ERR {src}: {exc}", file=sys.stderr)

    report_path = args.report or (args.output_dir / "_LOCAL_ONLY_anonymization_report.json")
    report_obj = {
        "files": reports,
        "failures": failures,
        "notes": [
            "No automated process guarantees absolute anonymity.",
            "Visually review the result before publishing or sending it.",
            "Images require manual masks for PII visible in pixels.",
            "Automatic PII redaction may produce false positives or negatives.",
            "DO NOT SHARE this report: it contains original file paths/names.",
        ],
    }
    report_path.write_text(json.dumps(report_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nReport: {report_path}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
