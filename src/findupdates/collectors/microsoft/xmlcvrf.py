"""Convert CVRF 1.1 XML into the JSON-shaped mapping consumed by the JSON parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

from findupdates.collectors.errors import ParseError

_NOTE_TYPES = {
    "description": 2,
    "details": 2,
    "general": 2,
}
_REMEDIATION_TYPES = {
    "vendor fix": 2,
    "workaround": 0,
    "mitigation": 1,
    "known issue": 5,
}


def parse_cvrf_xml(body: bytes) -> tuple[str, Mapping[str, Any]]:
    """Return (document_id, JSON-like CVRF object). Rejects DTD/entity payloads."""
    prefix = body[:4096].upper()
    if b"<!DOCTYPE" in prefix or b"<!ENTITY" in prefix:
        raise ParseError("CVRF XML with DTD/entity declarations is not accepted")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise ParseError(f"invalid CVRF XML: {exc}") from exc

    document_id = _text(root, "DocumentTracking", "Identification", "ID") or "unknown-document"
    published = _text(root, "DocumentTracking", "InitialReleaseDate")
    revised = _text(root, "DocumentTracking", "CurrentReleaseDate")
    products = [
        {"ProductID": product_id, "Value": name} for product_id, name in _product_map(root).items()
    ]
    vulnerabilities = [_vulnerability(element) for element in _children(root, "Vulnerability")]
    payload: dict[str, Any] = {
        "DocumentTracking": {
            "Identification": {"ID": document_id},
            "InitialReleaseDate": published,
            "CurrentReleaseDate": revised,
        },
        "ProductTree": {"FullProductName": products},
        "Vulnerability": vulnerabilities,
    }
    return document_id, payload


def _vulnerability(element: ET.Element) -> dict[str, Any]:
    notes: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    for note in _descendants(element, "Note"):
        text = _clean("".join(note.itertext()))
        if not text:
            continue
        title = (note.attrib.get("Title") or note.attrib.get("Type") or "note").strip()
        notes.append(
            {
                "Title": title,
                "Type": _NOTE_TYPES.get(title.casefold(), 1),
                "Value": text,
            }
        )
        if "workaround" in title.casefold():
            remediations.append({"Type": 0, "Description": text})
    statuses: list[dict[str, Any]] = []
    for status in _descendants(element, "Status"):
        product_ids = [
            text for child in _descendants(status, "ProductID") if (text := _clean(child.text))
        ]
        statuses.append(
            {
                "Type": 3 if "not affected" not in status.attrib.get("Type", "").casefold() else 0,
                "Status": status.attrib.get("Type"),
                "ProductID": product_ids,
            }
        )
    for remediation in _descendants(element, "Remediation"):
        kind = (remediation.attrib.get("Type") or "").casefold()
        description = _direct_text(remediation, "Description")
        node: dict[str, Any] = {
            "Type": _REMEDIATION_TYPES.get(kind, 2),
            "Description": description,
            "URL": _direct_text(remediation, "URL"),
            "ProductID": [
                text
                for child in _descendants(remediation, "ProductID")
                if (text := _clean(child.text))
            ],
            "RestartRequired": _direct_text(remediation, "RestartRequired"),
            "FixedBuild": _direct_text(remediation, "FixedBuild"),
        }
        remediations.append(node)
    return {
        "Title": _direct_text(element, "Title"),
        "CVE": _direct_text(element, "CVE"),
        "Ordinal": element.attrib.get("Ordinal"),
        "ReleaseDate": _direct_text(element, "ReleaseDate"),
        "RevisionDate": _direct_text(element, "RevisionDate"),
        "CurrentReleaseDate": _direct_text(element, "CurrentReleaseDate"),
        "Notes": notes,
        "ProductStatuses": statuses,
        "Remediations": remediations,
    }


def _product_map(root: ET.Element) -> dict[str, str]:
    products: dict[str, str] = {}
    for element in _descendants(root, "FullProductName"):
        product_id = element.attrib.get("ProductID")
        name = _clean("".join(element.itertext()))
        if product_id and name:
            products[product_id] = name
    return products


def _text(root: ET.Element, *path: str) -> str | None:
    current = root
    for name in path:
        match = next((child for child in current if _local(child.tag) == name), None)
        if match is None:
            return None
        current = match
    return _clean("".join(current.itertext()))


def _direct_text(parent: ET.Element, local_name: str) -> str | None:
    for child in parent:
        if _local(child.tag) == local_name:
            return _clean("".join(child.itertext()))
    return None


def _children(parent: ET.Element, local_name: str) -> list[ET.Element]:
    return [child for child in parent if _local(child.tag) == local_name]


def _descendants(parent: ET.Element, local_name: str) -> list[ET.Element]:
    return [element for element in parent.iter() if _local(element.tag) == local_name]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = " ".join(value.split()).strip()
    return stripped or None
