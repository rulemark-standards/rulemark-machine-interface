#!/usr/bin/env python3
"""Fail closed when RuleMark release representations disagree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from pypdf import PdfReader


class Gate:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def passed(self, message: str) -> None:
        print(f"[PASS] {message}")

    def failed(self, message: str) -> None:
        self.failures.append(message)
        print(f"[FAIL] {message}")

    def equal(self, actual: Any, expected: Any, label: str) -> None:
        if actual == expected:
            self.passed(label)
        else:
            self.failed(f"{label}: expected {expected!r}, got {actual!r}")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_text(value: str) -> str:
    return " ".join(value.split())


def pdf_facts(path: Path) -> tuple[str, int, int, str]:
    data = path.read_bytes()
    reader = PdfReader(path)
    text = normalize_text("\n".join(page.extract_text() or "" for page in reader.pages))
    return sha256_bytes(data), len(data), len(reader.pages), text


def standard_block(source: str, canonical_id: str) -> str | None:
    marker = f'canonical_id: "{canonical_id}"'
    start = source.find(marker)
    if start < 0:
        return None
    next_start = source.find('schema_version: "1.0"', start + len(marker))
    return source[start:next_start if next_start >= 0 else len(source)]


def check_pdf(gate: Gate, standard: dict[str, Any], path: Path, label: str) -> None:
    canonical_id = standard["canonical_id"]
    if not path.exists():
        gate.failed(f"{canonical_id} {label} missing: {path}")
        return
    try:
        digest, byte_count, page_count, text = pdf_facts(path)
    except Exception as error:  # fail closed on malformed PDFs
        gate.failed(f"{canonical_id} {label} unreadable: {error}")
        return
    gate.equal(digest, standard["sha256"], f"{canonical_id} {label} SHA-256")
    gate.equal(byte_count, standard["bytes"], f"{canonical_id} {label} bytes")
    gate.equal(page_count, standard["pages"], f"{canonical_id} {label} pages")
    for required in standard["pdf_identity"]["required_text"]:
        if normalize_text(required) in text:
            gate.passed(f"{canonical_id} PDF contains {required!r}")
        else:
            gate.failed(f"{canonical_id} PDF missing required identity text {required!r}")
    if standard["pdf_identity"]["mode"] == "canonical_id_and_title":
        if canonical_id in text:
            gate.passed(f"{canonical_id} PDF contains canonical ID")
        else:
            gate.failed(f"{canonical_id} PDF does not contain canonical ID")


def check_signature(gate: Gate, standard: dict[str, Any], canonical_dir: Path) -> None:
    signature = standard.get("signature")
    if not signature:
        return
    path = canonical_dir / signature
    if not path.exists():
        gate.failed(f"{standard['canonical_id']} signature missing: {path}")
        return
    content = path.read_text(encoding="utf-8")
    expected = f"sha256:{standard['sha256']}"
    if expected in content:
        gate.passed(f"{standard['canonical_id']} signed hash")
    else:
        gate.failed(f"{standard['canonical_id']} signature does not contain {expected}")


def check_canonical_registry(
    gate: Gate, standard: dict[str, Any], registry_by_id: dict[str, dict[str, Any]]
) -> None:
    canonical_id = standard["canonical_id"]
    record = registry_by_id.get(canonical_id)
    if record is None:
        gate.failed(f"{canonical_id} absent from Canonical Archive registry")
        return
    for key in ("version", "status", "title"):
        gate.equal(record.get(key), standard[key], f"{canonical_id} canonical registry {key}")
    gate.equal(
        record.get("locations", {}).get("canonical_file"),
        standard["canonical_file_url"],
        f"{canonical_id} canonical file URL",
    )


def check_web_source(gate: Gate, standard: dict[str, Any], source: str) -> None:
    canonical_id = standard["canonical_id"]
    block = standard_block(source, canonical_id)
    if block is None:
        gate.failed(f"{canonical_id} absent from RuleMark Web source registry")
        return
    expected_fragments = {
        "version": f'version: "{standard["version"]}"',
        "title": f'title: "{standard["title"]}"',
        "SHA-256": f'sha256: "{standard["sha256"]}"',
        "bytes": f'bytes: {standard["bytes"]}',
        "record filename": standard["record_filename"],
        "citation": f'citation: "{standard["citation"]}"',
    }
    for label, fragment in expected_fragments.items():
        if fragment in block:
            gate.passed(f"{canonical_id} web source {label}")
        else:
            gate.failed(f"{canonical_id} web source missing {label}: {fragment}")
    issued_at = standard.get("registry_issued_at")
    expected_date = f'issued_at: "{issued_at}"' if issued_at else "issued_at: null"
    if expected_date in block:
        gate.passed(f"{canonical_id} web source registry issue date")
    else:
        gate.failed(f"{canonical_id} web source missing registry issue date {expected_date}")


def fetch_bytes(url: str) -> bytes:
    separator = "&" if "?" in url else "?"
    cache_busted = f"{url}{separator}integrity_gate={int(time.time())}"
    request = urllib.request.Request(cache_busted, headers={"User-Agent": "RuleMark-Integrity-Gate/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} for {url}")
        return response.read()


def fetch_json(url: str) -> dict[str, Any]:
    return json.loads(fetch_bytes(url).decode("utf-8"))


def check_online(gate: Gate, standards: list[dict[str, Any]], base_url: str) -> None:
    try:
        registry = fetch_json(f"{base_url}/registry/v1/standards.json")
        registry_by_id = {item["canonical_id"]: item for item in registry["standards"]}
    except Exception as error:
        gate.failed(f"online Registry JSON unavailable: {error}")
        return

    for standard in standards:
        canonical_id = standard["canonical_id"]
        online_registry = registry_by_id.get(canonical_id)
        if online_registry is None:
            gate.failed(f"{canonical_id} absent from online Registry JSON")
        else:
            gate.equal(online_registry.get("standard_version"), standard["version"], f"{canonical_id} online registry version")
            gate.equal(online_registry.get("title"), standard["title"], f"{canonical_id} online registry title")
            gate.equal(online_registry.get("pdf_sha256"), standard["sha256"], f"{canonical_id} online registry SHA-256")

        machine_url = f"{base_url}/m/v1/standards/{canonical_id}/versions/{standard['version']}.json"
        try:
            machine = fetch_json(machine_url)
            pdf = machine.get("artifacts", {}).get("pdf", {})
            gate.equal(machine.get("version"), standard["version"], f"{canonical_id} online machine version")
            gate.equal(machine.get("title"), standard["title"], f"{canonical_id} online machine title")
            gate.equal(machine.get("citation"), standard["citation"], f"{canonical_id} online machine citation")
            gate.equal(pdf.get("sha256"), standard["sha256"], f"{canonical_id} online machine SHA-256")
            gate.equal(pdf.get("bytes"), standard["bytes"], f"{canonical_id} online machine bytes")
            gate.equal(pdf.get("url"), standard["canonical_file_url"], f"{canonical_id} online machine PDF URL")
            signature_url = pdf.get("signature_url")
            if signature_url:
                signature = fetch_bytes(signature_url).decode("utf-8", errors="replace")
                if f"sha256:{standard['sha256']}" in signature:
                    gate.passed(f"{canonical_id} online signature hash")
                else:
                    gate.failed(f"{canonical_id} online signature does not match normative artifact")
        except Exception as error:
            gate.failed(f"{canonical_id} online Machine JSON unavailable: {error}")

        try:
            pdf_data = fetch_bytes(standard["canonical_file_url"])
            gate.equal(sha256_bytes(pdf_data), standard["sha256"], f"{canonical_id} online download SHA-256")
            gate.equal(len(pdf_data), standard["bytes"], f"{canonical_id} online download bytes")
        except Exception as error:
            gate.failed(f"{canonical_id} online download unavailable: {error}")

        try:
            detail = fetch_bytes(f"{base_url}/standards/{canonical_id}").decode("utf-8", errors="replace")
            if standard["sha256"] in detail and f"{standard['bytes']:,}" in detail:
                gate.passed(f"{canonical_id} human page integrity metadata")
            else:
                gate.failed(f"{canonical_id} human page does not expose expected hash and bytes")
        except Exception as error:
            gate.failed(f"{canonical_id} human page unavailable: {error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical-dir", type=Path, required=True)
    parser.add_argument("--records-dir", type=Path, required=True)
    parser.add_argument("--web-dir", type=Path)
    parser.add_argument("--machine-dir", type=Path)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--base-url", default="https://rulemark.org")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gate = Gate()
    manifest_path = args.canonical_dir / "integrity" / "standards.json"
    try:
        manifest = load_json(manifest_path)
        standards = manifest["standards"]
    except Exception as error:
        print(f"[FATAL] Cannot load integrity baseline {manifest_path}: {error}")
        return 1

    ids = [item["canonical_id"] for item in standards]
    if len(ids) == len(set(ids)):
        gate.passed("canonical IDs are unique")
    else:
        gate.failed("integrity baseline contains duplicate canonical IDs")

    canonical_registry = load_json(args.canonical_dir / "registry" / "standards.json")
    canonical_by_id = {item["canonical_id"]: item for item in canonical_registry["standards"]}
    web_source = None
    if args.web_dir:
        web_path = args.web_dir / "lib" / "registry.ts"
        if web_path.exists():
            web_source = web_path.read_text(encoding="utf-8")
        else:
            gate.failed(f"RuleMark Web source registry missing: {web_path}")

    machine_by_id: dict[str, dict[str, Any]] | None = None
    if args.machine_dir:
        machine_registry_path = args.machine_dir / "registry" / "standards.json"
        if machine_registry_path.exists():
            machine_registry = load_json(machine_registry_path)
            gate.equal(
                machine_registry.get("registry_meta", {}).get("authority"),
                "derived_from_canonical_archive",
                "Machine Interface registry authority boundary",
            )
            machine_by_id = {item["canonical_id"]: item for item in machine_registry["standards"]}
        else:
            gate.failed(f"Machine Interface derived registry missing: {machine_registry_path}")

    for standard in standards:
        canonical_id = standard["canonical_id"]
        record_path = args.records_dir / standard["record_filename"]
        check_pdf(gate, standard, record_path, "Records PDF")

        alias = standard.get("canonical_alias_filename")
        if alias:
            alias_path = args.records_dir / alias
            check_pdf(gate, standard, alias_path, "canonical-ID alias")
            if record_path.exists() and alias_path.exists():
                gate.equal(record_path.read_bytes(), alias_path.read_bytes(), f"{canonical_id} legacy filename alias bytes")

        canonical_document = standard.get("canonical_document")
        if canonical_document:
            check_pdf(gate, standard, args.canonical_dir / canonical_document, "Canonical Archive PDF")
        check_signature(gate, standard, args.canonical_dir)
        check_canonical_registry(gate, standard, canonical_by_id)
        if web_source is not None:
            check_web_source(gate, standard, web_source)
        if args.machine_dir:
            machine_artifact = args.machine_dir / "artifacts" / f"{canonical_id}.pdf"
            if machine_artifact.exists():
                check_pdf(gate, standard, machine_artifact, "Machine Interface artifact")
            if machine_by_id is not None:
                mirror = machine_by_id.get(canonical_id)
                if mirror is None:
                    gate.failed(f"{canonical_id} absent from Machine Interface derived registry")
                else:
                    gate.equal(mirror.get("version"), standard["version"], f"{canonical_id} machine mirror version")
                    gate.equal(mirror.get("status"), standard["status"], f"{canonical_id} machine mirror status")

    gate.equal(set(canonical_by_id), set(ids), "Canonical Archive registry membership")
    if machine_by_id is not None:
        gate.equal(set(machine_by_id), set(ids), "Machine Interface mirror membership")
    if args.online:
        check_online(gate, standards, args.base_url.rstrip("/"))

    print("\n=== RuleMark Integrity Gate ===")
    if gate.failures:
        print(f"BLOCKED: {len(gate.failures)} failure(s)")
        for failure in gate.failures:
            print(f" - {failure}")
        return 1
    print(f"PASS: {len(standards)} standard(s) are internally consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
