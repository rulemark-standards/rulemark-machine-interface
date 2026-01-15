#!/usr/bin/env python3
"""
Publish a canonical record to the rulemark-canonical-archive repository.

Steps:
  - Read canonical/RM-S-DAO-001.json from this repo
  - Transform it into a FROZEN machine record
  - Copy it into machine/RM-S-DAO-001.json in the archive repo
  - Copy the PDF into documents/RM-S-DAO-001.pdf in the archive repo
  - Update registry/standards.json in the archive repo
  - Update or create records/index.html in the archive repo
"""

import json
import shutil
import sys
from pathlib import Path

CANONICAL_ID = "RM-S-DAO-001"
TARGET_REPO_NAME = "rulemark-canonical-archive"


def find_target_repo(source_repo: Path) -> Path:
    """
    Try to locate the target archive repo by walking a few parent levels
    and looking for a directory named TARGET_REPO_NAME.
    """
    # First prefer a child directory inside this repo
    child_candidate = source_repo / TARGET_REPO_NAME
    if not child_candidate.exists():
        child_candidate.mkdir(parents=True, exist_ok=True)
        return child_candidate
    if child_candidate.is_dir():
        return child_candidate

    # Walk a few levels of parents and look for a matching directory name
    parents = [source_repo.parent]
    # Add up to three more parents if they exist
    for i in range(1, 4):
        try:
            parents.append(source_repo.parents[i])
        except IndexError:
            break

    for parent in parents:
        if not parent.exists() or not parent.is_dir():
            continue
        candidate = parent / TARGET_REPO_NAME
        if candidate.exists() and candidate.is_dir():
            return candidate

        # Also scan one level of children for a matching name
        try:
            for child in parent.iterdir():
                if child.is_dir() and child.name == TARGET_REPO_NAME:
                    return child
        except PermissionError:
            continue

    print(f"[ERROR] Target repository '{TARGET_REPO_NAME}' not found near {source_repo}")
    sys.exit(1)


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def publish_canonical():
    source_repo = Path(__file__).resolve().parent.parent
    target_repo = find_target_repo(source_repo)

    print(f"[INFO] Source repo: {source_repo}")
    print(f"[INFO] Target repo: {target_repo}")

    # 1. Load source canonical JSON
    source_json_path = source_repo / "canonical" / f"{CANONICAL_ID}.json"
    if not source_json_path.exists():
        print(f"[ERROR] Source canonical JSON not found: {source_json_path}")
        sys.exit(1)

    data = load_json(source_json_path)

    # 2. Transform into FROZEN machine record for archive
    identity = data.get("identity", {})
    identity["status"] = "FROZEN"
    data["identity"] = identity

    registry = data.get("registry", {})
    registry["registered"] = True
    registry["verified"] = True
    registry["frozen"] = True
    data["registry"] = registry

    artifacts = data.get("artifacts", {})
    primary = artifacts.get("primary_pdf", {})
    primary["path"] = f"documents/{CANONICAL_ID}.pdf"
    artifacts["primary_pdf"] = primary
    data["artifacts"] = artifacts

    # 3. Paths in target repo
    target_machine_dir = target_repo / "machine"
    target_documents_dir = target_repo / "documents"
    target_registry_dir = target_repo / "registry"
    target_records_dir = target_repo / "records"

    target_machine_dir.mkdir(parents=True, exist_ok=True)
    target_documents_dir.mkdir(parents=True, exist_ok=True)
    target_registry_dir.mkdir(parents=True, exist_ok=True)
    target_records_dir.mkdir(parents=True, exist_ok=True)

    # 4. Write machine/RM-S-DAO-001.json
    target_json_path = target_machine_dir / f"{CANONICAL_ID}.json"
    save_json(target_json_path, data)
    print(f"[OK] Wrote {target_json_path}")

    # 5. Copy PDF
    source_pdf_path = source_repo / "artifacts" / f"{CANONICAL_ID}.pdf"
    if not source_pdf_path.exists():
        print(f"[ERROR] Source PDF not found: {source_pdf_path}")
        sys.exit(1)

    target_pdf_path = target_documents_dir / f"{CANONICAL_ID}.pdf"
    shutil.copy2(source_pdf_path, target_pdf_path)
    print(f"[OK] Copied PDF to {target_pdf_path}")

    # 6. Update registry/standards.json
    registry_path = target_registry_dir / "standards.json"
    if registry_path.exists():
        registry_data = load_json(registry_path)
    else:
        registry_data = {
            "registry_meta": {
                "schema_version": "1.0",
                "authority": "sole_source_of_truth",
            },
            "standards": [],
        }

    standards = registry_data.get("standards", [])
    standards = [s for s in standards if s.get("canonical_id") != CANONICAL_ID]
    standards.append(
        {
            "canonical_id": CANONICAL_ID,
            "status": "FROZEN",
            "path": f"machine/{CANONICAL_ID}.json",
        }
    )
    registry_data["standards"] = standards
    save_json(registry_path, registry_data)
    print(f"[OK] Updated {registry_path}")

    # 7. Update records/index.html
    index_path = target_records_dir / "index.html"
    title = data.get("semantics", {}).get("title", CANONICAL_ID)
    category = data.get("presentation", {}).get("category", "Standard")

    entry = (
        f'        <li>\n'
        f'            <a href="../machine/{CANONICAL_ID}.json">{CANONICAL_ID}</a> - '
        f'{title} ({category}, FROZEN)\n'
        f'            <a href="../documents/{CANONICAL_ID}.pdf">[PDF]</a>\n'
        f'        </li>\n'
    )

    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            html = f.read()

        if CANONICAL_ID in html:
            print(f"[WARN] Entry for {CANONICAL_ID} already present in {index_path}")
        elif "</ul>" in html:
            html = html.replace("</ul>", entry + "    </ul>")
            with open(index_path, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[OK] Updated {index_path}")
        else:
            print(f"[WARN] Could not find </ul> in {index_path}; no HTML change applied.")
    else:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RuleMark Canonical Archive - Standards</title>
</head>
<body>
    <h1>RuleMark Canonical Archive</h1>
    <h2>Standards</h2>
    <ul>
{entry}    </ul>
</body>
</html>
"""
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[OK] Created {index_path}")

    print(f"[DONE] Published {CANONICAL_ID} to archive repo (no git commit performed).")


if __name__ == "__main__":
    publish_canonical()

