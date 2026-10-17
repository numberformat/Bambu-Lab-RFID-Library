#!/usr/bin/env python3
"""Poll the upstream GitHub fork network and import validated RFID tag records."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from parse import Tag  # noqa: E402


UPSTREAM = "queengooborg/Bambu-Lab-RFID-Library"
WORKFLOW_FILE = "network-tag-import.yml"
API_ROOT = "https://api.github.com"
UID_PATTERN = re.compile(r"[0-9A-Fa-f]{8}\Z")
FORK_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
ALLOWED_SUFFIXES = (".bin", ".json", ".nfc")
MAX_AUXILIARY_FILE_SIZE = 5 * 1024 * 1024

# These mappings mirror the repository's library_checker.py conventions.
CATEGORY_MAP = {
    "PA-S": "Support Material",
    "PLA-S": "Support Material",
    "Support": "Support Material",
    "PVA": "Support Material",
    "ABS-S": "Support Material",
    "PETG-CF": "PETG",
    "TPU-AMS": "TPU",
    "ABS-GF": "ABS",
    "PLA-CF": "PLA",
    "PA-CF": "PA",
    "ASA-CF": "ASA",
    "ASA Aero": "ASA",
}
MATERIAL_MAP = {
    "Support for PA": ["Support for PA-PET"],
    "Support For PA": ["Support for PA-PET"],
    "Support G": ["Support for PA-PET"],
    "Support W": ["Support for PLA-PETG"],
    "Support for PLA": ["Support for PLA (New Version)", "Support for PLA-PETG"],
    "PETG-CF": ["PETG CF"],
    "PETG HF": ["PETG Translucent"],
    "PLA Basic": ["PLA Basic Gradient", "PLA Silk Multi-Color"],
    "PLA Silk": ["PLA Silk Multi-Color"],
    "PLA": ["PLA Silk Multi-Color"],
}


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=REPOSITORY_ROOT,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def api_pages(url: str):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required to inspect the fork network")

    while url:
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "Bambu-Lab-RFID-Library-fork-import",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.load(response)
                link_header = response.headers.get("Link", "")
        except (HTTPError, URLError, TimeoutError) as error:
            raise RuntimeError(f"GitHub API request failed for {url}: {error}") from error

        if isinstance(payload, list):
            yield from payload
        elif isinstance(payload, dict) and isinstance(payload.get("workflow_runs"), list):
            yield from payload["workflow_runs"]
        else:
            yield payload
            return

        next_url = ""
        for link in link_header.split(","):
            if 'rel="next"' in link:
                next_url = link[link.find("<") + 1 : link.find(">")]
                break
        url = next_url


def previous_successful_run_time() -> datetime:
    repository = os.environ["GITHUB_REPOSITORY"]
    current_run_id = int(os.environ["GITHUB_RUN_ID"])
    url = (
        f"{API_ROOT}/repos/{repository}/actions/workflows/{WORKFLOW_FILE}/runs"
        "?branch=main&status=completed&per_page=100"
    )
    for run in api_pages(url):
        if run.get("id", current_run_id) >= current_run_id:
            continue
        if run.get("conclusion") == "success" and run.get("run_started_at"):
            return parse_time(run["run_started_at"]) - timedelta(hours=1)

    # On first activation, catch recent fork pushes without importing the full
    # historical network. A manual dispatch can request a full backfill.
    return datetime.now(timezone.utc) - timedelta(hours=24)


def recent_push_events(repository: str, cutoff: datetime):
    owner, name = repository.split("/", 1)
    url = f"{API_ROOT}/repos/{owner}/{name}/events?per_page=100"
    for event in api_pages(url):
        if not isinstance(event, dict):
            continue
        created_at = event.get("created_at")
        if not created_at or parse_time(created_at) < cutoff:
            # Events are returned newest first, so older pages cannot match.
            break
        if event.get("type") != "PushEvent":
            continue
        payload = event.get("payload", {})
        ref = payload.get("ref", "")
        head = payload.get("head", "")
        before = payload.get("before", "")
        if ref.startswith("refs/heads/") and re.fullmatch(r"[0-9a-fA-F]{40}", head):
            yield {
                "created_at": created_at,
                "head": head,
                "before": (
                    before
                    if re.fullmatch(r"[0-9a-fA-F]{40}", before) and set(before) != {"0"}
                    else ""
                ),
            }


def fork_network_repositories() -> list[dict]:
    pending = [UPSTREAM]
    visited = {UPSTREAM.lower()}
    repositories = []

    while pending:
        parent = pending.pop(0)
        owner, name = parent.split("/", 1)
        url = f"{API_ROOT}/repos/{owner}/{name}/forks?per_page=100&sort=newest"
        for fork in api_pages(url):
            full_name = fork.get("full_name", "")
            if not FORK_NAME_PATTERN.fullmatch(full_name):
                continue
            key = full_name.lower()
            if key in visited:
                continue
            visited.add(key)
            repositories.append(fork)
            pending.append(full_name)

    return repositories


def fetch_commit(repository: str, sha: str, fetched: set[str]) -> None:
    if sha in fetched:
        return
    if git("cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode != 0:
        url = f"https://github.com/{repository}.git"
        try:
            git("fetch", "--no-tags", "--depth=1", url, sha)
        except subprocess.CalledProcessError as error:
            message = error.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(f"Could not fetch {repository}@{sha}: {message}") from error
    fetched.add(sha)


def added_paths(base: str, head: str) -> list[str]:
    raw = git("diff", "--diff-filter=A", "--name-only", "-z", base, head).stdout
    paths = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            paths.append(encoded.decode("ascii"))
        except UnicodeDecodeError:
            continue
    return paths


def deleted_paths(base: str, head: str) -> list[str]:
    # Disable rename detection so a move also counts as deleting the old path.
    raw = git(
        "diff", "--no-renames", "--diff-filter=D", "--name-only", "-z", base, head
    ).stdout
    return [path.decode("utf-8", "replace") for path in raw.split(b"\0") if path]


def tag_directory_for_dump(path: str) -> tuple[str, str] | None:
    pure_path = PurePosixPath(path)
    parts = pure_path.parts
    if len(parts) != 5 or pure_path.is_absolute():
        return None
    category, material, color, uid, filename = parts
    if (
        category.startswith(".")
        or not UID_PATTERN.fullmatch(uid)
        or not filename.endswith("-dump.bin")
    ):
        return None
    if any(part in {"", ".", ".."} or "\n" in part or "\r" in part for part in parts):
        return None
    if not (REPOSITORY_ROOT / category).is_dir():
        return None
    return "/".join(parts[:4]), uid.upper()


def read_blob(revision: str, path: str) -> bytes:
    return git("show", f"{revision}:{path}").stdout


def tree_paths(revision: str, directory: str) -> list[str]:
    raw = git("ls-tree", "-r", "-z", "--name-only", revision, "--", directory).stdout
    paths = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            paths.append(encoded.decode("ascii"))
        except UnicodeDecodeError:
            continue
    return paths


def known_uids() -> set[str]:
    result = set()
    for path in REPOSITORY_ROOT.glob("*/*/*/*"):
        if path.is_dir() and UID_PATTERN.fullmatch(path.name):
            result.add(path.name.upper())
    return result


def parse_tag(filename: str, data: bytes) -> Tag:
    # Keep parser warnings visible on the Tag, but don't reject otherwise
    # parseable dumps for non-fatal issues such as blank blocks or missing keys.
    return Tag(filename, data)


def check_location(tag: Tag, directory: str) -> str | None:
    category_dir, material_dir, _color_dir, uid_dir = directory.split("/")
    category = tag.data["filament_type"]
    material = tag.data["detailed_filament_type"]
    expected_category = CATEGORY_MAP.get(category, category)
    material_options = MATERIAL_MAP.get(material, material)
    if not isinstance(material_options, list):
        material_options = [material_options]
    if material not in material_options:
        material_options.append(material)

    if category_dir != expected_category:
        return f"folder category is {category_dir!r}; expected {expected_category!r}"
    if material_dir not in material_options:
        return f"folder material is {material_dir!r}; expected one of {material_options!r}"
    if tag.data["uid"].upper() != uid_dir.upper():
        return f"folder UID is {uid_dir}; dump contains UID {tag.data['uid']}"
    return None


def existing_colors(directory: str, category: str, material: str) -> set[str]:
    color_dir = REPOSITORY_ROOT / directory
    colors = set()
    if not color_dir.is_dir():
        return colors
    for path in color_dir.rglob("*-dump.bin"):
        try:
            tag = parse_tag(str(path), path.read_bytes())
        except Exception:
            continue
        if (
            tag.data["filament_type"] == category
            and tag.data["detailed_filament_type"] == material
        ):
            colors.add(tag.data["filament_color"])
    return colors


def allowed_payload(path: str, tag_directory: str) -> bool:
    pure_path = PurePosixPath(path)
    if str(pure_path.parent) != tag_directory:
        return False
    if not pure_path.name.isascii() or pure_path.name.startswith("."):
        return False
    return pure_path.name.lower().endswith(ALLOWED_SUFFIXES)


def companion_matches_tag(path: str, payload: bytes, primary_tag: Tag) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".bin":
        return PurePosixPath(path).name.lower().endswith("-key.bin")
    try:
        companion = parse_tag(path, payload)
    except Exception as error:
        print(f"Ignoring companion file {path}: it failed tag parsing ({error})")
        return False

    for field in ("uid", "filament_type", "detailed_filament_type", "filament_color"):
        if companion.data[field] != primary_tag.data[field]:
            print(f"Ignoring companion file {path}: {field} does not match the validated dump")
            return False
    return True


def main() -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    scan_all = os.environ.get("SCAN_ALL", "false").lower() == "true"
    cutoff = datetime.min.replace(tzinfo=timezone.utc) if scan_all else previous_successful_run_time()
    current_repository = repository.lower()
    known = known_uids()
    proposed_uids: set[str] = set()
    imported_paths: set[str] = set()
    color_cache: dict[tuple[str, str, str, str], set[str]] = {}
    fetched: set[str] = set()
    seen_pushes: set[tuple[str, str, str]] = set()

    forks = fork_network_repositories()
    print(f"Checking {len(forks)} repositories in the upstream fork network")

    for fork in forks:
        full_name = fork.get("full_name", "")
        if (
            not FORK_NAME_PATTERN.fullmatch(full_name)
            or full_name.lower() in {UPSTREAM.lower(), current_repository}
        ):
            continue
        pushed_at = fork.get("pushed_at")
        if not pushed_at or (not scan_all and parse_time(pushed_at) < cutoff):
            continue

        for event in recent_push_events(full_name, cutoff):
            key = (full_name.lower(), event["before"], event["head"])
            if key in seen_pushes:
                continue
            seen_pushes.add(key)
            head = event["head"]
            base = event["before"] or "HEAD"
            try:
                fetch_commit(full_name, head, fetched)
                if event["before"]:
                    fetch_commit(full_name, event["before"], fetched)
            except RuntimeError as error:
                print(f"Ignoring unavailable push {full_name}@{head}: {error}")
                continue

            if base != "HEAD" and git("cat-file", "-e", f"{base}^{{commit}}", check=False).returncode != 0:
                print(f"Ignoring push {full_name}@{head}: its before commit is unavailable")
                continue

            removals = deleted_paths(base, head)
            if removals:
                examples = ", ".join(repr(path) for path in removals[:5])
                remainder = len(removals) - 5
                if remainder > 0:
                    examples += f", and {remainder} more"
                print(
                    f"Ignoring push {full_name}@{head}: it deletes {len(removals)} "
                    f"tracked file(s) ({examples})"
                )
                continue

            candidates: dict[str, tuple[str, str]] = {}
            for path in added_paths(base, head):
                record = tag_directory_for_dump(path)
                if record:
                    tag_directory, uid = record
                    candidates.setdefault(tag_directory, (path, uid))

            for tag_directory, (dump_path, uid) in candidates.items():
                if uid in known or uid in proposed_uids:
                    print(f"Ignoring {dump_path}: UID {uid} is already present")
                    continue
                try:
                    dump = read_blob(head, dump_path)
                    tag = parse_tag(dump_path, dump)
                except Exception as error:
                    print(f"Ignoring {dump_path}: tag dump failed validation ({error})")
                    continue

                if tag.warnings:
                    print(f"Accepting {dump_path} with non-blocking parser warnings:")
                    for warning in tag.warnings:
                        print(f"  - {warning}")

                location_error = check_location(tag, tag_directory)
                if location_error:
                    print(f"Ignoring {dump_path}: {location_error}")
                    continue

                category = tag.data["filament_type"]
                material = tag.data["detailed_filament_type"]
                color_folder = "/".join(tag_directory.split("/")[:3])
                existing_key = (color_folder, category, material, "")
                if existing_key not in color_cache:
                    color_cache[existing_key] = existing_colors(color_folder, category, material)
                colors = color_cache[existing_key]
                if colors and colors != {tag.data["filament_color"]}:
                    print(
                        f"Ignoring {dump_path}: its color {tag.data['filament_color']!r} "
                        f"conflicts with existing color data {sorted(colors)!r} in {color_folder}"
                    )
                    continue

                # Copy recognized tag data files only. Scripts, documentation,
                # parsed text output, archives, and unrelated artifacts are excluded.
                for candidate_path in tree_paths(head, tag_directory):
                    if not allowed_payload(candidate_path, tag_directory):
                        continue
                    if candidate_path.endswith("-dump.bin") and candidate_path != dump_path:
                        continue
                    try:
                        payload = read_blob(head, candidate_path)
                    except subprocess.CalledProcessError:
                        continue
                    if len(payload) > MAX_AUXILIARY_FILE_SIZE:
                        print(f"Ignoring oversized companion file {candidate_path}")
                        continue
                    if candidate_path != dump_path and not companion_matches_tag(candidate_path, payload, tag):
                        continue

                    destination = REPOSITORY_ROOT / candidate_path
                    if destination.exists():
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(payload)
                    imported_paths.add(candidate_path)

                if dump_path not in imported_paths:
                    print(f"Ignoring {dump_path}: no new tag payload files were available to import")
                    continue
                proposed_uids.add(uid)
                color_cache[existing_key] = {tag.data["filament_color"]}
                print(f"Accepted tag UID {uid} from {full_name}: {tag_directory}")
    if imported_paths:
        paths = sorted(imported_paths)
        for offset in range(0, len(paths), 100):
            git("add", "--", *paths[offset : offset + 100])
        print(f"Staged {len(imported_paths)} recognized files for {len(proposed_uids)} new tag(s)")
        changed = "true"
    else:
        print("No newly added, quality-checked RFID tags found")
        changed = "false"

    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as output:
            output.write(f"changed={changed}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
