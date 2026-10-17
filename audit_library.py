#!/usr/bin/env python3
"""Read-only integrity audit for the Bambu Lab RFID tag library."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from convert import extract_keys_from_blocks
from library_checker import CATEGORY_MAP, MATERIAL_MAP
from parse import (
	BLOCKS_PER_TAG,
	BYTES_PER_BLOCK,
	TOTAL_SECTORS,
	Tag,
	TagDataError,
	bytes_to_hex,
)


UID_RE = re.compile(r"^[0-9A-Fa-f]{8}$")
LEGACY_UID_DIRECTORY_RE = re.compile(r"^([0-9A-Fa-f]{8}) - 250g$")
HEX_UIDS_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?![0-9A-Fa-f])")
HEX_BLOCK_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}|\?\?){16}$")
CONFLICT_RE = re.compile(r"^(?:<<<<<<<|=======|>>>>>>>|\|\|\|\|\|\|\|)(?:\s|$)")
GARBAGE_NAMES = (
	".DS_Store", "Thumbs.db", "desktop.ini", ".gitkeep", ".swp", ".swo",
)
GARBAGE_SUFFIXES = ("~", ".tmp", ".bak", ".orig", ".rej", ".old", ".swp", ".swo")
SUPPORT_DIRS = {
	".git", ".github", ".vscode", "__pycache__", "tests", ".venv",
	"venv", "node_modules", "dist", "build", "target",
}
TAG_JSON_SOURCES = {
	"proxmark3",
	"bambuman",
	"queengooborg/Bambu-Lab-RFID-Library/convert.py",
}
KEY_BYTES = TOTAL_SECTORS * 2 * 6


def _is_relative_to(path: Path, parent: Path) -> bool:
	try:
		path.relative_to(parent)
		return True
	except ValueError:
		return False


@dataclass
class Finding:
	severity: str
	check: str
	path: str
	message: str
	details: Optional[Dict[str, Any]] = None


@dataclass
class TagRecord:
	uid: str
	path: Path
	uid_directory: Path
	data_hash: str
	blocks: List[bytes]
	metadata: Dict[str, Any]
	known: List[List[Optional[bytes]]]


class Audit:
	"""Collect findings and normalized tag records without changing the tree."""

	def __init__(self, root: Path, scope: Optional[Path] = None, strict: bool = False):
		self.root = root.resolve()
		self.scope = scope.resolve() if scope else self.root
		self.strict = strict
		self.findings: List[Finding] = []
		self.counts: Dict[str, int] = defaultdict(int)
		self.records: List[TagRecord] = []
		self.category_colors: Dict[Tuple[str, str, str], Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
		self.material_ids: Dict[Tuple[str, str, str], Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
		self.variant_locations: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
		self.dump_hashes: Dict[str, List[Tuple[str, str, Path]]] = defaultdict(list)
		self.uid_records: Dict[str, List[TagRecord]] = defaultdict(list)

	def report(
		self,
		severity: str,
		check: str,
		path: Path,
		message: str,
		details: Optional[Dict[str, Any]] = None,
	) -> None:
		if severity == "WARNING" and self.strict:
			severity = "ERROR"
		try:
			display_path = path.resolve().relative_to(self.root).as_posix()
		except ValueError:
			display_path = str(path)
		self.findings.append(Finding(severity, check, display_path or ".", message, details))

	def run(self) -> Dict[str, Any]:
		if not self.root.is_dir():
			raise OSError(f"Audit root is not a directory: {self.root}")
		if not self.scope.exists():
			raise OSError(f"Audit path does not exist: {self.scope}")
		if not _is_relative_to(self.scope.resolve(), self.root):
			raise OSError(f"Audit path must be inside repository root: {self.scope}")

		self._scan_repository_text()
		for data_root in self._data_roots():
			self._scan_data_root(data_root)
		self._check_indexes()
		self._check_cross_directory_color_variants()
		return self.report_data()

	def report_data(self) -> Dict[str, Any]:
		counts = {
			"errors": sum(f.severity == "ERROR" for f in self.findings),
			"warnings": sum(f.severity == "WARNING" for f in self.findings),
			"info": sum(f.severity == "INFO" for f in self.findings),
		}
		return {
			"summary": {
				"uid_directories_scanned": self.counts["uid_directories"],
				"valid_dumps": self.counts["valid_dumps"],
				"invalid_dumps": self.counts["invalid_dumps"],
				"key_files_checked": self.counts["key_files"],
				"json_files_checked": self.counts["json_files"],
				"nfc_files_checked": self.counts["nfc_files"],
				**counts,
			},
			"findings": [asdict(f) for f in sorted(self.findings, key=lambda x: (x.severity, x.path, x.check, x.message))],
		}

	def _is_selected(self, path: Path) -> bool:
		return _is_relative_to(path.resolve(), self.scope)

	def _data_roots(self) -> List[Path]:
		if self.scope == self.root:
			return sorted(
				(p for p in self.root.iterdir() if p.is_dir() and p.name not in SUPPORT_DIRS and not p.name.startswith(".")),
				key=lambda p: p.name.casefold(),
			)
		parts = self.scope.relative_to(self.root).parts
		if not parts:
			return []
		root = self.root / parts[0]
		if root.is_dir() and root.name not in SUPPORT_DIRS and not root.name.startswith("."):
			return [root]
		return []

	def _scan_repository_text(self) -> None:
		"""Look for merge markers in textual source and data files."""
		text_suffixes = {".py", ".yml", ".yaml", ".md", ".txt", ".json", ".nfc", ".dic", ".toml", ".ini", ".cfg"}
		for base, dirs, files in os.walk(self.root):
			base_path = Path(base)
			dirs[:] = [d for d in dirs if d not in (SUPPORT_DIRS - {".github", "tests"}) and d != ".git"]
			for name in files:
				path = base_path / name
				if not self._is_selected(path) and self.scope != self.root:
					continue
				if path.suffix.lower() not in text_suffixes and name not in {"README", "LICENSE"}:
					continue
				try:
					text = path.read_text(encoding="utf-8")
				except UnicodeDecodeError as exc:
					if self._is_data_path(path):
						self.report("ERROR", "INVALID_TEXT_ENCODING", path, f"Text file is not valid UTF-8: {exc}")
					continue
				except OSError as exc:
					self.report("ERROR", "READ_ERROR", path, f"Could not read file: {exc}")
					continue
				for line_number, line in enumerate(text.splitlines(), 1):
					if CONFLICT_RE.match(line.strip()):
						self.report(
							"ERROR", "MERGE_CONFLICT_MARKER", path,
							f"Unresolved merge marker on line {line_number}",
							{"line": line_number, "content": line[:160]},
						)

	def _is_data_path(self, path: Path) -> bool:
		try:
			first = path.relative_to(self.root).parts[0]
		except (ValueError, IndexError):
			return False
		return first not in SUPPORT_DIRS and not first.startswith(".")

	def _scan_data_root(self, data_root: Path) -> None:
		for base, dirs, files in os.walk(data_root, topdown=True):
			path = Path(base)
			if not self._is_selected(path):
				dirs[:] = [
					d for d in dirs
					if _is_relative_to((path / d).resolve(), self.scope)
					or _is_relative_to(self.scope, (path / d).resolve())
				]
				continue
			rel = path.relative_to(self.root)
			level = len(rel.parts)
			dirs[:] = sorted((d for d in dirs if d not in SUPPORT_DIRS), key=str.casefold)
			if not dirs and not files:
				self.report("WARNING", "EMPTY_DIRECTORY", path, "Directory contains no files or subdirectories")
			if len(rel.parts) >= 4 and len(rel.parts) > 4:
				self.report("ERROR", "UNEXPECTED_NESTING", path, "Directories beneath a UID directory are not part of the documented layout")
				dirs[:] = []
				continue
			if level == 4:
				self._audit_uid_directory(path, files, dirs)
				# UID folders may not contain another directory level.
				dirs[:] = []
				continue
			for name in files:
				file_path = path / name
				self._audit_basic_file(file_path)
				if level < 4 and name not in {"README.md", "_attribution.txt"}:
					self.report("WARNING", "UNEXPECTED_FILE_LOCATION", file_path, "Data files are expected inside a UID directory")
			if level > 4:
				for name in files:
					self.report("ERROR", "UNEXPECTED_NESTING", path / name, "File is nested below the UID directory level")

	def _audit_basic_file(self, path: Path) -> None:
		try:
			size = path.stat().st_size
		except OSError as exc:
			self.report("ERROR", "READ_ERROR", path, f"Could not stat file: {exc}")
			return
		if size == 0:
			self.report("ERROR", "ZERO_LENGTH_FILE", path, "File is empty")
		if path.name in GARBAGE_NAMES or path.name.endswith(GARBAGE_SUFFIXES):
			self.report("WARNING", "TEMPORARY_FILE", path, "File name matches a common OS/editor temporary artifact")

	def _audit_uid_directory(self, path: Path, filenames: Sequence[str], child_dirs: Sequence[str]) -> None:
		self.counts["uid_directories"] += 1
		uid_dir = path.name
		legacy_match = LEGACY_UID_DIRECTORY_RE.fullmatch(uid_dir)
		if UID_RE.fullmatch(uid_dir):
			directory_uid = uid_dir.upper()
			if uid_dir != uid_dir.upper():
				self.report("INFO", "NONCANONICAL_UID_CASE", path, "UID directory uses lowercase hexadecimal characters")
		elif legacy_match:
			directory_uid = legacy_match.group(1).upper()
			self.report("WARNING", "NONCANONICAL_UID_DIRECTORY", path, "Legacy UID directory includes a ' - 250g' annotation; the embedded 8-digit UID is still checked")
		else:
			directory_uid = ""
			self.report("ERROR", "BAD_UID_DIRECTORY", path, "UID directory name must contain exactly 8 hexadecimal characters")
		parts = path.relative_to(self.root).parts
		if len(parts) >= 4 and parts[-2] == parts[-3]:
			self.report("ERROR", "DUPLICATED_DIRECTORY_LEVEL", path, "Material and color directory names are identical")
		if child_dirs:
			for name in child_dirs:
				self.report("ERROR", "UNEXPECTED_NESTING", path / name, "UID directory contains a nested directory")
		files = [path / n for n in filenames]
		if not files:
			self.report("WARNING", "EMPTY_UID_DIRECTORY", path, "UID directory contains no files")
		for file_path in files:
			self._audit_basic_file(file_path)

		valid_dumps: List[Tuple[Path, Tag, bytes, str]] = []
		valid_json: List[Tuple[Path, List[bytes], List[List[Optional[bytes]]], str, Tag]] = []
		valid_nfc: List[Tuple[Path, List[bytes], List[List[Optional[bytes]]], str, Tag]] = []
		key_files: List[Path] = []

		for file_path in files:
			name = file_path.name
			if file_path.suffix.lower() in {".bin", ".json", ".nfc"}:
				self._check_filename_uid(file_path, directory_uid)
			if file_path.suffix.lower() == ".bin":
				if name.lower().endswith("-dump.bin"):
					tag, raw, warnings = self._parse_tag_file(file_path, "INVALID_DUMP", count="valid_dumps")
					if tag is not None and raw is not None:
						digest = hashlib.sha256(raw).hexdigest()
						valid_dumps.append((file_path, tag, raw, digest))
						self.dump_hashes[digest].append((tag.data["uid"], self._rel(file_path), file_path))
						if directory_uid and tag.data["uid"].upper() != directory_uid:
							self.report("ERROR", "UID_MISMATCH", file_path, "UID parsed from dump block 0 does not match its UID directory", {"directory_uid": directory_uid, "dump_uid": tag.data["uid"].upper()})
						self._check_block_zero(file_path, tag)
						self._check_metadata(file_path, tag, path)
						self._check_location(file_path, tag, parts)
					else:
						self.counts["invalid_dumps"] += 1
				elif name.lower().endswith("-key.bin"):
					key_files.append(file_path)
					self.counts["key_files"] += 1
				else:
					self.report("WARNING", "UNKNOWN_FILE", file_path, "Binary file is not named as a recognized dump or key file")
			elif file_path.suffix.lower() == ".json":
				if re.search(r"-dump(?:-?\d+)?-dump\.json$", name, re.IGNORECASE) or name.lower().endswith("-dump.json"):
					record = self._audit_json_dump(file_path, directory_uid)
					if record:
						valid_json.append(record)
				else:
					self._audit_auxiliary_text(file_path)
					if name.lower().endswith(("-decrypted.json", "-keys.json")):
						self.report("INFO", "AUXILIARY_FILE", file_path, "Recognized optional JSON sidecar; not treated as a canonical full dump")
					else:
						self.report("WARNING", "UNKNOWN_FILE", file_path, "JSON file is not a recognized dump or known auxiliary sidecar")
			elif file_path.suffix.lower() == ".nfc":
				record = self._audit_nfc(file_path, directory_uid)
				if record:
					valid_nfc.append(record)
				self.counts["nfc_files"] += 1
			elif file_path.suffix.lower() in {".txt", ".dic", ".md"} or name == "_attribution.txt":
				self._audit_auxiliary_text(file_path)
				if file_path.suffix.lower() == ".dic":
					self.report("INFO", "AUXILIARY_FILE", file_path, "Recognized optional key dictionary sidecar")
				elif name.endswith("-parsed.txt"):
					self.report("INFO", "AUXILIARY_FILE", file_path, "Recognized optional parsed-text sidecar")
				elif name not in {"README.md", "_attribution.txt"}:
					self.report("WARNING", "UNKNOWN_FILE", file_path, "Text file is not a recognized tag sidecar")
			else:
				self.report("WARNING", "UNKNOWN_FILE", file_path, "File extension is not part of a recognized tag representation")

		key_sources = [(dump_path, tag.blocks) for dump_path, tag, _, _ in valid_dumps]
		if not key_sources:
			key_sources.extend((source_path, blocks) for source_path, blocks, _, _, _ in valid_json)
		for key_path in key_files:
			self._audit_key_file(key_path, key_sources, directory_uid)

		for source_path, tag, raw, digest in valid_dumps:
			self._add_record(tag.data["uid"], source_path, path, digest, tag.blocks, tag.data, self._known_binary_blocks(tag.blocks))
		for source_path, blocks, known, uid, json_tag in valid_json:
			for dump_path, dump_tag, raw, _ in valid_dumps:
				self._compare_known_blocks(source_path, blocks, known, dump_path, raw, "JSON_DUMP_MISMATCH", self._known_binary_blocks(dump_tag.blocks))
			if not valid_dumps:
				self._check_metadata(source_path, json_tag, path)
				self._check_location(source_path, json_tag, parts)
			raw = b"".join(blocks)
			self._add_record(uid, source_path, path, hashlib.sha256(raw).hexdigest(), blocks, json_tag.data, known)
		for source_path, blocks, known, uid, nfc_tag in valid_nfc:
			for dump_path, dump_tag, raw, _ in valid_dumps:
				self._compare_known_blocks(source_path, blocks, known, dump_path, raw, "NFC_DUMP_MISMATCH", self._known_binary_blocks(dump_tag.blocks))
			if not valid_dumps and not valid_json and all(all(v is not None for v in block) for block in known):
				self._check_metadata(source_path, nfc_tag, path)
				self._check_location(source_path, nfc_tag, parts)
			raw = b"".join(blocks)
			self._add_record(uid, source_path, path, hashlib.sha256(raw).hexdigest(), blocks, nfc_tag.data, known)

		if key_files and not (valid_dumps or valid_json or valid_nfc):
			for key_path in key_files:
				self.report("WARNING", "ORPHAN_KEY_FILE", key_path, "Key file has no valid dump, JSON dump, or NFC representation in this UID directory")
		if valid_dumps:
			present = {"dump.bin", "key.bin" if key_files else "", "dump.json" if valid_json else "", ".nfc" if valid_nfc else ""} - {""}
			missing = [n for n in ("key.bin", "dump.json", ".nfc") if n not in present]
			if missing:
				self.report("INFO", "MISSING_GENERATED_FORMATS", path, "Optional generated representation(s) are absent: " + ", ".join(missing), {"missing": missing})
		elif valid_json or valid_nfc:
			self.report("INFO", "MISSING_PRIMARY_BINARY", path, "No canonical binary dump is present; another valid tag representation is available")

	def _parse_tag_file(self, path: Path, check: str, count: Optional[str] = None) -> Tuple[Optional[Tag], Optional[bytes], List[str]]:
		try:
			raw = path.read_bytes()
		except OSError as exc:
			self.report("ERROR", "READ_ERROR", path, f"Could not read tag file: {exc}")
			return None, None, []
		if not raw:
			return None, raw, []
		try:
			tag = Tag(path.name, raw, fail_on_warn=True)
		except TagDataError as strict_exc:
			try:
				tag = Tag(path.name, raw, fail_on_warn=False)
			except Exception as exc:
				self.report("ERROR", check, path, f"Tag parser rejected the data: {exc}")
				return None, raw, []
			warnings = list(tag.warnings)
			for warning in warnings:
				self.report("WARNING", "DUMP_PARSE_WARNING", path, warning)
			if not warnings:
				self.report("WARNING", "DUMP_PARSE_WARNING", path, str(strict_exc))
		except Exception as exc:
			self.report("ERROR", check, path, f"Tag parser rejected the data: {exc}")
			return None, raw, []
		else:
			warnings = list(tag.warnings)
		if count:
			self.counts[count] += 1
		return tag, raw, warnings

	def _check_block_zero(self, path: Path, tag: Tag) -> None:
		if not tag.blocks:
			return
		block = tag.blocks[0]
		expected_bcc = block[0] ^ block[1] ^ block[2] ^ block[3]
		if block[4] != expected_bcc:
			self.report("ERROR", "INVALID_MANUFACTURER_BLOCK", path, "Block 0 UID checksum (BCC) does not match the first four UID bytes", {"expected_bcc": f"{expected_bcc:02X}", "actual_bcc": f"{block[4]:02X}"})

	def _check_metadata(self, path: Path, tag: Tag, uid_directory: Path) -> None:
		data = tag.data
		for field in ("filament_type", "detailed_filament_type", "material_id", "variant_id"):
			if not str(data.get(field, "")).strip():
				self.report("WARNING", "SUSPICIOUS_METADATA", path, f"Parsed {field} is empty", {"field": field})
		colors = str(data.get("filament_color", "" )).split(" / ")
		if not colors or any(not re.fullmatch(r"#[0-9A-Fa-f]{8}", color) for color in colors):
			self.report("ERROR", "INVALID_COLOR_METADATA", path, "Parsed filament color is not a valid 4-byte hexadecimal color", {"filament_color": data.get("filament_color")})
		diameter = data.get("filament_diameter")
		if diameter and (not math.isfinite(diameter.value) or diameter.value <= 0):
			self.report("ERROR", "SUSPICIOUS_METADATA", path, "Filament diameter is non-finite or not positive", {"value": diameter.value})
		elif diameter and diameter.value > 5:
			self.report("WARNING", "SUSPICIOUS_METADATA", path, "Filament diameter is unusually large", {"value": diameter.value})
		for field in ("spool_weight", "filament_length"):
			value = data.get(field)
			if value and (value.value < 0 or value.value > 10000):
				self.report("WARNING", "SUSPICIOUS_METADATA", path, f"Parsed {field} is outside the broad expected range", {"value": value.value})
		for name, value in data.get("temperatures", {}).items():
			if getattr(value, "unit", None) == "C" and (value.value > 400 or value.value < -20):
				self.report("WARNING", "SUSPICIOUS_METADATA", path, f"Parsed temperature {name} is unusual", {"value": value.value})
		date = data.get("production_date")
		if isinstance(date, str) and date and "_" in date:
			self.report("WARNING", "SUSPICIOUS_METADATA", path, "Production date-like field could not be interpreted as a date", {"value": date})

	def _check_location(self, path: Path, tag: Tag, parts: Sequence[str]) -> None:
		if len(parts) < 4:
			return
		category_dir, material_dir, color_dir = parts[-4:-1]
		category = tag.data["filament_type"]
		expected_category = CATEGORY_MAP.get(category, category)
		if category_dir != expected_category:
			self.report("ERROR", "WRONG_CATEGORY", path, f"Tag category {category!r} belongs under {expected_category!r}, not {category_dir!r}", {"category": category, "expected": expected_category, "actual": category_dir})
		material = tag.data["detailed_filament_type"]
		mapped = MATERIAL_MAP.get(material, [])
		allowed = list(mapped) if isinstance(mapped, list) else [mapped]
		if material not in allowed:
			allowed.append(material)
		if material_dir not in allowed:
			self.report("ERROR", "WRONG_MATERIAL", path, f"Tag material {material!r} is not mapped to directory {material_dir!r}", {"material": material, "allowed_directories": allowed, "actual": material_dir})
		location = (category_dir, material_dir, color_dir)
		color = str(tag.data.get("filament_color", ""))
		self.category_colors[location][color].append(self._rel(path))
		material_id = str(tag.data.get("material_id", ""))
		self.material_ids[location][material_id].append(self._rel(path))
		variant = str(tag.data.get("variant_id", ""))
		self.variant_locations[(category_dir, material_dir, variant)].append(color_dir)

	def _check_filename_uid(self, path: Path, directory_uid: str) -> None:
		if path.suffix.lower() not in {".bin", ".json", ".nfc"}:
			return
		if not UID_RE.fullmatch(directory_uid):
			return
		found = set(HEX_UIDS_RE.findall(path.name.upper()))
		if found and directory_uid.upper() not in found:
			self.report("ERROR", "UID_MISMATCH", path, "UID embedded in filename does not match its UID directory", {"directory_uid": directory_uid.upper(), "filename_uids": sorted(found)})

	def _audit_key_file(self, path: Path, sources: Sequence[Tuple[Path, List[bytes]]], directory_uid: str) -> None:
		try:
			keys = path.read_bytes()
		except OSError as exc:
			self.report("ERROR", "READ_ERROR", path, f"Could not read key file: {exc}")
			return
		if len(keys) != KEY_BYTES:
			self.report("ERROR", "INVALID_KEY_FILE", path, f"Key file must contain {KEY_BYTES} bytes for the 16 Key A and 16 Key B values (found {len(keys)})", {"expected_bytes": KEY_BYTES, "actual_bytes": len(keys)})
			return
		key_values = [keys[i:i + 6] for i in range(0, len(keys), 6)]
		missing_key_indices = [i for i, key in enumerate(key_values) if key in (b"\x00" * 6, b"\xFF" * 6)]
		if missing_key_indices:
			self.report("WARNING", "SUSPICIOUS_KEY_SET", path, "Key file contains all-zero or all-FF key placeholders", {"key_slots": missing_key_indices})
		for dump_path, blocks in sources:
			try:
				expected = b"".join(extract_keys_from_blocks(blocks))
			except Exception as exc:
				self.report("ERROR", "INVALID_KEY_FILE", path, f"Could not extract keys from {dump_path.name}: {exc}")
				continue
			if len(expected) != KEY_BYTES:
				self.report("WARNING", "KEY_FORMAT_SCOPE", path, f"Parser exposes {len(expected)} key bytes from this dump; key file stores {KEY_BYTES}")
			else:
				mismatch = None
				for key_index in range(TOTAL_SECTORS * 2):
					expected_key = expected[key_index * 6:(key_index + 1) * 6]
					file_key = keys[key_index * 6:(key_index + 1) * 6]
					placeholders = (b"\x00" * 6, b"\xFF" * 6)
					if expected_key in placeholders or file_key in placeholders:
						continue  # Either representation may mark an unavailable key.
					if expected_key != file_key:
						mismatch = (key_index % TOTAL_SECTORS, "A" if key_index < TOTAL_SECTORS else "B")
						break
				if mismatch:
					sector, key_type = mismatch
					self.report("WARNING", "KEY_MISMATCH", path, f"Key file Key {key_type} differs from dump sector {sector}; the sidecar may contain a separately recovered key", {"dump": self._rel(dump_path), "sector": sector, "key_type": key_type})

	def _audit_json_dump(self, path: Path, directory_uid: str) -> Optional[Tuple[Path, List[bytes], List[List[Optional[bytes]]], str, Tag]]:
		self.counts["json_files"] += 1
		try:
			text = path.read_text(encoding="utf-8")
			obj = json.loads(text)
		except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
			self.report("ERROR", "INVALID_JSON", path, f"Dump JSON could not be decoded: {exc}")
			return None
		if not isinstance(obj, dict):
			self.report("ERROR", "INVALID_JSON", path, "Dump JSON top-level value must be an object")
			return None
		if obj.get("FileType") not in (None, "mfc v2"):
			self.report("ERROR", "INVALID_JSON", path, "Dump JSON FileType must be 'mfc v2'", {"file_type": obj.get("FileType")})
		if obj.get("Created") not in TAG_JSON_SOURCES:
			self.report("WARNING", "JSON_SOURCE_UNRECOGNIZED", path, "Dump JSON Created field is missing or not one of the repository's known sources", {"created": obj.get("Created")})
		blocks_obj = obj.get("blocks")
		if not isinstance(blocks_obj, dict):
			self.report("ERROR", "INVALID_JSON", path, "Dump JSON must contain a blocks object")
			return None
		try:
			indices = sorted(int(k) for k in blocks_obj)
		except (TypeError, ValueError):
			self.report("ERROR", "INVALID_JSON", path, "Block keys must be integer block numbers")
			return None
		if indices not in [list(range(n)) for n in BLOCKS_PER_TAG]:
			self.report("ERROR", "INVALID_JSON", path, f"Dump JSON must contain a contiguous supported block map ({BLOCKS_PER_TAG} blocks)", {"block_count": len(indices)})
			return None
		blocks: List[bytes] = []
		known: List[List[Optional[bytes]]] = []
		for i in indices:
			value = blocks_obj.get(str(i), blocks_obj.get(i))
			if not isinstance(value, str) or not HEX_BLOCK_RE.fullmatch(value):
				self.report("ERROR", "INVALID_JSON", path, f"Block {i} must contain exactly 16 hexadecimal bytes (or ?? unknown-byte markers)")
				return None
			pairs = [value[j:j + 2] for j in range(0, len(value), 2)]
			known_block = [None if pair == "??" else bytes.fromhex(pair) for pair in pairs]
			known.append(known_block)
			blocks.append(bytes(0 if byte is None else byte[0] for byte in known_block))
		if obj.get("FileType") == "mfc v2" and "Card" not in obj:
			self.report("ERROR", "INVALID_JSON", path, "mfc v2 dump is missing its Card object")
		card = obj.get("Card", {})
		json_uid = card.get("UID") if isinstance(card, dict) else None
		if json_uid is not None:
			if not isinstance(json_uid, str) or not UID_RE.fullmatch(json_uid.replace(" ", "")):
				self.report("ERROR", "INVALID_JSON", path, "Card.UID must be an 8-digit hexadecimal UID", {"uid": json_uid})
			else:
				json_uid = json_uid.replace(" ", "").upper()
				if UID_RE.fullmatch(directory_uid) and json_uid != directory_uid.upper():
					self.report("ERROR", "UID_MISMATCH", path, "JSON UID does not match its UID directory", {"directory_uid": directory_uid.upper(), "json_uid": json_uid})
		else:
			self.report("ERROR", "INVALID_JSON", path, "Dump JSON is missing Card.UID")
		block_uid = bytes_to_hex(blocks[0][:4])
		if UID_RE.fullmatch(directory_uid) and block_uid != directory_uid.upper():
			self.report("ERROR", "UID_MISMATCH", path, "UID parsed from JSON block 0 does not match its UID directory", {"directory_uid": directory_uid.upper(), "json_block_uid": block_uid})
		if json_uid and json_uid != block_uid:
			self.report("ERROR", "UID_MISMATCH", path, "Card.UID disagrees with the UID stored in block 0", {"card_uid": json_uid, "block_uid": block_uid})
		self._check_sector_keys(path, obj, blocks, known)
		tag = self._tag_from_blocks(path, blocks)
		if not tag:
			return None
		self._check_block_zero(path, tag)
		return path, blocks, known, block_uid, tag

	def _check_sector_keys(self, path: Path, obj: Dict[str, Any], blocks: List[bytes], known: List[List[Optional[bytes]]]) -> None:
		sector_keys = obj.get("SectorKeys")
		if sector_keys is None:
			self.report("INFO", "JSON_SECTOR_KEYS_ABSENT", path, "SectorKeys metadata is absent; block trailer keys remain available for validation")
			return
		if not isinstance(sector_keys, dict):
			self.report("ERROR", "INVALID_JSON", path, "SectorKeys must be an object")
			return
		for sector in range(TOTAL_SECTORS):
			entry = sector_keys.get(str(sector))
			if not isinstance(entry, dict):
				self.report("ERROR", "INVALID_JSON", path, f"SectorKeys is missing sector {sector}")
				continue
			trailer = sector * 4 + 3
			for key_name, offset in (("KeyA", 0), ("KeyB", 10)):
				value = entry.get(key_name)
				if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}|\?\?){6}", value):
					self.report("ERROR", "INVALID_JSON", path, f"Sector {sector} {key_name} must contain six hexadecimal bytes")
					continue
				for i in range(6):
					pair = value[i * 2:i * 2 + 2]
					expected = known[trailer][offset + i]
					if pair != "??" and expected is not None and bytes.fromhex(pair) != expected:
						self.report("ERROR", "KEY_MISMATCH", path, f"JSON sector {sector} {key_name} disagrees with block trailer")
						break
				# Captures may zero/fill with FF an unreadable key. Those are the
				# invalid-key sentinels used by Tag, so treat them as unknown here.
				if value.upper() in {"000000000000", "FFFFFFFFFFFF"}:
					for i in range(6):
						known[trailer][offset + i] = None

	def _audit_nfc(self, path: Path, directory_uid: str) -> Optional[Tuple[Path, List[bytes], List[List[Optional[bytes]]], str, Tag]]:
		try:
			text = path.read_text(encoding="utf-8")
		except (OSError, UnicodeDecodeError) as exc:
			self.report("ERROR", "INVALID_NFC", path, f"NFC file is not valid UTF-8 text: {exc}")
			return None
		headers: Dict[str, str] = {}
		block_lines: Dict[int, str] = {}
		for line_number, line in enumerate(text.splitlines(), 1):
			line = line.strip()
			if not line or line.startswith("#"):
				continue
			if ":" not in line:
				self.report("ERROR", "INVALID_NFC", path, f"Malformed NFC line {line_number}: missing ':'")
				return None
			key, value = (part.strip() for part in line.split(":", 1))
			match = re.fullmatch(r"Block\s+(\d+)", key)
			if match:
				index = int(match.group(1))
				if index in block_lines:
					self.report("ERROR", "INVALID_NFC", path, f"Duplicate block {index}")
					return None
				block_lines[index] = value
			else:
				if key in headers:
					self.report("ERROR", "INVALID_NFC", path, f"Duplicate NFC header {key}")
					return None
				headers[key] = value
		expected_headers = {
			"Filetype": "Flipper NFC device",
			"Version": "4",
			"Device type": "Mifare Classic",
			"Mifare Classic type": "1K",
			"Data format version": "2",
		}
		for key, value in expected_headers.items():
			if headers.get(key) != value:
				self.report("ERROR", "INVALID_NFC", path, f"Expected {key}: {value}", {"actual": headers.get(key)})
		if sorted(block_lines) != list(range(64)):
			self.report("ERROR", "INVALID_NFC", path, "Mifare Classic 1K NFC capture must contain blocks 0 through 63", {"blocks_found": len(block_lines)})
			return None
		blocks: List[bytes] = []
		known: List[List[Optional[bytes]]] = []
		for index in range(64):
			parts = block_lines[index].split()
			if len(parts) != BYTES_PER_BLOCK or any(not re.fullmatch(r"[0-9A-Fa-f]{2}|\?\?", p) for p in parts):
				self.report("ERROR", "INVALID_NFC", path, f"Block {index} must contain 16 hex bytes or ?? markers")
				return None
			known_block = [None if p == "??" else bytes.fromhex(p) for p in parts]
			known.append(known_block)
			blocks.append(bytes(0 if b is None else b[0] for b in known_block))
		for trailer in range(3, len(blocks), 4):
			for offset in (0, 10):
				key = blocks[trailer][offset:offset + 6]
				if key in (b"\x00" * 6, b"\xFF" * 6):
					known[trailer][offset:offset + 6] = [None] * 6
		file_uid = self._parse_uid_header(path, headers.get("UID"))
		block_uid = bytes_to_hex(blocks[0][:4])
		if file_uid and UID_RE.fullmatch(directory_uid) and file_uid != directory_uid.upper():
			self.report("ERROR", "UID_MISMATCH", path, "NFC UID does not match its UID directory", {"directory_uid": directory_uid.upper(), "nfc_uid": file_uid})
		uid_bytes_known = all(byte is not None for byte in known[0][:4])
		if UID_RE.fullmatch(directory_uid) and uid_bytes_known and block_uid != directory_uid.upper():
			self.report("ERROR", "UID_MISMATCH", path, "NFC block 0 UID does not match its UID directory", {"directory_uid": directory_uid.upper(), "block_uid": block_uid})
		if file_uid and uid_bytes_known and file_uid != block_uid:
			self.report("ERROR", "UID_MISMATCH", path, "NFC UID header disagrees with block 0", {"header_uid": file_uid, "block_uid": block_uid})
		if headers.get("ATQA"):
			atqa = re.sub(r"\s+", "", headers["ATQA"]).upper()
			if not re.fullmatch(r"[0-9A-F]{4}", atqa) or atqa != blocks[0][6:8][::-1].hex().upper():
				self.report("ERROR", "INVALID_NFC", path, "ATQA header is invalid or disagrees with block 0")
		if headers.get("SAK"):
			sak = re.sub(r"\s+", "", headers["SAK"]).upper()
			if not re.fullmatch(r"[0-9A-F]{2}", sak) or sak != f"{blocks[0][5]:02X}":
				self.report("ERROR", "INVALID_NFC", path, "SAK header is invalid or disagrees with block 0")
		# Tag parsing is applied to reconstructed memory; unknown bytes remain zero only for
		# parser field extraction, and never participate in byte comparisons below.
		tag = self._tag_from_blocks(path, blocks, report_warnings=False)
		if not tag:
			return None
		return path, blocks, known, file_uid or block_uid, tag

	def _parse_uid_header(self, path: Path, value: Optional[str]) -> Optional[str]:
		if value is None:
			self.report("ERROR", "INVALID_NFC", path, "NFC file is missing its UID header")
			return None
		uid = re.sub(r"\s+", "", value).upper()
		if not UID_RE.fullmatch(uid):
			self.report("ERROR", "INVALID_NFC", path, "NFC UID must contain four hexadecimal bytes", {"uid": value})
			return None
		return uid

	def _tag_from_blocks(self, path: Path, blocks: List[bytes], report_warnings: bool = True) -> Optional[Tag]:
		raw = b"".join(blocks)
		try:
			tag = Tag(path.name, raw, fail_on_warn=True)
		except TagDataError as strict_exc:
			try:
				tag = Tag(path.name, raw, fail_on_warn=False)
			except Exception as exc:
				self.report("ERROR", "INVALID_TAG_DATA", path, f"Tag parser rejected reconstructed data: {exc}")
				return None
			if report_warnings:
				for warning in tag.warnings or [str(strict_exc)]:
					self.report("WARNING", "DUMP_PARSE_WARNING", path, warning)
		except Exception as exc:
			self.report("ERROR", "INVALID_TAG_DATA", path, f"Tag parser rejected reconstructed data: {exc}")
			return None
		return tag

	def _compare_known_blocks(
		self,
		left_path: Path,
		left_blocks: List[bytes],
		left_known: List[List[Optional[bytes]]],
		right_path: Path,
		right_raw: bytes,
		check: str,
		right_known: Optional[List[List[Optional[bytes]]]] = None,
	) -> None:
		right_blocks = [right_raw[i:i + BYTES_PER_BLOCK] for i in range(0, len(right_raw), BYTES_PER_BLOCK)]
		if right_known is None:
			right_known = [[bytes([byte]) for byte in block] for block in right_blocks]
		if len(left_blocks) != len(right_blocks):
			if {len(left_blocks), len(right_blocks)} == {64, 72}:
				self.report("INFO", "REPRESENTATION_BLOCK_COUNT", left_path, "Accepted 64-block and 72-block recovery representations; comparing shared blocks", {"other": self._rel(right_path), "left_blocks": len(left_blocks), "right_blocks": len(right_blocks)})
			else:
				self.report("ERROR", check, left_path, "Representations contain different block counts", {"other": self._rel(right_path), "left_blocks": len(left_blocks), "right_blocks": len(right_blocks)})
				return
		mismatches = []
		for block_index in range(min(len(left_blocks), len(right_blocks))):
			for byte_index, expected in enumerate(left_known[block_index]):
				actual = right_known[block_index][byte_index]
				if expected is not None and actual is not None and expected != actual:
					mismatches.append({"block": block_index, "byte": byte_index})
					break
		if mismatches:
			first = mismatches[0]
			self.report(
				"ERROR", check, left_path,
				f"Block {first['block']} differs from {right_path.name} at byte {first['byte']}",
				{"other": self._rel(right_path), "mismatch_count": len(mismatches), "mismatches": mismatches[:32]},
			)

	def _audit_auxiliary_text(self, path: Path) -> None:
		try:
			text = path.read_text(encoding="utf-8")
		except (OSError, UnicodeDecodeError) as exc:
			self.report("ERROR", "INVALID_TEXT_ENCODING", path, f"Text sidecar is not valid UTF-8: {exc}")
			return
		if text and not text.strip():
			self.report("WARNING", "WHITESPACE_ONLY_FILE", path, "Text file contains only whitespace")

	def _add_record(
		self,
		uid: str,
		path: Path,
		uid_directory: Path,
		digest: str,
		blocks: List[bytes],
		metadata: Dict[str, Any],
		known: Optional[List[List[Optional[bytes]]]] = None,
	) -> None:
		if known is None:
			known = [[bytes([byte]) for byte in block] for block in blocks]
		record = TagRecord(uid.upper(), path, uid_directory, digest, blocks, metadata, known)
		self.records.append(record)
		self.uid_records[record.uid].append(record)

	def _known_binary_blocks(self, blocks: List[bytes]) -> List[List[Optional[bytes]]]:
		known: List[List[Optional[bytes]]] = [[bytes([byte]) for byte in block] for block in blocks]
		for block_index, block in enumerate(blocks):
			if block_index % 4 != 3:
				continue
			for offset in (0, 10):
				key = block[offset:offset + 6]
				if key in (b"\x00" * 6, b"\xFF" * 6):
					known[block_index][offset:offset + 6] = [None] * 6
		return known

	def _records_compatible(self, left: TagRecord, right: TagRecord) -> bool:
		if len(left.blocks) != len(right.blocks) and {len(left.blocks), len(right.blocks)} != {64, 72}:
			return False
		for block_index in range(min(len(left.blocks), len(right.blocks))):
			for byte_index in range(BYTES_PER_BLOCK):
				a = left.known[block_index][byte_index]
				b = right.known[block_index][byte_index]
				if a is not None and b is not None and a != b:
					return False
		return True

	def _check_indexes(self) -> None:
		for digest, entries in self.dump_hashes.items():
			if len(entries) > 1:
				paths = sorted({p for _, p, _ in entries})
				severity = "ERROR" if len({uid for uid, _, _ in entries}) > 1 else "WARNING"
				self.report(severity, "DUPLICATE_DUMP", entries[0][2], "Identical binary dump content appears more than once", {"sha256": digest, "paths": paths})
		for uid, records in self.uid_records.items():
			locations: Dict[Path, set] = defaultdict(set)
			for record in records:
				locations[record.uid_directory].add(record.data_hash)
			conflicting_pair = next(
				((left, right) for index, left in enumerate(records) for right in records[index + 1:] if not self._records_compatible(left, right)),
				None,
			)
			if conflicting_pair:
				left, right = conflicting_pair
				paths = sorted(self._rel(p) for p in locations)
				self.report("ERROR", "DUPLICATE_UID_CONFLICT", left.path, f"UID {uid} appears with conflicting known data", {"uid": uid, "paths": paths, "conflicting_paths": [self._rel(left.path), self._rel(right.path)]})
			elif len(locations) > 1:
				paths = sorted(self._rel(p) for p in locations)
				self.report("WARNING", "DUPLICATE_UID", next(iter(records)).path, f"UID {uid} appears in multiple directories with identical or compatible data", {"uid": uid, "paths": paths})
		for location, colors in self.category_colors.items():
			if len(colors) > 1:
				self.report("ERROR", "COLOR_CONFLICT", self.root.joinpath(*location), "Tags in the same color directory contain multiple parsed color values", {"colors": {k: v for k, v in colors.items()}})
		for location, ids in self.material_ids.items():
			if len(ids) > 1:
				self.report("WARNING", "MATERIAL_ID_CONFLICT", self.root.joinpath(*location), "Tags in the same color directory contain multiple material identifiers", {"material_ids": {k: v for k, v in ids.items()}})

	def _check_cross_directory_color_variants(self) -> None:
		for (category, material, variant), colors in self.variant_locations.items():
			unique = sorted(set(colors))
			if variant and len(unique) > 1:
				self.report("INFO", "VARIANT_IN_MULTIPLE_COLOR_DIRECTORIES", self.root / category / material, "A variant identifier appears under multiple color directory names", {"variant_id": variant, "color_directories": unique})

	def _rel(self, path: Path) -> str:
		try:
			return path.resolve().relative_to(self.root).as_posix()
		except ValueError:
			return str(path)


def render_report(report: Dict[str, Any], only_errors: bool = False, verbose: bool = False) -> str:
	summary = report["summary"]
	lines = [
		"RFID Library Audit",
		"==================",
		"",
		f"UID directories scanned: {summary['uid_directories_scanned']:>8}",
		f"Valid dumps:             {summary['valid_dumps']:>8}",
		f"Invalid dumps:           {summary['invalid_dumps']:>8}",
		f"Key files checked:       {summary['key_files_checked']:>8}",
		f"JSON files checked:      {summary['json_files_checked']:>8}",
		f"NFC files checked:       {summary['nfc_files_checked']:>8}",
		"",
		f"Errors:   {summary['errors']}",
		f"Warnings: {summary['warnings']}",
		f"Info:     {summary['info']}",
	]
	levels = ["ERROR"] if only_errors else ["ERROR", "WARNING"] + (["INFO"] if verbose else [])
	for level in levels:
		findings = [f for f in report["findings"] if f["severity"] == level]
		if not findings:
			continue
		lines.extend(["", level + "S", "-" * (len(level) + 1)])
		for finding in findings:
			lines.append(f"[{finding['check']}] {finding['path']}")
			lines.append(f"  {finding['message']}")
			if verbose and finding.get("details"):
				lines.append(f"  details: {json.dumps(finding['details'], sort_keys=True, default=str)}")
	return "\n".join(lines)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Read-only audit of Bambu Lab RFID library data")
	parser.add_argument("--verbose", action="store_true", help="Show informational findings and finding details")
	parser.add_argument("--json", metavar="FILE", help="Write the structured audit report to FILE")
	parser.add_argument("--only-errors", action="store_true", help="Print only ERROR-level findings")
	parser.add_argument("--path", default=".", help="Audit this path under the repository root")
	parser.add_argument("--strict", action="store_true", help="Promote WARNING findings to ERROR")
	return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
	args = parse_args(argv)
	root = Path(__file__).resolve().parent
	requested_path = Path(args.path)
	scope = (requested_path if requested_path.is_absolute() else root / requested_path).resolve()
	try:
		audit = Audit(root, scope=scope, strict=args.strict)
		report = audit.run()
		print(render_report(report, args.only_errors, args.verbose))
		if args.json:
			out = Path(args.json)
			if not out.is_absolute():
				out = Path.cwd() / out
			out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
		return 1 if report["summary"]["errors"] else 0
	except Exception as exc:
		print(f"Audit failed internally: {type(exc).__name__}: {exc}", file=sys.stderr)
		return 2


if __name__ == "__main__":
	raise SystemExit(main())
