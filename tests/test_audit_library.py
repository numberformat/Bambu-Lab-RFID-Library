import json
import struct
import tempfile
import unittest
from pathlib import Path

from audit_library import Audit
from convert import extract_keys_from_blocks, write_dump_json, write_flipper_nfc
from parse import Tag


def make_dump(uid="11223344", color=b"\xFF\x55\x00\x00", serial=0):
	uid_bytes = bytes.fromhex(uid)
	blocks = [bytearray(16) for _ in range(64)]
	blocks[0][:4] = uid_bytes
	blocks[0][4] = uid_bytes[0] ^ uid_bytes[1] ^ uid_bytes[2] ^ uid_bytes[3]
	blocks[0][5] = 0x08
	blocks[0][6:8] = b"\x04\x00"
	blocks[1][:8] = b"A00-A0\x00\x00"
	blocks[1][8:16] = b"10300\x00\x00\x00"
	blocks[2][:3] = b"PLA"
	blocks[4][:9] = b"PLA Basic"
	blocks[5][:4] = color
	blocks[5][4:6] = (1200).to_bytes(2, "little")
	blocks[5][8:12] = struct.pack("<f", 1.75)
	blocks[6][0:2] = (50).to_bytes(2, "little")
	blocks[6][2:4] = (8).to_bytes(2, "little")
	blocks[6][6:8] = (60).to_bytes(2, "little")
	blocks[6][8:10] = (220).to_bytes(2, "little")
	blocks[6][10:12] = (190).to_bytes(2, "little")
	blocks[8][12:16] = struct.pack("<f", 0.4)
	blocks[9][:4] = b"TRAY"
	blocks[10][4:6] = (1000).to_bytes(2, "little")
	blocks[12][:16] = b"2025_01_02_03_04"
	blocks[13][:16] = b"2025_01_02_03_04"
	blocks[14][4:6] = (330).to_bytes(2, "little")
	blocks[16][:4] = b"\x01\x00\x01\x00"
	blocks[17][:2] = b"\x00\x00"
	blocks[13][15] = serial
	for sector in range(16):
		trailer = blocks[sector * 4 + 3]
		trailer[:6] = bytes([0x20 + sector]) * 6
		trailer[6:10] = bytes.fromhex("FF078069")
		trailer[10:16] = bytes([0x40 + sector]) * 6
	return b"".join(blocks)


class AuditLibraryTests(unittest.TestCase):
	def setUp(self):
		self.temp = tempfile.TemporaryDirectory()
		self.root = Path(self.temp.name)

	def tearDown(self):
		self.temp.cleanup()

	def uid_dir(self, uid="11223344", category="PLA", material="PLA Basic", color="Orange"):
		path = self.root / category / material / color / uid
		path.mkdir(parents=True, exist_ok=True)
		return path

	def write_dump(self, directory, data=None, filename_uid=None):
		data = data or make_dump(directory.name)
		filename_uid = filename_uid or directory.name
		path = directory / f"hf-mf-{filename_uid}-dump.bin"
		path.write_bytes(data)
		return path

	def write_bundle(self, directory, data=None, include_key=True, include_json=True, include_nfc=True):
		data = data or make_dump(directory.name)
		dump = self.write_dump(directory, data)
		tag = Tag(dump.name, data, fail_on_warn=True)
		if include_key:
			(directory / f"hf-mf-{directory.name}-key.bin").write_bytes(b"".join(extract_keys_from_blocks(tag.blocks)))
		if include_json:
			write_dump_json(directory / f"hf-mf-{directory.name}-dump.json", tag)
		if include_nfc:
			write_flipper_nfc(directory / f"hf-mf-{directory.name}.nfc", tag)
		return data

	def findings(self):
		return Audit(self.root).run()["findings"]

	def checks(self):
		return {f["check"] for f in self.findings()}

	def test_valid_uid_directory(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_key=False, include_json=False, include_nfc=False)
		findings = self.findings()
		self.assertNotIn("ERROR", {f["severity"] for f in findings})
		self.assertIn("MISSING_GENERATED_FORMATS", {f["check"] for f in findings})

	def test_empty_directory(self):
		(self.root / "PLA" / "PLA Basic" / "Orange" / "11223344").mkdir(parents=True)
		self.assertIn("EMPTY_UID_DIRECTORY", self.checks())

	def test_zero_byte_dump(self):
		directory = self.uid_dir()
		(self.write_dump(directory)).write_bytes(b"")
		self.assertIn("ZERO_LENGTH_FILE", self.checks())

	def test_truncated_dump(self):
		directory = self.uid_dir()
		self.write_dump(directory, b"\x00" * 32)
		self.assertIn("INVALID_DUMP", self.checks())

	def test_malformed_uid_directory(self):
		directory = self.uid_dir(uid="ABC123")
		self.write_dump(directory, make_dump("11223344"), filename_uid="ABC123")
		self.assertIn("BAD_UID_DIRECTORY", self.checks())

	def test_directory_uid_vs_dump_uid_mismatch(self):
		directory = self.uid_dir(uid="11223344")
		self.write_dump(directory, make_dump("AABBCCDD"), filename_uid="11223344")
		self.assertIn("UID_MISMATCH", self.checks())

	def test_key_file_wrong_length(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_key=False, include_json=False, include_nfc=False)
		(directory / f"hf-mf-{directory.name}-key.bin").write_bytes(b"\x00" * 12)
		self.assertIn("INVALID_KEY_FILE", self.checks())

	def test_keys_disagree_with_dump(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_json=False, include_nfc=False)
		key = directory / f"hf-mf-{directory.name}-key.bin"
		content = bytearray(key.read_bytes())
		content[0] ^= 1
		key.write_bytes(content)
		self.assertIn("KEY_MISMATCH", self.checks())

	def test_malformed_json(self):
		directory = self.uid_dir()
		self.write_dump(directory)
		(directory / f"hf-mf-{directory.name}-dump.json").write_text("{bad json", encoding="utf-8")
		self.assertIn("INVALID_JSON", self.checks())

	def test_json_uid_mismatch(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_key=False, include_nfc=False)
		path = directory / f"hf-mf-{directory.name}-dump.json"
		obj = json.loads(path.read_text())
		obj["Card"]["UID"] = "AABBCCDD"
		path.write_text(json.dumps(obj), encoding="utf-8")
		self.assertIn("UID_MISMATCH", self.checks())

	def test_json_block_mismatch(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_key=False, include_nfc=False)
		path = directory / f"hf-mf-{directory.name}-dump.json"
		obj = json.loads(path.read_text())
		obj["blocks"]["5"] = "00" * 16
		path.write_text(json.dumps(obj), encoding="utf-8")
		self.assertIn("JSON_DUMP_MISMATCH", self.checks())

	def test_malformed_nfc(self):
		directory = self.uid_dir()
		self.write_dump(directory)
		(directory / f"hf-mf-{directory.name}.nfc").write_text("not an NFC capture\n", encoding="utf-8")
		self.assertIn("INVALID_NFC", self.checks())

	def test_nfc_uid_mismatch(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_key=False, include_json=False)
		path = directory / f"hf-mf-{directory.name}.nfc"
		text = path.read_text()
		path.write_text(text.replace("UID: 11 22 33 44", "UID: AA BB CC DD"), encoding="utf-8")
		self.assertIn("UID_MISMATCH", self.checks())

	def test_duplicate_identical_dump(self):
		first = self.uid_dir(color="Orange")
		self.write_dump(first)
		second = self.uid_dir(color="Orange Copy")
		self.write_dump(second)
		checks = self.checks()
		self.assertIn("DUPLICATE_DUMP", checks)
		self.assertIn("DUPLICATE_UID", checks)

	def test_same_uid_with_conflicting_dumps(self):
		first = self.uid_dir(color="Orange")
		self.write_dump(first, make_dump(serial=1))
		second = self.uid_dir(color="Orange Copy")
		self.write_dump(second, make_dump(serial=2))
		self.assertIn("DUPLICATE_UID_CONFLICT", self.checks())

	def test_unexpected_file(self):
		directory = self.uid_dir()
		self.write_dump(directory)
		(directory / "notes.exe").write_bytes(b"artifact")
		self.assertIn("UNKNOWN_FILE", self.checks())

	def test_unresolved_git_conflict_marker(self):
		directory = self.uid_dir()
		self.write_dump(directory)
		(directory / "notes.txt").write_text("<<<<<<< HEAD\nconflict\n=======\nother\n>>>>>>> branch\n", encoding="utf-8")
		self.assertIn("MERGE_CONFLICT_MARKER", self.checks())

	def test_wrong_category_and_material_location(self):
		category_dir = self.uid_dir(category="ABS")
		self.write_dump(category_dir)
		material_dir = self.uid_dir(uid="AABBCCDD", category="PLA", material="PLA Matte")
		self.write_dump(material_dir, make_dump("AABBCCDD"))
		checks = self.checks()
		self.assertIn("WRONG_CATEGORY", checks)
		self.assertIn("WRONG_MATERIAL", checks)

	def test_multiple_colors_in_one_color_directory(self):
		first = self.uid_dir(uid="11223344")
		self.write_dump(first, make_dump("11223344", color=b"\xFF\x55\x00\x00"))
		second = self.uid_dir(uid="AABBCCDD")
		self.write_dump(second, make_dump("AABBCCDD", color=b"\x00\x55\xFF\x00"))
		self.assertIn("COLOR_CONFLICT", self.checks())

	def test_generated_formats_match(self):
		directory = self.uid_dir()
		self.write_bundle(directory)
		findings = self.findings()
		self.assertNotIn("ERROR", {f["severity"] for f in findings})
		self.assertEqual(1, Audit(self.root).run()["summary"]["valid_dumps"])

	def test_proxmark_json_zero_key_b_is_treated_as_unknown(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_nfc=False)
		path = directory / f"hf-mf-{directory.name}-dump.json"
		obj = json.loads(path.read_text())
		obj["Created"] = "proxmark3"
		for sector in range(16):
			trailer = sector * 4 + 3
			obj["blocks"][str(trailer)] = obj["blocks"][str(trailer)][:20] + "00" * 6
			obj["SectorKeys"][str(sector)]["KeyB"] = "000000000000"
		path.write_text(json.dumps(obj), encoding="utf-8")
		findings = self.findings()
		self.assertNotIn("JSON_DUMP_MISMATCH", {f["check"] for f in findings})
		self.assertNotIn("ERROR", {f["severity"] for f in findings})

	def test_flipper_zero_key_b_is_treated_as_unknown(self):
		directory = self.uid_dir()
		self.write_bundle(directory, include_key=False, include_json=False)
		path = directory / f"hf-mf-{directory.name}.nfc"
		lines = path.read_text().splitlines()
		for index, line in enumerate(lines):
			if line.startswith("Block 3:"):
				parts = line.split()
				lines[index] = " ".join(parts[:12] + ["00"] * 6)
		path.write_text("\n".join(lines) + "\n", encoding="utf-8")
		findings = self.findings()
		self.assertNotIn("NFC_DUMP_MISMATCH", {f["check"] for f in findings})
		self.assertNotIn("ERROR", {f["severity"] for f in findings})

	def test_partial_binary_representation_is_compatible_with_full_dump(self):
		directory = self.uid_dir()
		data = make_dump(directory.name)
		self.write_bundle(directory, data, include_json=False, include_nfc=True)
		partial = bytearray(data)
		for trailer in range(3, 64, 4):
			partial[trailer * 16 + 10:trailer * 16 + 16] = b"\x00" * 6
		(directory / f"PLA-CF-Black-sample-{directory.name}-dump.bin").write_bytes(partial)
		findings = self.findings()
		checks = {f["check"] for f in findings}
		self.assertNotIn("NFC_DUMP_MISMATCH", checks)
		self.assertNotIn("DUPLICATE_UID_CONFLICT", checks)
		self.assertNotIn("KEY_MISMATCH", checks)

	def test_72_block_json_matches_shared_binary_blocks(self):
		directory = self.uid_dir()
		data = make_dump(directory.name)
		self.write_dump(directory, data)
		extra_blocks = [bytearray(16) for _ in range(8)]
		for sector in range(2):
			trailer = extra_blocks[sector * 4 + 3]
			trailer[:6] = bytes([0x60 + sector]) * 6
			trailer[6:10] = bytes.fromhex("FF078069")
			trailer[10:16] = bytes([0x70 + sector]) * 6
		tag = Tag("recovery", data + b"".join(extra_blocks), fail_on_warn=True)
		write_dump_json(directory / f"hf-mf-{directory.name}-dump18-dump.json", tag)
		findings = self.findings()
		self.assertNotIn("JSON_DUMP_MISMATCH", {f["check"] for f in findings})
		self.assertIn("REPRESENTATION_BLOCK_COUNT", {f["check"] for f in findings})

	def test_path_scope_reaches_uid_directory(self):
		directory = self.uid_dir()
		self.write_dump(directory)
		report = Audit(self.root, scope=directory).run()
		self.assertEqual(1, report["summary"]["uid_directories_scanned"])


if __name__ == "__main__":
	unittest.main()
