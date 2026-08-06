import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("alcoa_rubberstamp", RELEASE_ROOT / "alcoa_rubberstamp.py")
rubberstamp = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(rubberstamp)


class RubberStampTests(unittest.TestCase):
    def make_tree(self, root: Path) -> None:
        (root / "nested").mkdir()
        (root / "zeta.txt").write_text("zeta\n", encoding="utf-8")
        (root / "nested" / "alpha.txt").write_text("alpha\n", encoding="utf-8")

    def test_commitment_is_deterministic_and_ordered_by_portable_path(self):
        with tempfile.TemporaryDirectory() as first_tmp, tempfile.TemporaryDirectory() as second_tmp:
            first = Path(first_tmp)
            second = Path(second_tmp)
            self.make_tree(first)
            (second / "nested").mkdir()
            (second / "nested" / "alpha.txt").write_text("alpha\n", encoding="utf-8")
            (second / "zeta.txt").write_text("zeta\n", encoding="utf-8")
            records_one = rubberstamp.collect_records(first)
            records_two = rubberstamp.collect_records(second)
            self.assertEqual(records_one, records_two)
            self.assertEqual(
                rubberstamp.commitment_for(records_one),
                rubberstamp.commitment_for(records_two),
            )

    def test_custom_output_directory_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_tree(root)
            out = root / "custom-proof-output"
            out.mkdir()
            (out / "old.json").write_text("{}", encoding="utf-8")
            excluded = rubberstamp._excluded_relative_dirs(root, out)
            records = rubberstamp.collect_records(root, excluded)
            self.assertEqual(excluded, ["custom-proof-output"])
            self.assertNotIn("custom-proof-output/old.json", [item["path"] for item in records])

    def test_manifest_has_no_absolute_root_and_uses_utc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_tree(root)
            records = rubberstamp.collect_records(root)
            manifest = rubberstamp.build_manifest(
                records, [], None, rubberstamp.NO_PRIOR_STATE
            )
            serialized = json.dumps(manifest)
            self.assertNotIn(str(root), serialized)
            self.assertTrue(manifest["created_at_utc"].endswith("Z"))
            self.assertEqual(manifest["schema"], rubberstamp.MANIFEST_SCHEMA)

    def test_prior_state_changes_commitment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_tree(root)
            records = rubberstamp.collect_records(root)
            prior = {
                "schema": rubberstamp.PRIOR_STATE_SCHEMA,
                "source": "test checkpoint",
                "identifier": "checkpoint-42",
                "observed_at_utc": "2026-08-04T12:00:00Z",
            }
            normalized = rubberstamp.validate_prior_state(prior)
            digest = rubberstamp.hashlib.sha256(
                rubberstamp.canonical_json_bytes(normalized)
            ).digest()
            without = rubberstamp.commitment_for(records)[1]
            with_prior = rubberstamp.commitment_for(records, digest)[1]
            self.assertNotEqual(without, with_prior)

    def test_verify_detects_added_missing_and_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_tree(root)
            records = rubberstamp.collect_records(root)
            manifest = rubberstamp.build_manifest(records, [], None, rubberstamp.NO_PRIOR_STATE)
            self.assertEqual(rubberstamp.verify_tree(root, manifest), [])

            (root / "zeta.txt").write_text("changed\n", encoding="utf-8")
            (root / "nested" / "alpha.txt").unlink()
            (root / "added.txt").write_text("added\n", encoding="utf-8")
            errors = rubberstamp.verify_tree(root, manifest)
            self.assertIn("missing: nested/alpha.txt", errors)
            self.assertIn("added: added.txt", errors)
            self.assertIn("content changed: zeta.txt", errors)

    def test_manifest_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_tree(root)
            records = rubberstamp.collect_records(root)
            manifest = rubberstamp.build_manifest(records, [], None, rubberstamp.NO_PRIOR_STATE)
            manifest["commitment"]["value"] = "0" * 64
            self.assertIn(
                "manifest commitment does not recompute",
                rubberstamp.verify_tree(root, manifest),
            )

    def test_duplicate_manifest_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_tree(root)
            records = rubberstamp.collect_records(root)
            manifest = rubberstamp.build_manifest(records, [], None, rubberstamp.NO_PRIOR_STATE)
            manifest["files"].append(dict(manifest["files"][0]))
            with self.assertRaises(rubberstamp.RubberStampError):
                rubberstamp.validate_manifest_shape(manifest)

    def test_example_fixture_matches_published_vector(self):
        fixture = RELEASE_ROOT / "examples" / "fixture"
        expected = json.loads(
            (RELEASE_ROOT / "examples" / "fixture.expected.json").read_text(encoding="utf-8")
        )
        records = rubberstamp.collect_records(fixture)
        tree, commitment = rubberstamp.commitment_for(records)
        self.assertEqual(records, expected["files"])
        self.assertEqual(tree, expected["file_tree_root"])
        self.assertEqual(commitment, expected["commitment"])

    def test_ots_error_is_nonzero_and_never_reported_as_success(self):
        failed = subprocess.CompletedProcess(["ots"], 9, stdout="", stderr="calendar unavailable")
        with mock.patch.object(rubberstamp.subprocess, "run", return_value=failed):
            with self.assertRaises(rubberstamp.RubberStampError) as raised:
                rubberstamp.run_ots_stamp(Path("commitment.txt"))
        self.assertEqual(raised.exception.exit_code, rubberstamp.EXIT_OTS_FAILED)

    def test_cli_verify_returns_nonzero_for_changed_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "records"
            out = root / "proofs"
            root.mkdir()
            self.make_tree(root)
            self.assertEqual(
                rubberstamp.main(["create", "--root", str(root), "--out", str(out)]),
                0,
            )
            manifest = next(out.glob("alcoa-manifest-*.json"))
            (root / "zeta.txt").write_text("different\n", encoding="utf-8")
            self.assertEqual(
                rubberstamp.main(["verify", "--root", str(root), "--manifest", str(manifest)]),
                rubberstamp.EXIT_VERIFY_FAILED,
            )


if __name__ == "__main__":
    unittest.main()
