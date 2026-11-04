#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_cert_signing.py
~~~~~~~~~~~~~~~~~~~~
End-to-end test suite for Sideloady-with-cert-signing:
  1. Verifies discovery and parsing of the certificate folder (`.p12` + `.mobileprovision`
     + `PASSWORD.txt`) without exposing any secret or personal values.
  2. Verifies the patched `Sideloadly-Cert.app` bundle (`sideloadly.dylib` proxy +
     `sideloadly_orig.dylib` + `sideloadly_cert_hook.py`).
  3. Builds a minimal arm64 iOS `.ipa` fixture and signs it end-to-end with:
     - Sideloadly's hooked `GuiImpactor` + `signpipe.process_ipa` engine
     - `zsign` backend
  4. Verifies `codesign -dvvv`, `Authority`, `TeamIdentifier`, `embedded.mobileprovision`,
     and signed entitlements dynamically against the loaded certificate.
  5. Verifies the `sideloadly_re_mcp.py` JSON-RPC 2.0 MCP server and Advanced Options
     Drag-and-Drop staging state machine.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import sideloadly_cert_hook as cert_hook  # noqa: E402

_loader = importlib.machinery.SourceFileLoader(
    "sideloadly_cert_sign", str(PROJECT_ROOT / "bin" / "sideloadly-cert-sign")
)
_sign_spec = importlib.util.spec_from_loader(_loader.name, _loader)
assert _sign_spec and _sign_spec.loader
cert_sign_mod = importlib.util.module_from_spec(_sign_spec)
_sign_spec.loader.exec_module(cert_sign_mod)


def create_minimal_ios_ipa(ipa_path: pathlib.Path, bundle_id: str = "com.example.testapp") -> pathlib.Path:
    """Build a valid minimal arm64 iOS .ipa bundle for signing tests."""
    with tempfile.TemporaryDirectory(prefix="sl_ipa_build_") as tmp:
        tmp_dir = pathlib.Path(tmp)
        app_dir = tmp_dir / "Payload" / "TestApp.app"
        app_dir.mkdir(parents=True, exist_ok=True)

        c_src = tmp_dir / "main.c"
        c_src.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        bin_path = app_dir / "TestApp"

        sdk_proc = subprocess.run(
            ["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
            capture_output=True,
            text=True,
        )
        if sdk_proc.returncode == 0 and sdk_proc.stdout.strip():
            subprocess.run(
                [
                    "/usr/bin/clang",
                    "-arch",
                    "arm64",
                    "-isysroot",
                    sdk_proc.stdout.strip(),
                    "-miphoneos-version-min=15.0",
                    str(c_src),
                    "-o",
                    str(bin_path),
                ],
                check=True,
            )
        else:
            subprocess.run(
                ["/usr/bin/clang", "-arch", "arm64", str(c_src), "-o", str(bin_path)],
                check=True,
            )

        info_plist = {
            "CFBundleDevelopmentRegion": "en",
            "CFBundleDisplayName": "TestApp",
            "CFBundleExecutable": "TestApp",
            "CFBundleIdentifier": bundle_id,
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": "TestApp",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
            "LSRequiresIPhoneOS": True,
            "MinimumOSVersion": "15.0",
            "UIDeviceFamily": [1, 2],
        }
        (app_dir / "Info.plist").write_bytes(plistlib.dumps(info_plist))

        with zipfile.ZipFile(ipa_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_p in (tmp_dir / "Payload").rglob("*"):
                if file_p.is_file():
                    zf.write(file_p, file_p.relative_to(tmp_dir))

    return ipa_path


class SideloadlyCertSigningTests(unittest.TestCase):
    def test_01_discover_and_validate_certificate_folder(self) -> None:
        prof = cert_hook.discover_cert_folder(cert_hook.DEFAULT_CERT_FOLDER)
        self.assertIsNotNone(prof, "Certificate folder should be discovered")
        assert prof is not None
        self.assertEqual(len(prof.team_id), 10)
        self.assertTrue(len(prof.team_name) > 0)
        self.assertTrue(len(prof.provisioned_devices) >= 1)
        self.assertTrue(prof.app_id_full.startswith(f"{prof.team_id}."))

        cert_obj, pkey_obj, matched_pw = prof.load_credentials()
        self.assertIsNotNone(cert_obj)
        self.assertIsNotNone(pkey_obj)
        self.assertTrue(len(matched_pw) >= 1)

    def test_02_sideloadly_engine_signing_end_to_end(self) -> None:
        prof = cert_hook.discover_cert_folder(cert_hook.DEFAULT_CERT_FOLDER)
        assert prof is not None

        with tempfile.TemporaryDirectory(prefix="sl_test_sign_") as tmp:
            tmp_dir = pathlib.Path(tmp)
            unsigned_ipa = create_minimal_ios_ipa(tmp_dir / "unsigned.ipa", "com.example.demo")
            signed_ipa = tmp_dir / "signed_sideloadly.ipa"

            report = cert_sign_mod.sign_ipa_with_sideloadly_engine(
                profile=prof,
                input_ipa=unsigned_ipa,
                output_ipa=signed_ipa,
            )
            self.assertTrue(report["codesign_valid"])
            self.assertEqual(report["team_identifier"], prof.team_id)
            self.assertTrue(
                any(prof.team_id in auth for auth in report["authorities"]),
            )
            self.assertEqual(report["bundle_id"], "com.example.demo")
            self.assertEqual(
                report["entitlements"].get("application-identifier"),
                prof.app_id_full,
            )
            self.assertEqual(
                report["embedded_profile"].get("uuid"),
                prof.uuid,
            )

    def test_03_zsign_engine_signing_end_to_end(self) -> None:
        prof = cert_hook.discover_cert_folder(cert_hook.DEFAULT_CERT_FOLDER)
        assert prof is not None

        with tempfile.TemporaryDirectory(prefix="sl_test_zsign_") as tmp:
            tmp_dir = pathlib.Path(tmp)
            unsigned_ipa = create_minimal_ios_ipa(tmp_dir / "unsigned.ipa", "com.example.zsigndemo")
            signed_ipa = tmp_dir / "signed_zsign.ipa"

            report = cert_sign_mod.sign_ipa_with_zsign(
                profile=prof,
                input_ipa=unsigned_ipa,
                output_ipa=signed_ipa,
            )
            self.assertTrue(report["codesign_valid"])
            self.assertEqual(report["team_identifier"], prof.team_id)
            self.assertTrue(
                any(prof.team_id in auth for auth in report["authorities"]),
            )

    def test_04_mcp_server_jsonrpc(self) -> None:
        prof = cert_hook.discover_cert_folder(cert_hook.DEFAULT_CERT_FOLDER)
        assert prof is not None

        mcp_script = PROJECT_ROOT / "mcp" / "sideloadly_re_mcp.py"
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "inspect_apple_cert_bundle",
                    "arguments": {"cert_dir": str(cert_hook.DEFAULT_CERT_FOLDER)},
                },
            },
        ]
        stdin_payload = "\n".join(json.dumps(r) for r in requests) + "\n"
        proc = subprocess.run(
            [sys.executable, str(mcp_script)],
            input=stdin_payload,
            capture_output=True,
            text=True,
            check=True,
        )
        lines = [json.loads(ln) for ln in proc.stdout.strip().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 3)
        self.assertEqual(len(lines[1]["result"]["tools"]), 4)
        self.assertFalse(lines[2]["result"]["isError"])
        cert_meta = json.loads(lines[2]["result"]["content"][0]["text"])
        self.assertEqual(cert_meta["team_id"], prof.team_id)
        self.assertTrue(cert_meta["credentials_verified"])

    def test_05_advanced_options_drag_and_drop_staging(self) -> None:
        prof = cert_hook.discover_cert_folder(cert_hook.DEFAULT_CERT_FOLDER)
        assert prof is not None
        p12_file = prof.p12_path
        prov_file = prof.prov_path

        # 1. Clear state first
        st_clear = cert_hook.clear_ui_certificate()
        self.assertEqual(st_clear["status_state"], "idle")

        # 2. Drop .p12 alone -> staged
        st_p12 = cert_hook.stage_dropped_or_selected_paths([str(p12_file)])
        self.assertEqual(st_p12["status_state"], "staged")
        self.assertEqual(st_p12["p12_path"], str(p12_file.resolve()))
        self.assertEqual(st_p12["prov_path"], "")

        # 3. Drop .mobileprovision second -> auto-unlocks via sibling PASSWORD.txt and activates!
        st_both = cert_hook.stage_dropped_or_selected_paths([str(prov_file)])
        self.assertEqual(st_both["status_state"], "active")
        self.assertEqual(st_both["prov_path"], str(prov_file.resolve()))
        self.assertNotIn(" ", st_both["active_account_label"])
        self.assertIn("\u00a0", st_both["active_account_label"])
        self.assertIn(prof.team_id, st_both["active_account_label"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
