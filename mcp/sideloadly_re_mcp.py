#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sideloadly_re_mcp.py
~~~~~~~~~~~~~~~~~~~~
Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for Sideloadly Reverse Engineering
and Apple Developer Certificate (.p12 + .mobileprovision) IPA Signing.

Exposes 4 tools:
  - `inspect_apple_cert_bundle`: Parses & validates a .p12 + .mobileprovision folder without
    leaking secret passwords or private key material.
  - `inspect_sideloadly_bundle`: Inspects a Sideloadly.app or Sideloadly-Cert.app bundle
    (Mach-O architectures, dylib proxy status, Python hook status).
  - `sign_ipa_with_cert`: Signs an `.ipa` using either Sideloadly's native `signpipe` engine
    or `zsign`.
  - `verify_signed_ipa`: Verifies a signed `.ipa`'s Mach-O code signature, authorities,
    entitlements, and `embedded.mobileprovision`.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import pathlib
import subprocess
import sys
from typing import Any, Dict

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


TOOLS = [
    {
        "name": "inspect_apple_cert_bundle",
        "description": "Inspect and validate an Apple Developer Certificate folder (.p12 + .mobileprovision + optional PASSWORD.txt) without exposing secret values.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cert_dir": {
                    "type": "string",
                    "description": "Directory containing .p12 and .mobileprovision files.",
                }
            },
            "required": ["cert_dir"],
        },
    },
    {
        "name": "inspect_sideloadly_bundle",
        "description": "Inspect a macOS Sideloadly.app or Sideloadly-Cert.app bundle (Mach-O layout, proxy dylib status, and certificate hook status).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_path": {
                    "type": "string",
                    "description": "Path to Sideloadly.app or Sideloadly-Cert.app.",
                }
            },
            "required": ["app_path"],
        },
    },
    {
        "name": "sign_ipa_with_cert",
        "description": "Sign an iOS .ipa file with a local Apple Developer Certificate (.p12 + .mobileprovision) using Sideloadly's native engine or zsign.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ipa_path": {"type": "string", "description": "Input .ipa file path."},
                "output_path": {"type": "string", "description": "Output signed .ipa file path."},
                "cert_dir": {
                    "type": "string",
                    "description": "Certificate folder path (defaults to ~/Desktop/apple dev certificate).",
                },
                "engine": {
                    "type": "string",
                    "enum": ["sideloadly", "zsign"],
                    "description": "Signing engine to use (sideloadly or zsign).",
                },
                "bundle_id_mode": {
                    "type": "string",
                    "enum": ["keep_original", "match_profile"],
                    "description": "Whether to keep original CFBundleIdentifier or match provisioning profile.",
                },
            },
            "required": ["ipa_path", "output_path"],
        },
    },
    {
        "name": "verify_signed_ipa",
        "description": "Verify the Mach-O signature, Authority chain, TeamIdentifier, embedded.mobileprovision, and entitlements of a signed .ipa.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ipa_path": {"type": "string", "description": "Path to signed .ipa file."}
            },
            "required": ["ipa_path"],
        },
    },
]


def _handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "inspect_apple_cert_bundle":
        cert_dir = pathlib.Path(arguments.get("cert_dir") or cert_hook.DEFAULT_CERT_FOLDER)
        prof = cert_hook.discover_cert_folder(cert_dir)
        if prof is None:
            raise ValueError(f"No .p12 + .mobileprovision found in {cert_dir}")
        prof.load_credentials()
        meta = prof.to_metadata_dict()
        meta["credentials_verified"] = True
        return meta

    if name == "inspect_sideloadly_bundle":
        app_path = pathlib.Path(arguments["app_path"]).expanduser().resolve()
        fw_dir = app_path / "Contents" / "Frameworks"
        main_bin = app_path / "Contents" / "MacOS" / "Sideloadly"
        sl_dylib = fw_dir / "sideloadly.dylib"
        orig_dylib = fw_dir / "sideloadly_orig.dylib"
        hook_py = fw_dir / "sideloadly_cert_hook.py"

        file_out = subprocess.run(
            ["/usr/bin/file", str(main_bin), str(sl_dylib)],
            capture_output=True,
            text=True,
        ).stdout
        return {
            "app_path": str(app_path),
            "exists": app_path.is_dir(),
            "is_patched_with_cert_signing": orig_dylib.is_file() and hook_py.is_file(),
            "has_sideloadly_orig_dylib": orig_dylib.is_file(),
            "has_sideloadly_cert_hook_py": hook_py.is_file(),
            "macho_summary": file_out.strip(),
        }

    if name == "sign_ipa_with_cert":
        cert_dir = pathlib.Path(arguments.get("cert_dir") or cert_hook.DEFAULT_CERT_FOLDER)
        prof = cert_hook.discover_cert_folder(cert_dir)
        if prof is None:
            raise ValueError(f"No .p12 + .mobileprovision found in {cert_dir}")
        prof.bundle_id_mode = arguments.get("bundle_id_mode", "keep_original")
        engine = arguments.get("engine", "sideloadly")
        if engine == "sideloadly":
            return cert_sign_mod.sign_ipa_with_sideloadly_engine(
                profile=prof,
                input_ipa=pathlib.Path(arguments["ipa_path"]),
                output_ipa=pathlib.Path(arguments["output_path"]),
            )
        return cert_sign_mod.sign_ipa_with_zsign(
            profile=prof,
            input_ipa=pathlib.Path(arguments["ipa_path"]),
            output_ipa=pathlib.Path(arguments["output_path"]),
        )

    if name == "verify_signed_ipa":
        return cert_sign_mod.verify_signed_ipa(pathlib.Path(arguments["ipa_path"]))

    raise ValueError(f"Unknown tool: {name}")


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        req_id = req.get("id")
        method = req.get("method")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "sideloadly-re-mcp", "version": "1.0.0"},
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            params = req.get("params") or {}
            t_name = params.get("name", "")
            t_args = params.get("arguments") or {}
            try:
                data = _handle_tool_call(t_name, t_args)
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(data, indent=2)}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: {exc}"}],
                        "isError": True,
                    },
                }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif req_id is not None:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
