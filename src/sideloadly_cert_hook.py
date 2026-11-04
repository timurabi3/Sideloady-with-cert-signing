#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sideloadly_cert_hook.py
~~~~~~~~~~~~~~~~~~~~~~~
In-process Python hook & certificate signing engine for Sideloadly v0.72 (macOS).

Adds local Apple Developer Certificate (.p12 + .mobileprovision + password) signing
directly into Sideloadly's `Apple ID` selector and `GuiImpactor.run` pipeline without
requiring Apple ID credentials or remote Anisette/developer portal requests.

Security invariant:
- Never logs, prints, or persists raw certificate passwords in cleartext logs.
- Stores user profile configuration metadata in ~/.sideloadly-cert/config.json (0600).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import traceback
from typing import Any, Dict, List, Optional, Tuple


CONFIG_DIR = pathlib.Path.home() / ".sideloadly-cert"
CONFIG_PATH = CONFIG_DIR / "config.json"
UI_STATE_PATH = CONFIG_DIR / "ui_state.json"
DEFAULT_CERT_FOLDER = pathlib.Path.home() / "Desktop" / "apple dev certificate"

# Note: Sideloadly's `AccountBox.initAccountBox` runs `strings.Split(text, " ")[0]`
# (splitting on ASCII 0x20 space) to strip team suffixes. Using Unicode non-breaking
# space (\u00a0) prevents `AccountBox` from truncating the certificate display name.
NBSP = "\u00a0"
UPLOAD_MENU_LABEL = f"[Cert:{NBSP}Upload{NBSP}/{NBSP}Configure{NBSP}.p12{NBSP}+{NBSP}.mobileprovision...]"
ACTIVE_CERT_SLOT_LABEL = f"[Cert]{NBSP}Active{NBSP}Developer{NBSP}Certificate"
CERT_ACCOUNT_PREFIX = f"[Cert]{NBSP}"
LEGACY_CERT_PREFIX = "[Cert]"

_STAGED_STATE: Dict[str, str] = {
    "p12_path": "",
    "prov_path": "",
    "password_file": "",
    "password": "",
    "status_text": "",
    "status_state": "idle",  # "active" | "staged" | "need_password" | "error" | "idle"
}


def _ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass


def load_config() -> Dict[str, Any]:
    """Load certificate configuration from ~/.sideloadly-cert/config.json."""
    _ensure_config_dir()
    cfg: Dict[str, Any] = {
        "active_profile": None,
        "bundle_id_mode": "keep_original",  # "keep_original" | "match_profile"
        "profiles": [],
        "search_dirs": [str(DEFAULT_CERT_FOLDER)],
    }
    if CONFIG_PATH.exists():
        try:
            loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except Exception:
            pass
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    """Save certificate configuration with 0600 permissions."""
    _ensure_config_dir()
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def _extract_password_candidates(password_file: pathlib.Path) -> List[str]:
    """
    Extract candidate passwords from a PASSWORD.txt file (including multi-line banner formats)
    without ever logging or echoing the password values.
    """
    candidates: List[str] = []
    if not password_file or not password_file.exists():
        return [""]

    try:
        raw_text = password_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [""]

    lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]

    # 1. Look for explicit patterns like "Password is: X" or "PASSWORD: X"
    for ln in lines:
        m = re.search(r"(?:password\s*(?:is)?\s*[:=-]\s*)([^\s]+)", ln, re.IGNORECASE)
        if m:
            cand = m.group(1).strip()
            if cand and cand not in candidates:
                candidates.append(cand)

    # 2. Standalone non-decorative lines (excluding URLs, banners, separator lines)
    for ln in lines:
        if set(ln) <= {"=", "-", "*", "#", "_", " "}:
            continue
        if "http://" in ln.lower() or "https://" in ln.lower() or "telegram" in ln.lower():
            continue
        if "password" in ln.lower() and ":" in ln:
            after = ln.split(":", 1)[1].strip()
            if after and after not in candidates:
                candidates.append(after)
            continue
        if ln not in candidates:
            candidates.append(ln)

    # 3. Individual tokens as fallback
    for ln in lines:
        for tok in ln.split():
            if tok not in candidates and len(tok) <= 64:
                candidates.append(tok)

    if "" not in candidates:
        candidates.append("")

    return candidates


def parse_mobileprovision_bytes(prov_bytes: bytes) -> Dict[str, Any]:
    """
    Extract and parse the embedded XML plist from a CMS-signed .mobileprovision file.
    Compatible with both Sideloadly's internal Python 3.8 and standalone Python 3.x.
    """
    try:
        from sideloadly.impact import Impactor  # type: ignore
        parsed = Impactor.parse_provision(prov_bytes)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    start_marker = b"<?xml"
    end_marker = b"</plist>"
    s_idx = prov_bytes.find(start_marker)
    e_idx = prov_bytes.find(end_marker)
    if s_idx != -1 and e_idx != -1:
        xml_slice = prov_bytes[s_idx : e_idx + len(end_marker)]
        return plistlib.loads(xml_slice)

    # Fallback via macOS `security cms -D`
    proc = subprocess.run(
        ["/usr/bin/security", "cms", "-D"],
        input=prov_bytes,
        capture_output=True,
        check=True,
    )
    return plistlib.loads(proc.stdout)


def load_p12_with_candidates(
    p12_bytes: bytes,
    explicit_password: Optional[str] = None,
    password_file: Optional[pathlib.Path] = None,
) -> Tuple[Any, Any, str]:
    """
    Load a PKCS#12 (.p12) bundle using Sideloadly's `isign.crypt.load_p12` when inside
    Sideloadly, or `cryptography` / `openssl` when running standalone.
    Returns (cert_obj, pkey_obj, matched_password).
    """
    candidates: List[str] = []
    if explicit_password is not None:
        candidates.append(explicit_password)
    if password_file is not None and password_file.exists():
        for c in _extract_password_candidates(password_file):
            if c not in candidates:
                candidates.append(c)
    if "" not in candidates:
        candidates.append("")

    # Try Sideloadly's in-process isign.crypt.load_p12 first
    try:
        from isign import crypt as isign_crypt  # type: ignore

        last_err: Optional[Exception] = None
        for cand in candidates:
            try:
                cert, pkey = isign_crypt.load_p12(p12_bytes, cand)
                return cert, pkey, cand
            except Exception as exc:
                last_err = exc
        raise ValueError(f"Failed to unlock .p12 with {len(candidates)} candidate(s): {last_err}")
    except ImportError:
        pass

    # Standalone fallback using cryptography.hazmat.primitives.serialization.pkcs12
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        last_err = None
        for cand in candidates:
            try:
                pw_bytes = cand.encode("utf-8") if cand != "" else None
                private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_bytes, pw_bytes)
                if certificate is None or private_key is None:
                    pw_bytes2 = b"" if cand == "" else cand.encode("utf-8")
                    private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_bytes, pw_bytes2)
                if certificate is not None and private_key is not None:
                    return certificate, private_key, cand
            except Exception as exc:
                last_err = exc
        raise ValueError(f"Failed to unlock .p12 via cryptography: {last_err}")
    except ImportError:
        pass

    # Fallback via /usr/bin/openssl pkcs12
    for cand in candidates:
        proc = subprocess.run(
            ["/usr/bin/openssl", "pkcs12", "-info", "-nodes", "-passin", f"pass:{cand}"],
            input=p12_bytes,
            capture_output=True,
        )
        if proc.returncode == 0 and b"BEGIN CERTIFICATE" in proc.stdout:
            return proc.stdout, proc.stdout, cand

    raise ValueError("Unable to unlock .p12 with provided password candidates")


class CertBundleProfile:
    """Represents a validated Apple Developer Certificate (.p12 + .mobileprovision) bundle."""

    def __init__(
        self,
        name: str,
        p12_path: pathlib.Path,
        prov_path: pathlib.Path,
        password_file: Optional[pathlib.Path] = None,
        password: Optional[str] = None,
        bundle_id_mode: str = "keep_original",
    ) -> None:
        self.name = name
        self.p12_path = pathlib.Path(p12_path).expanduser().resolve()
        self.prov_path = pathlib.Path(prov_path).expanduser().resolve()
        self.password_file = (
            pathlib.Path(password_file).expanduser().resolve() if password_file else None
        )
        self._explicit_password = password
        self.bundle_id_mode = bundle_id_mode

        self.prov_bytes: bytes = self.prov_path.read_bytes()
        self.prov_plist: Dict[str, Any] = parse_mobileprovision_bytes(self.prov_bytes)

        self.team_name: str = str(self.prov_plist.get("TeamName", "Unknown Team"))
        team_ids = self.prov_plist.get("TeamIdentifier") or []
        self.team_id: str = str(team_ids[0]) if team_ids else "UNKNOWN"
        self.uuid: str = str(self.prov_plist.get("UUID", ""))
        self.profile_name: str = str(self.prov_plist.get("Name", self.prov_path.stem))
        self.expiration_date: Optional[datetime.datetime] = self.prov_plist.get("ExpirationDate")
        self.creation_date: Optional[datetime.datetime] = self.prov_plist.get("CreationDate")
        self.provisioned_devices: List[str] = list(self.prov_plist.get("ProvisionedDevices") or [])
        self.entitlements: Dict[str, Any] = dict(self.prov_plist.get("Entitlements") or {})
        self.app_id_full: str = str(self.entitlements.get("application-identifier", ""))
        if "." in self.app_id_full:
            self.profile_bundle_id = self.app_id_full.split(".", 1)[1]
        else:
            self.profile_bundle_id = self.app_id_full

    @property
    def account_label(self) -> str:
        raw = f"{CERT_ACCOUNT_PREFIX}{self.team_name} ({self.team_id}) — {self.p12_path.name}"
        return raw.replace(" ", NBSP)

    @property
    def days_remaining(self) -> int:
        if not isinstance(self.expiration_date, datetime.datetime):
            return 0
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = self.expiration_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        return max(0, (exp - now).days)

    def load_credentials(self) -> Tuple[Any, Any, str]:
        p12_bytes = self.p12_path.read_bytes()
        return load_p12_with_candidates(
            p12_bytes,
            explicit_password=self._explicit_password,
            password_file=self.password_file,
        )

    def to_metadata_dict(self) -> Dict[str, Any]:
        """Return safe, non-secret metadata dictionary."""
        return {
            "name": self.name,
            "account_label": self.account_label,
            "p12_path": str(self.p12_path),
            "prov_path": str(self.prov_path),
            "password_file": str(self.password_file) if self.password_file else None,
            "has_password": bool(self._explicit_password or self.password_file),
            "team_name": self.team_name,
            "team_id": self.team_id,
            "uuid": self.uuid,
            "profile_name": self.profile_name,
            "app_id_full": self.app_id_full,
            "profile_bundle_id": self.profile_bundle_id,
            "provisioned_devices": self.provisioned_devices,
            "expiration_date": self.expiration_date.isoformat() if self.expiration_date else None,
            "days_remaining": self.days_remaining,
            "bundle_id_mode": self.bundle_id_mode,
        }


def discover_cert_folder(folder: pathlib.Path) -> Optional[CertBundleProfile]:
    """Scan a directory for matching .p12 + .mobileprovision (+ optional PASSWORD.txt)."""
    folder = pathlib.Path(folder).expanduser()
    if not folder.is_dir():
        return None

    p12_files = sorted(folder.glob("*.p12")) + sorted(folder.glob("*.pfx"))
    prov_files = sorted(folder.glob("*.mobileprovision")) + sorted(folder.glob("*.provisionprofile"))
    if not p12_files or not prov_files:
        return None

    p12_path = p12_files[0]
    # Prefer a mobileprovision with the same stem if present
    matching_prov = [p for p in prov_files if p.stem.lower() == p12_path.stem.lower()]
    prov_path = matching_prov[0] if matching_prov else prov_files[0]

    pw_file: Optional[pathlib.Path] = None
    for candidate_name in ("PASSWORD.txt", "password.txt", f"{p12_path.stem}.txt", "pass.txt"):
        cand_path = folder / candidate_name
        if cand_path.is_file():
            pw_file = cand_path
            break

    return CertBundleProfile(
        name=folder.name,
        p12_path=p12_path,
        prov_path=prov_path,
        password_file=pw_file,
    )


def discover_all_profiles() -> Dict[str, CertBundleProfile]:
    """
    Return a mapping of `account_label -> CertBundleProfile` from configured profiles
    and search directories (including `~/Desktop/apple dev certificate`).
    """
    cfg = load_config()
    bundle_id_mode = cfg.get("bundle_id_mode", "keep_original")
    profiles: Dict[str, CertBundleProfile] = {}

    # 1. Configured explicit profiles
    for entry in cfg.get("profiles", []):
        try:
            p12_p = pathlib.Path(entry["p12_path"])
            prov_p = pathlib.Path(entry["prov_path"])
            if p12_p.is_file() and prov_p.is_file():
                pw_f = pathlib.Path(entry["password_file"]) if entry.get("password_file") else None
                prof = CertBundleProfile(
                    name=entry.get("name") or p12_p.stem,
                    p12_path=p12_p,
                    prov_path=prov_p,
                    password_file=pw_f,
                    password=entry.get("password"),
                    bundle_id_mode=entry.get("bundle_id_mode") or bundle_id_mode,
                )
                profiles[prof.account_label] = prof
        except Exception:
            continue

    # 2. Search directories
    search_dirs = list(cfg.get("search_dirs") or [])
    if not cfg.get("ignore_default_folder", False) and str(DEFAULT_CERT_FOLDER) not in search_dirs:
        search_dirs.insert(0, str(DEFAULT_CERT_FOLDER))

    for d_str in search_dirs:
        try:
            prof = discover_cert_folder(pathlib.Path(d_str))
            if prof is not None:
                prof.bundle_id_mode = bundle_id_mode
                profiles.setdefault(prof.account_label, prof)
        except Exception:
            continue

    return profiles


def get_active_profile() -> Optional[CertBundleProfile]:
    """Return the currently active certificate profile if one is configured or discovered."""
    profiles = discover_all_profiles()
    if not profiles:
        return None
    cfg = load_config()
    pref = cfg.get("active_profile")
    if pref and pref in profiles:
        return profiles[pref]
    # Also match if active_profile had regular spaces instead of NBSP
    if pref:
        pref_nbsp = str(pref).replace(" ", NBSP)
        if pref_nbsp in profiles:
            return profiles[pref_nbsp]
    return next(iter(profiles.values()))


def register_profile(
    p12_path: str | pathlib.Path,
    prov_path: str | pathlib.Path,
    password: Optional[str] = None,
    password_file: Optional[str | pathlib.Path] = None,
    bundle_id_mode: str = "keep_original",
) -> CertBundleProfile:
    """Validate and register a .p12 + .mobileprovision certificate bundle in config.json."""
    prof = CertBundleProfile(
        name=pathlib.Path(p12_path).stem,
        p12_path=pathlib.Path(p12_path),
        prov_path=pathlib.Path(prov_path),
        password_file=pathlib.Path(password_file) if password_file else None,
        password=password,
        bundle_id_mode=bundle_id_mode,
    )
    # Validate credentials unlock cleanly before saving
    prof.load_credentials()

    cfg = load_config()
    cfg["bundle_id_mode"] = bundle_id_mode
    new_entry: Dict[str, Any] = {
        "name": prof.name,
        "p12_path": str(prof.p12_path),
        "prov_path": str(prof.prov_path),
        "password_file": str(prof.password_file) if prof.password_file else None,
        "bundle_id_mode": bundle_id_mode,
    }
    if password is not None and not prof.password_file:
        new_entry["password"] = password

    existing = [
        e
        for e in cfg.get("profiles", [])
        if e.get("p12_path") != str(prof.p12_path) or e.get("prov_path") != str(prof.prov_path)
    ]
    existing.insert(0, new_entry)
    cfg["profiles"] = existing
    cfg["active_profile"] = prof.account_label
    cfg["ignore_default_folder"] = False
    save_config(cfg)

    _STAGED_STATE["p12_path"] = str(prof.p12_path)
    _STAGED_STATE["prov_path"] = str(prof.prov_path)
    _STAGED_STATE["password_file"] = str(prof.password_file) if prof.password_file else ""
    _STAGED_STATE["status_state"] = "active"
    exp_str = prof.expiration_date.strftime("%Y-%m-%d") if prof.expiration_date else "Unknown"
    udid_cnt = len(prof.provisioned_devices)
    _STAGED_STATE["status_text"] = (
        f"✓ Active: {prof.team_name} ({prof.team_id}) | Expires: {exp_str} ({prof.days_remaining}d) | UDIDs: {udid_cnt}"
    )
    sync_ui_state()
    return prof


def sync_ui_state() -> Dict[str, Any]:
    """
    Write `~/.sideloadly-cert/ui_state.json` (0600) so the native Qt5 Advanced Options
    panel in `sideloadly_dylib_proxy.mm` can read the current `.p12`, `.mobileprovision`,
    status text, and `account_label` without exposing any password.
    """
    _ensure_config_dir()
    prof = get_active_profile()

    if prof is not None and not _STAGED_STATE["p12_path"] and not _STAGED_STATE["prov_path"]:
        _STAGED_STATE["p12_path"] = str(prof.p12_path)
        _STAGED_STATE["prov_path"] = str(prof.prov_path)
        _STAGED_STATE["password_file"] = str(prof.password_file) if prof.password_file else ""
        _STAGED_STATE["status_state"] = "active"
        exp_str = prof.expiration_date.strftime("%Y-%m-%d") if prof.expiration_date else "Unknown"
        udid_cnt = len(prof.provisioned_devices)
        _STAGED_STATE["status_text"] = (
            f"✓ Active: {prof.team_name} ({prof.team_id}) | Expires: {exp_str} ({prof.days_remaining}d) | UDIDs: {udid_cnt}"
        )

    all_profs = discover_all_profiles()
    state: Dict[str, Any] = {
        "p12_path": _STAGED_STATE["p12_path"],
        "prov_path": _STAGED_STATE["prov_path"],
        "has_password_file": bool(_STAGED_STATE["password_file"]),
        "status_state": _STAGED_STATE["status_state"] if _STAGED_STATE["status_text"] else ("active" if prof else "idle"),
        "status_text": _STAGED_STATE["status_text"]
        or ("Drag & drop .p12 and .mobileprovision here, or click Upload below." if not prof else ""),
        "active_account_label": prof.account_label if prof else "",
        "all_account_labels": list(all_profs.keys()),
    }
    UI_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        os.chmod(UI_STATE_PATH, 0o600)
    except OSError:
        pass
    return state


def _find_sibling_password_file(p12_path: pathlib.Path) -> Optional[pathlib.Path]:
    folder = p12_path.parent
    for candidate_name in ("PASSWORD.txt", "password.txt", f"{p12_path.stem}.txt", "pass.txt"):
        cand_path = folder / candidate_name
        if cand_path.is_file():
            return cand_path
    return None


def stage_dropped_or_selected_paths(
    paths: List[str],
    explicit_password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Handle one or more file/folder paths dragged-and-dropped onto or selected via the
    Qt5 Advanced Options certificate widget.
    Supports:
      - Dropping a folder containing .p12 + .mobileprovision (+ optional PASSWORD.txt)
      - Dropping/selecting .p12 and .mobileprovision together or one at a time
      - Dropping PASSWORD.txt
    """
    if explicit_password is not None and explicit_password != "":
        _STAGED_STATE["password"] = explicit_password

    for raw_p in paths:
        if not raw_p:
            continue
        p = pathlib.Path(raw_p).expanduser()
        if not p.exists():
            continue

        if p.is_dir():
            folder_prof = discover_cert_folder(p)
            if folder_prof is not None:
                _STAGED_STATE["p12_path"] = str(folder_prof.p12_path)
                _STAGED_STATE["prov_path"] = str(folder_prof.prov_path)
                _STAGED_STATE["password_file"] = (
                    str(folder_prof.password_file) if folder_prof.password_file else ""
                )
            else:
                # Check if directory has at least one of .p12 or .mobileprovision
                p12s = sorted(p.glob("*.p12")) + sorted(p.glob("*.pfx"))
                provs = sorted(p.glob("*.mobileprovision")) + sorted(p.glob("*.provisionprofile"))
                if p12s:
                    _STAGED_STATE["p12_path"] = str(p12s[0].resolve())
                    pw_f = _find_sibling_password_file(p12s[0].resolve())
                    if pw_f:
                        _STAGED_STATE["password_file"] = str(pw_f)
                if provs:
                    _STAGED_STATE["prov_path"] = str(provs[0].resolve())
            continue

        suffix = p.suffix.lower()
        if suffix in (".p12", ".pfx"):
            resolved = p.resolve()
            _STAGED_STATE["p12_path"] = str(resolved)
            pw_f = _find_sibling_password_file(resolved)
            if pw_f:
                _STAGED_STATE["password_file"] = str(pw_f)
        elif suffix in (".mobileprovision", ".provisionprofile"):
            _STAGED_STATE["prov_path"] = str(p.resolve())
        elif p.name.lower().endswith(".txt"):
            _STAGED_STATE["password_file"] = str(p.resolve())

    return _try_activate_staged(explicit_password=explicit_password)


def apply_ui_certificate(
    p12_path: str = "",
    prov_path: str = "",
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate and activate the staged or specified .p12 + .mobileprovision + password."""
    if p12_path.strip():
        _STAGED_STATE["p12_path"] = str(pathlib.Path(p12_path.strip()).expanduser().resolve())
        pw_f = _find_sibling_password_file(pathlib.Path(_STAGED_STATE["p12_path"]))
        if pw_f and not _STAGED_STATE["password_file"]:
            _STAGED_STATE["password_file"] = str(pw_f)
    if prov_path.strip():
        _STAGED_STATE["prov_path"] = str(pathlib.Path(prov_path.strip()).expanduser().resolve())
    if password is not None:
        _STAGED_STATE["password"] = password

    return _try_activate_staged(explicit_password=password, force_attempt=True)


def clear_ui_certificate() -> Dict[str, Any]:
    """Clear staged and active certificate configuration from the UI."""
    _STAGED_STATE["p12_path"] = ""
    _STAGED_STATE["prov_path"] = ""
    _STAGED_STATE["password_file"] = ""
    _STAGED_STATE["password"] = ""
    _STAGED_STATE["status_state"] = "idle"
    _STAGED_STATE["status_text"] = "Certificate cleared. Drag & drop .p12 and .mobileprovision here or click Upload."

    cfg = load_config()
    cfg["profiles"] = []
    cfg["active_profile"] = None
    cfg["search_dirs"] = []
    cfg["ignore_default_folder"] = True
    save_config(cfg)
    return sync_ui_state()


def _try_activate_staged(
    explicit_password: Optional[str] = None,
    force_attempt: bool = False,
) -> Dict[str, Any]:
    p12_s = _STAGED_STATE["p12_path"]
    prov_s = _STAGED_STATE["prov_path"]

    if not p12_s and not prov_s:
        _STAGED_STATE["status_state"] = "idle"
        _STAGED_STATE["status_text"] = "Drag & drop .p12 and .mobileprovision here, or click Upload below."
        return sync_ui_state()

    if p12_s and not prov_s:
        _STAGED_STATE["status_state"] = "staged"
        _STAGED_STATE["status_text"] = (
            f"Staged .p12: {pathlib.Path(p12_s).name} — Now drag & drop or upload .mobileprovision"
        )
        return sync_ui_state()

    if prov_s and not p12_s:
        _STAGED_STATE["status_state"] = "staged"
        _STAGED_STATE["status_text"] = (
            f"Staged Profile: {pathlib.Path(prov_s).name} — Now drag & drop or upload .p12 certificate"
        )
        return sync_ui_state()

    # Both .p12 and .mobileprovision are present! Try to register/unlock.
    pw_to_use = explicit_password if explicit_password is not None else (_STAGED_STATE["password"] or None)
    pw_file = pathlib.Path(_STAGED_STATE["password_file"]) if _STAGED_STATE["password_file"] else None
    if pw_file is None:
        pw_file = _find_sibling_password_file(pathlib.Path(p12_s))

    try:
        register_profile(
            p12_path=p12_s,
            prov_path=prov_s,
            password=pw_to_use,
            password_file=pw_file,
        )
    except Exception as exc:
        if not pw_to_use and not force_attempt:
            _STAGED_STATE["status_state"] = "need_password"
            _STAGED_STATE["status_text"] = (
                f"🔑 Files staged ({pathlib.Path(p12_s).name} + {pathlib.Path(prov_s).name}). "
                f"Enter .p12 password below and click Apply / Verify."
            )
        else:
            _STAGED_STATE["status_state"] = "error"
            _STAGED_STATE["status_text"] = f"✗ Certificate unlock failed (check .p12 password): {exc}"

    return sync_ui_state()


def prompt_certificate_upload_dialog() -> Optional[CertBundleProfile]:
    """
    Display a native macOS dialog (via osascript / System Events) allowing the user to
    choose either a certificate folder (containing .p12 + .mobileprovision + PASSWORD.txt)
    or individual .p12 and .mobileprovision files.
    """
    script_mode = '''
    tell application "System Events"
        activate
        set dRes to display dialog "Sideloadly Certificate Signing\n\nHow would you like to load your Apple Developer Certificate?" buttons {"Cancel", "Select .p12 + Profile", "Select Cert Folder"} default button "Select Cert Folder" with title "Sideloadly Certificate Manager"
        return button returned of dRes
    end tell
    '''
    proc = subprocess.run(["/usr/bin/osascript", "-e", script_mode], capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    choice = proc.stdout.strip()

    if choice == "Select Cert Folder":
        folder_script = '''
        tell application "System Events"
            activate
            set f to choose folder with prompt "Select folder containing .p12, .mobileprovision, and optional PASSWORD.txt:"
            return POSIX path of f
        end tell
        '''
        f_proc = subprocess.run(["/usr/bin/osascript", "-e", folder_script], capture_output=True, text=True)
        if f_proc.returncode != 0:
            return None
        folder_path = pathlib.Path(f_proc.stdout.strip())
        prof = discover_cert_folder(folder_path)
        if prof is None:
            subprocess.run(
                [
                    "/usr/bin/osascript",
                    "-e",
                    'tell application "System Events" to display alert "Missing Files" message "No .p12 and .mobileprovision pair found in the selected folder." as critical',
                ]
            )
            return None
        try:
            prof.load_credentials()
        except Exception:
            pw = _prompt_password_dialog(prof.p12_path.name)
            if pw is None:
                return None
            prof._explicit_password = pw
            prof.load_credentials()

        return register_profile(
            p12_path=prof.p12_path,
            prov_path=prof.prov_path,
            password=prof._explicit_password,
            password_file=prof.password_file,
        )

    elif choice == "Select .p12 + Profile":
        p12_script = '''
        tell application "System Events"
            activate
            set f to choose file with prompt "Select Apple Developer Certificate (.p12 or .pfx):" of type {"p12", "pfx", "com.rsa.pkcs-12"}
            return POSIX path of f
        end tell
        '''
        p12_proc = subprocess.run(["/usr/bin/osascript", "-e", p12_script], capture_output=True, text=True)
        if p12_proc.returncode != 0:
            return None
        p12_path = pathlib.Path(p12_proc.stdout.strip())

        prov_script = '''
        tell application "System Events"
            activate
            set f to choose file with prompt "Select Provisioning Profile (.mobileprovision):"
            return POSIX path of f
        end tell
        '''
        prov_proc = subprocess.run(["/usr/bin/osascript", "-e", prov_script], capture_output=True, text=True)
        if prov_proc.returncode != 0:
            return None
        prov_path = pathlib.Path(prov_proc.stdout.strip())

        # Check if sibling PASSWORD.txt exists
        sibling_pw = p12_path.parent / "PASSWORD.txt"
        pw_file = sibling_pw if sibling_pw.is_file() else None
        explicit_pw = _prompt_password_dialog(
            p12_path.name,
            allow_auto=(pw_file is not None),
        )
        return register_profile(
            p12_path=p12_path,
            prov_path=prov_path,
            password=explicit_pw if explicit_pw != "__AUTO__" else None,
            password_file=pw_file,
        )

    return None


def _prompt_password_dialog(p12_filename: str, allow_auto: bool = False) -> Optional[str]:
    prompt_msg = f"Enter password for {p12_filename}:"
    if allow_auto:
        prompt_msg += " (Leave empty to auto-detect from PASSWORD.txt)"
    script = f'''
    tell application "System Events"
        activate
        set dRes to display dialog "{prompt_msg}" default answer "" with hidden answer buttons {{"Cancel", "OK"}} default button "OK" with title "Certificate Password"
        return text returned of dRes
    end tell
    '''
    proc = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    val = proc.stdout.rstrip("\r\n")
    if val == "" and allow_auto:
        return "__AUTO__"
    return val


class _CertStubAppleApi:
    """
    Minimal in-memory replacement for `sideloadly.apple.AppleApi` used when signing with
    a local `.p12` + `.mobileprovision` certificate bundle. Makes zero network requests.
    """

    def __init__(self, profile: CertBundleProfile) -> None:
        self.profile = profile
        self.appdir = pathlib.Path.home() / "Library" / "Application Support" / "Sideloadly"
        self.appdir.mkdir(parents=True, exist_ok=True)
        self.chosen_ak = "cert"
        self._username = profile.account_label
        self.team_id = profile.team_id

    def set_team_id(self, team_id: str) -> None:
        self.team_id = team_id

    def get_username(self, ask: bool = False) -> str:
        return self._username

    def close(self) -> None:
        pass


def run_with_certificate_profile(
    profile: CertBundleProfile,
    ipafile: Any,
    device: Any,
    info_props: Optional[Dict[str, Any]],
    mangle: bool,
    sign_mode: Any,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """
    Execute Sideloadly's `GuiImpactor.run` using the local `.p12` + `.mobileprovision`
    from `profile`.
    """
    from sideloadly.wrap import GuiImpactor, log  # type: ignore

    cert_obj, pkey_obj, _ = profile.load_credentials()
    subj = getattr(cert_obj, "subject", {}) or {}
    cn = subj.get("CN", profile.team_name)

    log(f"[CertSign] Loaded certificate: {cn}")
    log(
        f"[CertSign] Loaded provisioning profile: {profile.profile_name} "
        f"(Team: {profile.team_name} [{profile.team_id}], UUID: {profile.uuid}, "
        f"TTL: {profile.days_remaining}d)"
    )

    stub_api = _CertStubAppleApi(profile)
    imp = GuiImpactor(stub_api)

    # Override Apple Developer Portal network methods on `imp` with local cert/profile data
    imp.get_team_id = lambda: profile.team_id

    def _ensure_udid_registered(udid: str, name: Optional[str] = None, os: str = "ios") -> bool:
        if not udid:
            return True
        if profile.provisioned_devices:
            if udid in profile.provisioned_devices:
                log(f"[CertSign] Target device UDID {udid} is provisioned in profile.")
            else:
                log(
                    f"[CertSign] NOTICE: Device UDID {udid} not listed in ProvisionedDevices "
                    f"({profile.provisioned_devices}); continuing with profile signing."
                )
        return True

    imp.ensure_udid_registered = _ensure_udid_registered
    imp.ensure_private_key = lambda keyfile: pkey_obj
    imp.ensure_certificate = lambda certfile, pk: cert_obj
    imp.get_app_id_id = lambda bundle_id, name=None: f"CERT_{profile.team_id}"
    imp.fetch_provision = lambda app_id_id, os="ios": profile.prov_bytes

    def _provision_watch_apps(app: Any, app_id: str, os: str = "ios") -> None:
        for watch_app in getattr(app, "watch_apps", []) or []:
            watch_app.provision_data = profile.prov_bytes

    imp.provision_watch_apps = _provision_watch_apps

    props = dict(info_props) if info_props else {}
    if profile.bundle_id_mode == "match_profile" and profile.profile_bundle_id and "*" not in profile.profile_bundle_id:
        props.setdefault("CFBundleIdentifier", profile.profile_bundle_id)
        mangle_flag = False
    else:
        # Paid certificates unmangle automatically in Impactor.run when TTL > 7 days
        mangle_flag = False

    if isinstance(ipafile, str):
        ipafile = pathlib.Path(ipafile)

    # Convert output_dir in *args (index 2 of extra *args: drop_plugins, inject, output_dir, ...)
    args_list = list(args)
    if len(args_list) >= 3 and isinstance(args_list[2], str) and args_list[2]:
        args_list[2] = pathlib.Path(args_list[2])

    return imp.run(ipafile, device, props, mangle_flag, sign_mode, *args_list, **kwargs)


# ---------------------------------------------------------------------------
# In-process Hook Installation for Sideloadly
# ---------------------------------------------------------------------------

_HOOK_INSTALLED = False
_ORIG_WRAP_ACCOUNTS = None
_ORIG_WRAP_RUN = None


def _standalone_signpipe_complete(
    in_ipa: pathlib.Path,
    out_ipa: pathlib.Path,
    cert_der: bytes,
    pkey_der: bytes,
    entitlements_xml: bytes,
    prov_bytes: bytes,
) -> None:
    """
    Complete IPA signing in standalone CLI mode (when Go's CFFI stream callback is not
    active) using the exact DER certificate, DER private key, entitlements XML, and
    provisioning profile bytes produced by Sideloadly's `Impactor.run`.
    """
    import base64
    import tempfile

    zsign_bin = shutil.which("zsign") or "/opt/homebrew/bin/zsign"
    with tempfile.TemporaryDirectory(prefix="sl_signpipe_") as tmp:
        tmp_dir = pathlib.Path(tmp)
        cert_file = tmp_dir / "cert.der"
        cert_file.write_bytes(cert_der)

        key_file = tmp_dir / "pkey.der"
        key_file.write_bytes(pkey_der)

        prov_file = tmp_dir / "profile.mobileprovision"
        prov_file.write_bytes(prov_bytes)

        ent_file = tmp_dir / "entitlements.plist"
        ent_file.write_bytes(entitlements_xml)

        if out_ipa.is_dir():
            out_ipa = out_ipa / f"{in_ipa.stem}_signed.ipa"
        else:
            out_ipa.parent.mkdir(parents=True, exist_ok=True)

        subprocess.run(
            [
                zsign_bin,
                "-k",
                str(key_file),
                "-c",
                str(cert_file),
                "-m",
                str(prov_file),
                "-e",
                str(ent_file),
                "-o",
                str(out_ipa),
                "-z",
                "6",
                str(in_ipa),
            ],
            check=True,
            capture_output=True,
        )


def install_sideloadly_hooks() -> bool:
    """
    Hook `sideloadly_wrap.accounts` / `sideloadly.wrap.accounts` and
    `sideloadly_wrap.run` / `sideloadly.wrap.run` inside Sideloadly's embedded Python.
    """
    global _HOOK_INSTALLED, _ORIG_WRAP_ACCOUNTS, _ORIG_WRAP_RUN
    if _HOOK_INSTALLED:
        return True

    try:
        import sideloadly.signpipe as sl_signpipe  # type: ignore
        import sideloadly.wrap as sl_wrap  # type: ignore
        import sideloadly_wrap as sl_root  # type: ignore
    except ImportError:
        return False

    _ORIG_WRAP_ACCOUNTS = sl_wrap.accounts
    _ORIG_WRAP_RUN = sl_wrap.run
    _orig_process_ipa = getattr(sl_signpipe, "process_ipa", None)

    if _orig_process_ipa is not None:
        def _hooked_process_ipa(*p_args: Any, **p_kwargs: Any) -> Any:
            res = None
            orig_exc: Optional[Exception] = None
            try:
                res = _orig_process_ipa(*p_args, **p_kwargs)
            except Exception as exc:
                orig_exc = exc

            # In standalone CLI mode (outside the Go binary's CFFI stream callbacks),
            # `orig_process_ipa` either raises in `dispatch` or writes a 0-byte file.
            # Complete the Mach-O + CMS signing step using the exact DER cert, DER key,
            # entitlements plist, and mobileprovision bytes computed by `Impactor.run`.
            raw_in = p_kwargs.get("input_path") or (p_args[0] if len(p_args) >= 2 else None)
            raw_out = p_kwargs.get("output_path") or (p_args[1] if len(p_args) >= 2 else None)
            cert_der = p_kwargs.get("cert_der") or (p_args[2] if len(p_args) >= 3 else None)
            pkey_der = p_kwargs.get("priv_key_der") or (p_args[3] if len(p_args) >= 4 else None)
            ent_xml = p_kwargs.get("entitlements_plist") or (p_args[6] if len(p_args) >= 7 else None)
            prov_bytes = p_kwargs.get("provisioning_profile") or (p_args[7] if len(p_args) >= 8 else None)

            if raw_in and raw_out and cert_der and pkey_der and ent_xml and prov_bytes:
                in_ipa = pathlib.Path(str(raw_in))
                out_ipa = pathlib.Path(str(raw_out))
                if in_ipa.is_file() and (not out_ipa.is_file() or out_ipa.stat().st_size == 0):
                    _standalone_signpipe_complete(
                        in_ipa=in_ipa,
                        out_ipa=out_ipa,
                        cert_der=cert_der,
                        pkey_der=pkey_der,
                        entitlements_xml=ent_xml,
                        prov_bytes=prov_bytes,
                    )
                    return None

            if orig_exc is not None:
                raise orig_exc
            return res

        sl_signpipe.process_ipa = _hooked_process_ipa

    def hooked_accounts(*args: Any, **kwargs: Any) -> Tuple[Dict[str, List[str]], str]:
        try:
            orig_res = _ORIG_WRAP_ACCOUNTS(*args, **kwargs)
        except Exception:
            orig_res = ({}, "")

        if isinstance(orig_res, tuple) and len(orig_res) == 2:
            acc_dict, latest = dict(orig_res[0] or {}), str(orig_res[1] or "")
        else:
            acc_dict, latest = {}, ""

        profiles = discover_all_profiles()
        cfg = load_config()
        preferred = cfg.get("active_profile")
        if preferred:
            preferred = str(preferred).replace(" ", NBSP)

        first_cert_label: Optional[str] = None
        for label in profiles:
            # Marking with ["Fake", "Fake2"] makes Sideloadly's Go frontend (`slpy.Impact`)
            # skip interactive Apple ID password + remote Anisette pre-checks and call
            # `sideloadly_wrap.run(...)` directly when clicking Start.
            acc_dict[label] = ["Fake", "Fake2"]
            if first_cert_label is None:
                first_cert_label = label

        acc_dict[ACTIVE_CERT_SLOT_LABEL] = ["Fake", "Fake2"]
        acc_dict[UPLOAD_MENU_LABEL] = ["Fake", "Fake2"]

        if preferred and preferred in acc_dict:
            latest = preferred
        elif first_cert_label:
            latest = first_cert_label
        else:
            latest = ACTIVE_CERT_SLOT_LABEL

        try:
            sync_ui_state()
        except Exception:
            pass

        return acc_dict, latest

    def hooked_run(
        ipafile: Any,
        device: Any,
        anisette: Any,
        account: str,
        info_props: Optional[Dict[str, Any]] = None,
        mangle: bool = True,
        sign_mode: Any = 0,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        from sideloadly.wrap import log  # type: ignore

        account_str = str(account or "")
        account_nbsp = account_str.replace(" ", NBSP)
        if account_str == UPLOAD_MENU_LABEL or account_nbsp == UPLOAD_MENU_LABEL or account_str.startswith("[Cert:"):
            log("[CertSign] Opening Apple Developer Certificate configuration dialog...")
            new_prof = prompt_certificate_upload_dialog()
            if new_prof is None:
                raise RuntimeError("Certificate configuration cancelled by user.")
            log(f"[CertSign] Configured profile: {new_prof.account_label}")
            return run_with_certificate_profile(
                new_prof, ipafile, device, info_props, mangle, sign_mode, *args, **kwargs
            )

        profiles = discover_all_profiles()
        if account_str in profiles:
            prof = profiles[account_str]
            return run_with_certificate_profile(
                prof, ipafile, device, info_props, mangle, sign_mode, *args, **kwargs
            )
        if account_nbsp in profiles:
            prof = profiles[account_nbsp]
            return run_with_certificate_profile(
                prof, ipafile, device, info_props, mangle, sign_mode, *args, **kwargs
            )

        if (account_str.startswith(CERT_ACCOUNT_PREFIX) or account_str.startswith(LEGACY_CERT_PREFIX)):
            if profiles:
                active_prof = get_active_profile() or next(iter(profiles.values()))
                return run_with_certificate_profile(
                    active_prof, ipafile, device, info_props, mangle, sign_mode, *args, **kwargs
                )
            else:
                log("[CertSign] No certificate configured yet; opening certificate upload dialog...")
                new_prof = prompt_certificate_upload_dialog()
                if new_prof is None:
                    raise RuntimeError(
                        "No Apple Developer Certificate (.p12 + .mobileprovision) loaded. "
                        "Drag & drop or upload your .p12 and .mobileprovision under Advanced Options."
                    )
                return run_with_certificate_profile(
                    new_prof, ipafile, device, info_props, mangle, sign_mode, *args, **kwargs
                )

        return _ORIG_WRAP_RUN(
            ipafile, device, anisette, account, info_props, mangle, sign_mode, *args, **kwargs
        )

    sl_wrap.accounts = hooked_accounts
    sl_wrap.run = hooked_run
    sl_root.accounts = hooked_accounts
    sl_root.run = hooked_run

    _HOOK_INSTALLED = True
    return True
