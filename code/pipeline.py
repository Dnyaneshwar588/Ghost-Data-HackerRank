"""Deterministic deletion-audit pipeline.

The implementation intentionally keeps interpretation deterministic. Optional PDF/image
extractors are used when installed, but an unreadable artifact is reported rather than
treated as proof of deletion.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2,
    "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
RULE_ACTION = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE", "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT", "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE", "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT", "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN", "BACKUP_ARCHIVE": "RETAIN",
    "ACCOUNT_TOMBSTONE": "REDACT",
}


def dt(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)


def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


@dataclass(frozen=True)
class Evidence:
    file_id: str
    path: Path
    captured_at: datetime
    text: str
    readable: bool


class EvidenceExtractor:
    def __init__(self, root: Path) -> None:
        manifest = pd.read_csv(root / "evidence_files.csv")
        self.items: list[Evidence] = []
        self.missing: list[str] = []
        for row in manifest.to_dict("records"):
            path = root / str(row["file_path"])
            try:
                raw = path.read_bytes()
                text = self._extract(path, raw)
                self.items.append(Evidence(row["file_id"], path, dt(row["captured_at"]), text, True))
            except (OSError, UnicodeError, ValueError) as exc:
                self.missing.append(f"{row['file_id']}: {path} ({exc})")
                self.items.append(Evidence(row["file_id"], path, dt(row["captured_at"]), "", False))

    @staticmethod
    def _extract(path: Path, raw: bytes) -> str:
        suffix = path.suffix.lower()
        if suffix in {".json", ".sql", ".log", ".txt", ".csv"}:
            return raw.decode("utf-8", errors="replace")
        if suffix == ".pdf":
            try:
                from pypdf import PdfReader
                return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
            except ImportError:
                return ""
        if suffix in {".png", ".jpg", ".jpeg"}:
            try:
                import pytesseract
                from PIL import Image
                return pytesseract.image_to_string(Image.open(path))
            except ImportError:
                return ""
        return ""

    def matching(self, tokens: Iterable[str], at: datetime) -> list[Evidence]:
        tokens = [norm(t) for t in tokens if len(norm(t)) >= 4]
        return [e for e in self.items if e.readable and e.captured_at <= at and
                any(t in norm(e.text) for t in tokens)]


class IdentityResolver:
    def __init__(self, root: Path) -> None:
        self.current = pd.read_csv(root / "user_identities.csv").fillna("")
        self.audit = pd.read_csv(root / "user_audit_log.csv").fillna("")

    def resolve(self, email: str) -> tuple[list[str], list[str]]:
        email_n = norm(email)
        users = set(self.current.loc[self.current.email.map(norm) == email_n, "user_id"].tolist())
        changed = self.audit[self.audit.user_id.isin(users)]
        tokens = {email_n, *users}
        for row in changed.to_dict("records"):
            if row["field_name"] in {"email", "email_hash", "phone", "name"}:
                tokens.update(norm(row[k]) for k in ("old_value", "new_value") if row[k])
        return sorted(users), sorted(tokens)


class AuditAgent:
    def __init__(self, dataset: Path, request_file: str = "deletion_requests.csv") -> None:
        self.dataset = dataset
        self.requests = pd.read_csv(dataset / request_file).fillna("")
        self.activities = pd.read_csv(dataset / "system_activity.csv").fillna("")
        self.identities = IdentityResolver(dataset)
        self.evidence = EvidenceExtractor(dataset)
        self.resource_re = re.compile(
            r"\b(?:account|search|support|export|analytics|audit_record|backup|data_flow|"
            r"marketing|delivery|telemetry|cache|object|tombstone)[_-][A-Za-z0-9-]+\b", re.I)

    def _activity_matches(self, tokens: list[str], audit_at: datetime) -> pd.DataFrame:
        mask = pd.to_datetime(self.activities.event_time, utc=True) <= audit_at
        hay = self.activities.details.map(norm)
        return self.activities[mask & hay.map(lambda x: any(t in x for t in tokens))]

    def _resource_kind(self, resource: str, system: str, text: str) -> str:
        s = f"{resource} {system} {text}".lower()
        if "data_flow" in s or "connector" in s: return "FLOW"
        if "backup" in s or "archive" in s or "restore" in s: return "BACKUP"
        if "analytics" in s or "telemetry" in s: return "ANALYTICS"
        if "support" in s or "attachment" in s: return "SUPPORT"
        if "search" in s or "index" in s: return "SEARCH"
        if "export" in s: return "EXPORT"
        if "marketing" in s: return "MARKETING"
        if "audit" in s or "security" in s: return "RETAIN"
        return "ACCOUNT"

    def _step(self, phase: str, system: str, resource: str, operation: str,
              state: str, evidence_id: str) -> dict[str, Any]:
        return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource,
                "operation": operation, "state": state, "evidence_id": evidence_id}

    def investigate(self, row: pd.Series) -> tuple[str, list[dict[str, Any]]]:
        users, tokens = self.identities.resolve(row.email)
        audit_at = dt(row.audit_at)
        evidence = self.evidence.matching(tokens, audit_at)
        activities = self._activity_matches(tokens, audit_at)
        findings: list[dict[str, Any]] = []
        resources: dict[tuple[str, str], tuple[str, str, str]] = {}

        for _, a in activities.iterrows():
            text = f"{a.details} {a.resource_id}"
            if str(a.reported_result).upper() in {"SUCCESS", "PARTIAL", "FAILED"}:
                kind = self._resource_kind(a.resource_id, a.target_system, text)
                resources[(a.target_system, a.resource_id)] = (kind, a.activity_id, "")
                typ = str(a.event_type)
                if typ in {"CHECK_DATA_FLOW", "SYNC_RECORD"} and "enabled" in norm(a.details):
                    findings.append(self._step("FINDING", a.target_system, a.resource_id,
                                               "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", a.activity_id))
                elif typ == "CHECK_RESTORE_ACCESS" and "can still" in norm(a.details):
                    findings.append(self._step("FINDING", a.target_system, a.resource_id,
                                               "REPORT_RESTORE_RISK", "ACTIVE", a.activity_id))

        for e in evidence:
            for resource in sorted(set(self.resource_re.findall(e.text)), key=str):
                # Keep only resources in a matching evidence artifact; the identity token
                # match is the relationship proof and prevents unrelated corpus records.
                if resource.lower().endswith("_service"):
                    continue
                system = self._system_for(resource, e.text)
                kind = self._resource_kind(resource, system, e.text)
                resources.setdefault((system, resource), (kind, e.file_id, e.file_id))

        # An evidence artifact can prove a current record only when it contains a direct
        # identity token and a resource. Interpret explicit state words conservatively.
        for (system, resource), (kind, citation, file_id) in resources.items():
            if kind == "FLOW" or kind == "BACKUP":
                continue
            action = {"ACCOUNT": "DELETE", "SEARCH": "DELETE", "EXPORT": "DELETE",
                      "MARKETING": "DELETE", "SUPPORT": "REDACT",
                      "ANALYTICS": "ANONYMIZE", "RETAIN": "RETAIN"}.get(kind, "DELETE")
            evidence_text = " ".join(e.text for e in evidence if citation == e.file_id or citation == e.file_id)
            lower = norm(evidence_text)
            absent = any(x in lower for x in ("absent", "not found", "deleted=true", "deleted: true"))
            redacted = "redact" in lower or "redacted" in lower
            anonymized = "anonym" in lower
            if action == "RETAIN":
                if absent: continue
                resources[(system, resource)] = (kind, citation, file_id)
            elif absent and action == "DELETE":
                continue
            elif action == "REDACT" and redacted:
                continue
            elif action == "ANONYMIZE" and anonymized:
                continue
            else:
                op = "REPORT_EXPOSED_PII" if action in {"REDACT", "ANONYMIZE"} else "REPORT_REMAINING_RECORD"
                findings.append(self._step("FINDING", system, resource, op, "PRESENT", citation))

        # If no trustworthy identity exists, this is not a deletion request only when the
        # request text explicitly denies ownership; otherwise insufficient evidence is incomplete.
        if re.search(r"\bnot my account\b|\bdid not request\b|\bbelongs to someone else\b", norm(row.request_text)):
            return "NOT_APPLICABLE", []

        remediation: list[dict[str, Any]] = []
        verification: list[dict[str, Any]] = []
        for f in findings:
            op, system, resource = f["operation"], f["system_id"], f["resource_id"]
            if op == "REPORT_ACTIVE_DATA_FLOW":
                remediation.append(self._step("REMEDIATION", system, resource, "DISABLE_DATA_FLOW", "DISABLED", ""))
                verification.append(self._step("VERIFICATION", system, resource, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
            elif op == "REPORT_RESTORE_RISK":
                remediation.append(self._step("REMEDIATION", system, resource, "BLOCK_RESTORE", "BLOCKED", ""))
                verification.append(self._step("VERIFICATION", system, resource, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
            elif op == "REPORT_EXPOSED_PII":
                kind = self._resource_kind(resource, system, "")
                operation = "REDACT_RECORD" if kind == "SUPPORT" else "ANONYMIZE_RECORD"
                state = "REDACTED" if operation == "REDACT_RECORD" else "ANONYMIZED"
                remediation.append(self._step("REMEDIATION", system, resource, operation, state, ""))
                verification.append(self._step("VERIFICATION", system, resource,
                                                "VERIFY_RECORD_REDACTED" if state == "REDACTED" else "VERIFY_RECORD_ANONYMIZED",
                                                state, ""))
            else:
                remediation.append(self._step("REMEDIATION", system, resource, "DELETE_RECORD", "ABSENT", ""))
                verification.append(self._step("VERIFICATION", system, resource, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        # Account absence is a required baseline whenever a user was resolved.
        account_resources = [(s, r, c) for (s, r), (_, c, _) in resources.items() if "account" in r.lower()]
        for system, resource, citation in account_resources:
            if not any(v["resource_id"] == resource for v in verification):
                verification.append(self._step("VERIFICATION", system, resource, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        for (system, resource), (kind, citation, _) in resources.items():
            if kind == "RETAIN":
                verification.append(self._step("VERIFICATION", system, resource, "VERIFY_RECORD_PRESENT", "PRESENT", ""))

        if not findings and verification:
            status = "COMPLETE"
            for v in verification:
                v["evidence_id"] = next((e.file_id for e in evidence if v["resource_id"] in e.text),
                                        next((a.activity_id for _, a in activities.iterrows()
                                              if str(a.resource_id) == v["resource_id"]), ""))
            steps = verification
        else:
            status = "INCOMPLETE"
            steps = findings + remediation + verification
        steps.sort(key=lambda x: (PHASE_ORDER[x["phase"]], OP_ORDER[x["operation"]],
                                  x["system_id"], x["resource_id"]))
        for i, step in enumerate(steps, 1):
            step["step_no"] = i
        return status, steps

    @staticmethod
    def _system_for(resource: str, text: str) -> str:
        s = resource.lower()
        if "search" in s or "index" in s: return "search_service"
        if "support" in s or "attachment" in s: return "support_platform"
        if "analytics" in s: return "analytics_platform"
        if "backup" in s: return "backup_service"
        if "data_flow" in s or "connector" in s: return "integration_service"
        if "export" in s: return "export_service"
        if "marketing" in s: return "marketing_platform"
        if "audit" in s or "security" in s: return "security_service"
        return "account_service"

    def run(self) -> pd.DataFrame:
        rows = []
        for _, row in self.requests.iterrows():
            status, steps = self.investigate(row)
            rows.append({"case_id": row.case_id, "deletion_status": status,
                         "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
        return pd.DataFrame(rows).sort_values("case_id").reset_index(drop=True)


def validate_output(output: Path, request_count: int) -> list[str]:
    errors: list[str] = []
    data = pd.read_csv(output)
    if list(data.columns) != ["case_id", "deletion_status", "steps_json"]:
        errors.append("wrong columns")
    if len(data) != request_count or data.case_id.duplicated().any():
        errors.append("row count or uniqueness mismatch")
    allowed = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    for _, row in data.iterrows():
        if row.deletion_status not in allowed: errors.append(f"invalid status {row.case_id}")
        try: steps = json.loads(row.steps_json)
        except json.JSONDecodeError: errors.append(f"invalid JSON {row.case_id}"); continue
        if row.deletion_status == "NOT_APPLICABLE" and steps != []: errors.append(f"NA has steps {row.case_id}")
        for i, step in enumerate(steps, 1):
            if set(step) != {"step_no","phase","system_id","resource_id","operation","state","evidence_id"}:
                errors.append(f"schema {row.case_id}"); break
            if step["step_no"] != i: errors.append(f"numbering {row.case_id}"); break
    return sorted(set(errors))
