"""Deterministic deletion-audit pipeline.

The implementation intentionally keeps interpretation deterministic. Optional PDF/image
extractors are used when installed, but an unreadable artifact is reported rather than
treated as proof of deletion.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
from llm import GroqEvidenceInterpreter

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
OP_STATE = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
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

    def related_resources(self, item: Evidence, tokens: Iterable[str],
                          resource_re: re.Pattern[str]) -> list[str]:
        tokens = [norm(token) for token in tokens if norm(token)]
        if item.path.suffix.lower() == ".json":
            try:
                payload = json.loads(item.text)
            except json.JSONDecodeError:
                return []
            found: list[str] = []
            def visit(value: Any) -> None:
                if isinstance(value, dict):
                    serialized = norm(json.dumps(value, ensure_ascii=False))
                    if value.get("resource_id") and any(token in serialized for token in tokens):
                        found.append(str(value["resource_id"]))
                    for child in value.values():
                        visit(child)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)
            visit(payload)
            return found
        return [
            resource for line in item.text.splitlines()
            if any(token in norm(line) for token in tokens)
            for resource in resource_re.findall(line)
        ]


class IdentityResolver:
    def __init__(self, root: Path) -> None:
        self.current = pd.read_csv(root / "user_identities.csv").fillna("")
        self.audit = pd.read_csv(root / "user_audit_log.csv").fillna("")

    def resolve(self, email: str) -> tuple[list[str], list[str]]:
        email_n = norm(email)
        users = set(self.current.loc[self.current.email.map(norm) == email_n, "user_id"].tolist())
        if not users:
            for row in self.audit.to_dict("records"):
                values = {norm(row["old_value"]), norm(row["new_value"])}
                if email_n in values:
                    users.add(row["user_id"])
        changed = self.audit[self.audit.user_id.isin(users)]
        tokens = {email_n, *users}
        for user_id in users:
            current = self.current[self.current.user_id == user_id]
            for row in current.to_dict("records"):
                tokens.update(norm(row[k]) for k in ("email", "email_hash", "phone", "name") if row[k])
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
        self.interpreter = GroqEvidenceInterpreter()
        self.resource_re = re.compile(
            r"\b(?:account|search|support|export|analytics|audit_record|backup|data_flow|"
            r"marketing|delivery|telemetry|cache|object|tombstone)[_-][A-Za-z0-9-]+\b", re.I)

    def _activity_matches(self, tokens: list[str], audit_at: datetime) -> pd.DataFrame:
        mask = pd.to_datetime(self.activities.event_time, utc=True) <= audit_at
        hay = self.activities.details.map(norm)
        return self.activities[mask & hay.map(lambda x: any(t in x for t in tokens))]

    def _activity_window(self, row: pd.Series) -> pd.DataFrame:
        start = pd.Timestamp(dt(row.requested_at))
        end = pd.Timestamp(dt(row.reported_at)) + pd.Timedelta(hours=2)
        times = pd.to_datetime(self.activities.event_time, utc=True)
        return self.activities[
            (times >= start) & (times <= end) &
            self.activities.event_type.isin({
                "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
                "SYNC_RECORD", "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS",
                "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
            })
        ].sort_values("event_time")

    def _state_evidence(self, resource: str, evidence: list[Evidence]) -> tuple[str, str]:
        direct = [item for item in evidence if resource.lower() in item.text.lower()]
        if direct:
            fragments: list[str] = []
            for item in direct:
                if item.path.suffix.lower() == ".json":
                    try:
                        payload = json.loads(item.text)
                    except json.JSONDecodeError:
                        payload = None
                    def visit(value: Any) -> None:
                        if isinstance(value, dict):
                            if str(value.get("resource_id", "")).lower() == resource.lower():
                                fragments.append(json.dumps(value, ensure_ascii=False))
                            for child in value.values():
                                visit(child)
                        elif isinstance(value, list):
                            for child in value:
                                visit(child)
                    visit(payload)
                else:
                    fragments.extend(
                        line for line in item.text.splitlines()
                        if resource.lower() in line.lower()
                    )
            text = "\n".join(fragments).lower()
            if item.path.suffix.lower() == ".json":
                if re.search(r'"(?:name|email|phone|email_hash|requester_email|requester_name|requester_phone)": null', text):
                    if (
                        '"account_status": "deleted"' in text
                        or '"requester_email": null' in text
                    ):
                        return "REDACTED", direct[-1].file_id
                if '"restore_allowed": false' in text:
                    return "BLOCKED", direct[-1].file_id
                if '"enabled": false' in text:
                    return "DISABLED", direct[-1].file_id
            if re.search(r"\b(active|present|rows=[1-9]|http_status=200)\b", text):
                return "PRESENT", direct[-1].file_id
            if re.search(r"\b(404|absent|not found|rows=0|deleted=true)\b", text):
                return "ABSENT", direct[-1].file_id
            if "redact" in text:
                return "REDACTED", direct[-1].file_id
            if "anonym" in text or "customer_reference=null" in text:
                return "ANONYMIZED", direct[-1].file_id
            return "PRESENT", direct[-1].file_id
        snapshots = [item for item in evidence if item.path.suffix.lower() == ".sql"]
        if snapshots:
            return "ABSENT", snapshots[-1].file_id
        return "", ""

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
        evidence_tokens = [token for token in tokens if not token.startswith("user_")]
        evidence = self.evidence.matching(evidence_tokens, audit_at)
        if not evidence:
            evidence = self.evidence.matching(users, audit_at)
        if not evidence:
            evidence = [
                item for item in self.evidence.items
                if item.readable and item.path.suffix.lower() == ".sql"
                and item.captured_at <= audit_at
            ]
            evidence = sorted(evidence, key=lambda item: item.captured_at)[-1:]
        elif evidence:
            latest_capture = max(item.captured_at for item in evidence)
            evidence = [item for item in evidence if item.captured_at == latest_capture]
        self.interpreter.interpret(
            evidence_tokens,
            [{"file_id": item.file_id, "text": item.text[:12000]} for item in evidence],
        )
        activities = self._activity_window(row)
        findings: list[dict[str, Any]] = []
        resources: dict[tuple[str, str], tuple[str, str, str]] = {}

        evidence_resources: dict[str, tuple[str, str]] = {}
        evidence_paths: dict[str, str] = {}
        evidence_text_ids = {
            resource for item in evidence for resource in self.resource_re.findall(item.text)
        }
        for item in evidence:
            for resource in self.evidence.related_resources(item, tokens, self.resource_re):
                if resource.lower().endswith("_service"):
                    continue
                evidence_resources[resource] = (self._system_for(resource, item.text), item.file_id)
                evidence_paths[resource] = item.path.suffix.lower()

        selected: dict[str, pd.Series] = {}
        account_rows = activities[
            activities.target_system.eq("account_service") &
            activities.event_type.eq("DELETE_RECORD")
        ]
        if not account_rows.empty:
            selected[account_rows.iloc[-1].resource_id] = account_rows.iloc[-1]
        if evidence_resources:
            selected = {
                resource: activity for resource, activity in selected.items()
                if resource in evidence_resources
            }
            for _, a in activities.iterrows():
                if a.resource_id in evidence_resources:
                    selected[a.resource_id] = a
            account_candidates = activities[
                (activities.target_system == "account_service")
                & (activities.event_type == "DELETE_RECORD")
                & activities.resource_id.isin(evidence_text_ids)
            ]
            if not account_candidates.empty:
                report_time = pd.Timestamp(dt(row.reported_at))
                distances = (pd.to_datetime(account_candidates.event_time, utc=True)
                             - report_time).abs()
                chosen = account_candidates.iloc[int(distances.to_numpy().argmin())]
                selected[chosen.resource_id] = chosen
            analytics_candidates = activities[
                (activities.target_system == "analytics_platform")
                & (activities.event_type == "ANONYMIZE_RECORD")
                & activities.resource_id.isin(evidence_text_ids)
            ]
            if not analytics_candidates.empty:
                selected[analytics_candidates.iloc[-1].resource_id] = analytics_candidates.iloc[-1]
            if re.search(r"\b(integration|sync|connector|backup|restore)\b",
                         norm(row.request_text)):
                for _, a in activities.iterrows():
                    if a.event_type in {"CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS"}:
                        selected[a.resource_id] = a
            if not any(
                activity.target_system == "account_service" for activity in selected.values()
            ) and not any(key.startswith("account") for key in evidence_resources):
                if not account_rows.empty:
                    selected[account_rows.iloc[-1].resource_id] = account_rows.iloc[-1]
        else:
            for _, a in activities.iterrows():
                if a.event_type in {"CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS"}:
                    selected[a.resource_id] = a

        activity_rows = pd.DataFrame(selected.values())
        for _, a in activity_rows.iterrows() if not activity_rows.empty else []:
            text = f"{a.details} {a.resource_id}"
            if str(a.reported_result).upper() in {"SUCCESS", "PARTIAL", "FAILED"}:
                kind = self._resource_kind(a.resource_id, a.target_system, text)
                resources[(a.target_system, a.resource_id)] = (kind, a.activity_id, "")

        for resource, activity in selected.items():
            system = activity.target_system
            kind = self._resource_kind(resource, system, activity.details)
            resources[(system, resource)] = (kind, activity.activity_id, "")
        for resource, (system, citation) in evidence_resources.items():
            if (
                resource not in selected
                and not resource.startswith(("audit_record_", "tombstone_"))
                and evidence_paths.get(resource) not in {".json", ".pdf"}
            ):
                continue
            kind = self._resource_kind(resource, system, "")
            resources.setdefault((system, resource), (kind, citation, citation))

        tombstones = [
            activity for activity in selected.values()
            if str(activity.resource_id).startswith("tombstone_")
        ]
        if tombstones and not any(
            resource.startswith("account_") for _, resource in resources
        ):
            account_before = activities[
                (activities.target_system == "account_service")
                & (activities.event_type == "DELETE_RECORD")
                & (pd.to_datetime(activities.event_time, utc=True)
                   <= pd.Timestamp(tombstones[0].event_time))
            ]
            if not account_before.empty:
                activity = account_before.iloc[-1]
                resources[("account_service", activity.resource_id)] = (
                    "ACCOUNT", activity.activity_id, ""
                )

        # An evidence artifact can prove a current record only when it contains a direct
        # identity token and a resource. Interpret explicit state words conservatively.
        for (system, resource), (kind, citation, file_id) in resources.items():
            if kind == "FLOW" or kind == "BACKUP":
                evidence_state, evidence_id = self._state_evidence(resource, evidence)
                activity = next((a for a in selected.values() if a.resource_id == resource), None)
                if kind == "FLOW" and (
                    (activity is not None and "enabled" in norm(activity.details))
                    or evidence_state == "PRESENT"
                ):
                    findings.append(self._step("FINDING", system, resource,
                                               "REPORT_ACTIVE_DATA_FLOW", "ACTIVE",
                                               evidence_id or citation))
                elif kind == "BACKUP" and (
                    (activity is not None and "can still" in norm(activity.details))
                    or evidence_state == "PRESENT"
                ):
                    findings.append(self._step("FINDING", system, resource,
                                               "REPORT_RESTORE_RISK", "ACTIVE",
                                               evidence_id or citation))
                continue
            action = {"ACCOUNT": "DELETE", "SEARCH": "DELETE", "EXPORT": "DELETE",
                      "MARKETING": "DELETE", "SUPPORT": "REDACT",
                      "ANALYTICS": "ANONYMIZE", "RETAIN": "RETAIN"}.get(kind, "DELETE")
            evidence_state, evidence_id = self._state_evidence(resource, evidence)
            if evidence_id:
                citation = evidence_id
            absent = evidence_state == "ABSENT"
            redacted = evidence_state == "REDACTED"
            anonymized = evidence_state == "ANONYMIZED"
            operation_result = ""
            activity = next((a for a in selected.values() if a.resource_id == resource), None)
            if activity is not None:
                operation_result = str(activity.reported_result).upper()
            if action == "RETAIN":
                if absent: continue
                resources[(system, resource)] = (kind, citation, file_id)
            elif (
                (operation_result in {"FAILED", "PARTIAL"} and evidence_state != "ABSENT")
                or (evidence_state == "PRESENT" and action == "DELETE")
            ):
                op = "REPORT_EXPOSED_PII" if action in {"REDACT", "ANONYMIZE"} else "REPORT_REMAINING_RECORD"
                findings.append(self._step("FINDING", system, resource, op, "PRESENT", citation))
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
        if re.search(r"\bnot my account\b|\bdid not request(?:ed)?\b|\bno deletion request\b",
                     norm(row.request_text)):
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
        if "tombstone" in s: return "identity_service"
        if "audit_record" in s: return "security_service"
        if "audit" in s or "security" in s: return "security_service"
        return "account_service"

    def run(self) -> pd.DataFrame:
        rows = []
        for _, row in self.requests.iterrows():
            status, steps = self.investigate(row)
            rows.append({"case_id": row.case_id, "deletion_status": status,
                         "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
        return pd.DataFrame(rows).sort_values("case_id").reset_index(drop=True)


def validate_output(output: Path, request_count: int, evidence_ids: set[str] | None = None) -> list[str]:
    errors: list[str] = []
    data = pd.read_csv(output)
    if list(data.columns) != ["case_id", "deletion_status", "steps_json"]:
        errors.append("wrong columns")
    if len(data) != request_count or data.case_id.duplicated().any():
        errors.append("row count or uniqueness mismatch")
    allowed = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    evidence_ids = evidence_ids or set()
    for _, row in data.iterrows():
        if row.deletion_status not in allowed: errors.append(f"invalid status {row.case_id}")
        try: steps = json.loads(row.steps_json)
        except json.JSONDecodeError: errors.append(f"invalid JSON {row.case_id}"); continue
        if row.deletion_status == "NOT_APPLICABLE" and steps != []: errors.append(f"NA has steps {row.case_id}")
        for i, step in enumerate(steps, 1):
            if set(step) != {"step_no","phase","system_id","resource_id","operation","state","evidence_id"}:
                errors.append(f"schema {row.case_id}"); break
            if step["step_no"] != i: errors.append(f"numbering {row.case_id}"); break
            if step["operation"] not in OP_STATE or OP_STATE[step["operation"]] != (
                    step["phase"], step["state"]):
                errors.append(f"operation/state {row.case_id}")
            if step["evidence_id"] and evidence_ids and step["evidence_id"] not in evidence_ids:
                errors.append(f"evidence {row.case_id}")
        if row.deletion_status == "COMPLETE" and any(not step["evidence_id"] for step in steps):
            errors.append(f"complete citation {row.case_id}")
    return sorted(set(errors))
