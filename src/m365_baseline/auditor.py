"""Automated SMB Microsoft 365 MFA, phishing DNS auth, dark-web rotation, DR RPO, and VoIP audit engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TenantPosture:
    tenant_id: str
    domain: str
    mfa_coverage_pct: float
    legacy_auth_blocked: bool
    dedicated_admin_accounts: bool
    spf_strict: bool
    dkim_enabled: bool
    dmarc_policy: str  # "none" | "quarantine" | "reject"
    unrotated_leaks: int
    last_backup_age_hours: float
    rpo_max_hours: float
    backup_immutable: bool
    last_restore_drill_days: int
    voip_tls_srtp_enabled: bool


@dataclass(frozen=True)
class ControlFinding:
    control_id: str
    severity: str  # "critical" | "high" | "medium"
    message: str


@dataclass(frozen=True)
class AuditReport:
    tenant_id: str
    domain: str
    score: int
    compliant: bool
    findings: tuple[ControlFinding, ...] = field(default_factory=tuple)


def evaluate_tenant_posture(t: TenantPosture) -> AuditReport:
    """Audit tenant across identity, email auth, breached credentials, backup/DR, and VoIP controls."""
    findings: list[ControlFinding] = []
    penalty = 0

    if t.mfa_coverage_pct < 100.0:
        findings.append(
            ControlFinding("ID-01", "critical", f"MFA coverage at {t.mfa_coverage_pct:.1f}% (must be 100%).")
        )
        penalty += 25
    if not t.legacy_auth_blocked:
        findings.append(ControlFinding("ID-02", "critical", "Legacy IMAP/POP3/SMTP auth still enabled."))
        penalty += 20
    if not t.dedicated_admin_accounts:
        findings.append(ControlFinding("ID-03", "high", "Global admins lack separate privileged accounts."))
        penalty += 10

    if not t.spf_strict:
        findings.append(ControlFinding("MAIL-01", "high", "SPF record does not terminate with hard fail (-all)."))
        penalty += 10
    if not t.dkim_enabled:
        findings.append(ControlFinding("MAIL-02", "high", "DKIM outbound signing not enabled."))
        penalty += 10
    if t.dmarc_policy not in ("quarantine", "reject"):
        findings.append(ControlFinding("MAIL-03", "high", f"DMARC policy '{t.dmarc_policy}' lacks enforcement."))
        penalty += 15

    if t.unrotated_leaks > 0:
        findings.append(
            ControlFinding("CRED-01", "critical", f"{t.unrotated_leaks} breached credential(s) awaiting rotation.")
        )
        penalty += min(25, 10 * t.unrotated_leaks)

    if t.last_backup_age_hours > t.rpo_max_hours:
        findings.append(
            ControlFinding(
                "DR-01",
                "critical",
                f"Backup age {t.last_backup_age_hours:.1f}h exceeds {t.rpo_max_hours:.1f}h RPO.",
            )
        )
        penalty += 20
    if not t.backup_immutable:
        findings.append(ControlFinding("DR-02", "critical", "Cloud backup target lacks immutability lock."))
        penalty += 20
    if t.last_restore_drill_days > 30:
        findings.append(
            ControlFinding("DR-03", "medium", f"Last verified restore test was {t.last_restore_drill_days}d ago (>30d).")
        )
        penalty += 5

    if not t.voip_tls_srtp_enabled:
        findings.append(ControlFinding("VOIP-01", "high", "VoIP SIP trunk lacks TLS + SRTP media encryption."))
        penalty += 10

    score = max(0, 100 - penalty)
    critical_or_high = any(f.severity in ("critical", "high") for f in findings)
    return AuditReport(
        tenant_id=t.tenant_id,
        domain=t.domain,
        score=score,
        compliant=not critical_or_high and score >= 90,
        findings=tuple(findings),
    )


def prioritize_remediation(reports: list[AuditReport]) -> list[tuple[str, str, str]]:
    """Rank remediation actions across multi-tenant SMB fleet (critical before high before medium)."""
    rank = {"critical": 0, "high": 1, "medium": 2}
    tasks: list[tuple[int, str, str, str]] = []
    for rep in reports:
        for f in rep.findings:
            tasks.append((rank[f.severity], rep.tenant_id, f.control_id, f.message))
    tasks.sort(key=lambda item: (item[0], item[1], item[2]))
    return [(t_id, cid, msg) for _, t_id, cid, msg in tasks]
