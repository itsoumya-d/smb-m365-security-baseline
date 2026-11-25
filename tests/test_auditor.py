from m365_baseline.auditor import TenantPosture, evaluate_tenant_posture, prioritize_remediation


def _hardened(tenant_id: str = "t-01", domain: str = "example.co.nz", **overrides) -> TenantPosture:
    base = dict(
        tenant_id=tenant_id,
        domain=domain,
        mfa_coverage_pct=100.0,
        legacy_auth_blocked=True,
        dedicated_admin_accounts=True,
        spf_strict=True,
        dkim_enabled=True,
        dmarc_policy="reject",
        unrotated_leaks=0,
        last_backup_age_hours=2.0,
        rpo_max_hours=4.0,
        backup_immutable=True,
        last_restore_drill_days=14,
        voip_tls_srtp_enabled=True,
    )
    base.update(overrides)
    return TenantPosture(**base)


def test_fully_hardened_tenant_scores_100_and_compliant():
    report = evaluate_tenant_posture(_hardened())
    assert report.score == 100
    assert report.compliant is True
    assert report.findings == ()


def test_missing_mfa_and_immutable_backup_fails_critical_controls():
    report = evaluate_tenant_posture(
        _hardened(mfa_coverage_pct=84.0, legacy_auth_blocked=False, backup_immutable=False)
    )
    assert report.compliant is False
    assert report.score == 35
    ids = {f.control_id for f in report.findings}
    assert ids == {"ID-01", "ID-02", "DR-02"}


def test_restore_drill_over_30_days_still_allows_compliance_above_90_if_no_critical_high():
    report = evaluate_tenant_posture(_hardened(last_restore_drill_days=45))
    assert report.score == 95
    assert report.compliant is True
    assert [f.control_id for f in report.findings] == ["DR-03"]


def test_prioritize_remediation_orders_critical_before_high_and_medium():
    r1 = evaluate_tenant_posture(_hardened("t-a", spf_strict=False, last_restore_drill_days=60))
    r2 = evaluate_tenant_posture(_hardened("t-b", unrotated_leaks=2, voip_tls_srtp_enabled=False))
    queue = prioritize_remediation([r1, r2])
    assert queue[0][:2] == ("t-b", "CRED-01")
    assert queue[-1][:2] == ("t-a", "DR-03")
