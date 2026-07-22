#!/usr/bin/env python3
"""
RM-S-PAY-001 Reference Verifier
===============================

Reference implementation of the verification procedure in RM-S-PAY-001 §15.1
(27 steps) and the determination rules of §16.

Purpose: prove the standard can actually be implemented, and that the §21 test
cases produce the results the standard states.

Usage:
    python3 rm_s_pay_001_verifier.py
"""

import sys
from decimal import Decimal, InvalidOperation, getcontext
from datetime import datetime, timedelta

getcontext().prec = 40


class Verification:
    def __init__(self):
        self.steps = []
        self.failures = []
        self.gap_codes = set()
        self.violation_codes = set()
        self.unmet_should = []
        self.notes = []

    def step(self, n, desc, ok, code=None, detail="", gap=False):
        """gap=True: could not be verified (data absent) -> §16.6 DEFICIENT
           gap=False: verified and wrong                 -> §16.3 FAIL"""
        self.steps.append((n, desc, ok, detail))
        if not ok and code:
            if code not in self.failures:
                self.failures.append(code)
            (self.gap_codes if gap else self.violation_codes).add(code)
        return ok

    def should_unmet(self, name):
        self.unmet_should.append(name)


def amt(v):
    """§18.2 — amounts are decimal strings; floats are prohibited."""
    if isinstance(v, float):
        raise TypeError("float amount encountered; §18.2 prohibits floating point")
    if v is None:
        return None
    try:
        return Decimal(str(v))
    except InvalidOperation:
        return None


def ts(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None


# §18.4 permitted status transitions
TRANSITIONS = {
    "INITIATED": {"AUTHORIZED", "FAILED"},
    "AUTHORIZED": {"SUBMITTED", "FAILED"},
    "SUBMITTED": {"PENDING_EXTERNAL_CONFIRMATION", "EXECUTING", "SETTLED", "FAILED"},
    "PENDING_EXTERNAL_CONFIRMATION": {"EXECUTING", "SETTLED", "FAILED"},
    "EXECUTING": {"SETTLED", "FAILED", "REVERSED"},
    "SETTLED": {"REFUNDED_PARTIAL", "REFUNDED_FULL", "CHARGEBACK"},
    "REFUNDED_PARTIAL": {"REFUNDED_PARTIAL", "REFUNDED_FULL", "CHARGEBACK"},
    "FAILED": set(),
    "REVERSED": set(),
    "REFUNDED_FULL": set(),
    "CHARGEBACK": set(),
}

TERMINAL_NO_SETTLE = {"FAILED", "REVERSED", "REFUNDED_FULL"}

TIME_SOURCE_PRECEDENCE = ["TRUSTED_TIMESTAMP", "BLOCK_TIMESTAMP",
                          "SETTLEMENT_TIMESTAMP", "UTC_SYSTEM"]


def verify(rec):
    v = Verification()
    cs = rec.get("conformity_subject", {})
    pi = rec.get("payment_instruction", {})
    au = rec.get("authorization", {})
    ex = rec.get("execution", {})
    hist = rec.get("status_history", [])
    st = rec.get("settlement")
    fin = rec.get("finality")
    parties = rec.get("parties", {})

    # 1. standard identifier, version, machine identifier
    std = rec.get("standard", {})
    v.step(1, "confirm standard id/version/machine id",
           std.get("standard_id") == "RM-S-PAY-001" and bool(std.get("standard_version"))
           and bool(std.get("machine_identifier")), "RMFPAY-ID-001")

    # 2. conformity subject type and identifier uniqueness
    has_pay = bool(cs.get("payment_id"))
    has_batch = bool(cs.get("batch_id"))
    v.step(2, "conformity subject identity",
           bool(cs.get("conformity_subject_id")) and (has_pay ^ has_batch),
           "RMFPAY-ID-001")

    # 3. obligated party
    op = rec.get("obligated_party", {})
    v.step(3, "confirm obligated party",
           bool(op.get("obligated_party_id")) and bool(op.get("legal_name")),
           "RMFPAY-ID-002")

    # 4. verification time + §18.8 authoritative time source
    vt = ts(rec.get("verification_time"))
    tsrc = rec.get("time_sources", {})
    v.step(4, "confirm verification time (UTC)", vt is not None, "RMFPAY-ID-001")
    vsrc = tsrc.get("verification_time_source")
    v.step(4, "declare authoritative time source (§18.8)",
           vsrc in ("UTC_SYSTEM", "TRUSTED_TIMESTAMP"), "RMFPAY-TIM-001")
    if st and not tsrc.get("settlement_time_source"):
        v.step(4, "settlement time source declared", False, "RMFPAY-TIM-001")
    if fin and not tsrc.get("finality_time_source"):
        v.step(4, "finality time source declared", False, "RMFPAY-TIM-001")
    disc = tsrc.get("max_observed_discrepancy_seconds")
    if disc is not None and disc > 300 and not tsrc.get("discrepancy_recorded"):
        v.step(4, "time discrepancy within 300s tolerance", False, "RMFPAY-TIM-001",
               f"{disc}s")

    # 5. payment_id unique within network and environment
    v.step(5, "payment identifier unique",
           bool(pi.get("payment_id")) and pi.get("payment_id") == cs.get("payment_id"),
           "RMFPAY-ID-003")

    # 6. payer / payee / agent identity
    payer, payee = parties.get("payer"), parties.get("payee")
    ident_ok = bool(payer and payer.get("party_id")) and bool(payee and payee.get("party_id"))
    if cs.get("conformity_subject_type") == "AGENT_PAYMENT":
        ident_ok = ident_ok and bool(parties.get("agent"))
    v.step(6, "identify payer, payee, agent", ident_ok, "RMFPAY-ID-002", gap=True)

    # 7. payment instruction content
    v.step(7, "payment instruction complete",
           all(pi.get(k) for k in ("payment_id", "created_at", "purpose_code",
                                   "gross_amount", "currency"))
           and pi.get("decimals") is not None, "RMFPAY-INS-001", gap=True)

    # 8. amount representation
    g = amt(pi.get("gross_amount"))
    v.step(8, "amounts are decimal strings with declared decimals",
           g is not None and isinstance(pi.get("gross_amount"), str), "RMFPAY-AMT-001")

    # 9. authorization bound to instruction, not later than first execution
    auth_t = ts(au.get("authorized_at"))
    exec_t = ts(ex.get("submitted_at"))
    v.step(9, "authorization evidence present and ordered",
           bool(au.get("authorization_id")) and auth_t is not None
           and (exec_t is None or auth_t <= exec_t), "RMFPAY-AUT-001", gap=True)
    _ad = au.get("instruction_digest")
    if not _ad or not au.get("authorization_scope"):
        # digest or scope absent -> cannot verify (curable gap)
        v.step(9, "authorization binding present", False, "RMFPAY-AUT-002", gap=True)
    elif _ad != pi.get("instruction_digest"):
        # present but bound to a different instruction -> affirmative violation
        v.step(9, "authorization bound to this instruction", False, "RMFPAY-AUT-002")
    else:
        v.step(9, "authorization bound to this instruction", True)
    v.step(9, "authentication not treated as authorization",
           au.get("authorization_method") != "AUTHENTICATION_ONLY", "RMFPAY-AUT-003")

    # 9b. agent limits (§7.4, §7.5)
    ag = parties.get("agent")
    if ag:
        v.step(9, "agent authorization fields complete",
               all(ag.get(k) for k in ("agent_id", "principal_id", "authorization_scope",
                                       "max_single_payment_amount", "allowed_payee_ids",
                                       "authorization_expires_at")), "RMFPAY-AGT-001")
        lim = amt(ag.get("max_single_payment_amount"))
        exp = ts(ag.get("authorization_expires_at"))
        over = (lim is not None and g is not None and g > lim)
        expired = (exp is not None and auth_t is not None and auth_t > exp)
        outside = (ag.get("allowed_payee_ids") and payee
                   and payee.get("party_id") not in ag["allowed_payee_ids"])
        v.step(9, "agent within limit, scope and expiry",
               not (over or expired or outside), "RMFPAY-AGT-002",
               f"over={over} expired={expired} outside={outside}")

    # 10. idempotency and duplicate detection
    v.step(10, "idempotency key present", bool(pi.get("idempotency_key")),
           "RMFPAY-DUP-001")
    dups = rec.get("_observed_duplicate_settlements", 0)
    v.step(10, "no duplicate successful payment without independent authorization",
           dups < 2, "RMFPAY-DUP-002", f"settlements with same key={dups}")

    # 11. submission and external proof of receipt
    v.step(11, "external proof of receipt", bool(ex.get("external_reference")),
           "RMFPAY-EXE-001", gap=True)

    # 12. replay status history
    hist_ok = len(hist) >= 1
    prev_t = None
    for i, e in enumerate(hist):
        t = ts(e.get("occurred_at"))
        if t is None or not e.get("actor_id") or not e.get("reason_code"):
            hist_ok = False
        if prev_t and t and t < prev_t:
            hist_ok = False
            v.notes.append("status times not monotonic")
        prev_t = t or prev_t
        if i > 0:
            a, b = hist[i - 1].get("status"), e.get("status")
            if b not in TRANSITIONS.get(a, set()):
                v.step(12, f"transition {a} -> {b} permitted", False, "RMFPAY-STA-001")
                if a in TERMINAL_NO_SETTLE and b == "SETTLED":
                    v.step(12, "prohibited terminal -> SETTLED", False, "RMFPAY-STA-002")
    v.step(12, "status history complete and monotonic", hist_ok, "RMFPAY-STA-001")
    current = hist[-1].get("status") if hist else None

    # 13. settlement evidence where SETTLED
    if current == "SETTLED" or any(e.get("status") == "SETTLED" for e in hist):
        v.step(13, "settlement evidence present", bool(st), "RMFPAY-SET-001", gap=True)
        if st:
            v.step(13, "settlement evidence complete",
                   all(st.get(k) for k in ("settlement_status", "settled_at",
                                           "settled_amount", "currency",
                                           "external_reference", "source",
                                           "evidence_id")), "RMFPAY-SET-002", gap=True)
            # §10.2 (revised): settled amount MUST reconcile to net_amount (§11.1)
            _fees = rec.get("fees", [])
            _payee_fees = sum((amt(f.get("amount")) or Decimal(0))
                              for f in _fees if f.get("borne_by") == "PAYEE")
            _fx = rec.get("exchange_rate")
            _rate = amt(_fx.get("rate")) if _fx else Decimal(1)
            _g = amt(pi.get("gross_amount")) or Decimal(0)
            _net = (_g * _rate) - _payee_fees
            _settled = amt(st.get("settled_amount"))
            if _settled is not None and not st.get("alternative_basis_declared"):
                v.step(13, "settled amount reconciles to net_amount (§10.2)",
                       _settled == _net, "RMFPAY-AMT-002",
                       f"settled={_settled} net={_net}")

    # 14. finality rules and state (§10.3–§10.6)
    if fin:
        v.step(14, "finality parameters present",
               all(fin.get(k) for k in ("finality_type", "rule_name", "rule_version",
                                        "reached_at", "evidence_id")),
               "RMFPAY-FIN-002")
        state = fin.get("finality_state")
        v.step(14, "finality state declared",
               state in ("PENDING", "CONDITIONAL", "REVERSIBLE", "IRREVOCABLE"),
               "RMFPAY-FIN-004")
        # §10.6 (revised): IRREVOCABLE requires operational finality reached,
        # all refund/dispute/chargeback windows expired with evidence, and no
        # ordinary reversal process remaining. Windows are per-payment facts,
        # not the generic transition table.
        if state == "IRREVOCABLE":
            cond = (fin.get("operational_finality_reached") is True
                    and fin.get("reversal_windows_expired") is True
                    and bool(fin.get("window_expiry_evidence_id"))
                    and fin.get("obligated_party_can_reverse") is False)
            v.step(14, "IRREVOCABLE conditions of §10.6 satisfied", cond,
                   "RMFPAY-FIN-004")
            # a later adjustment proves the classification was wrong
            if rec.get("adjustments"):
                v.step(14, "no adjustment after IRREVOCABLE", False, "RMFPAY-FIN-004")
        if fin.get("finality_type") == "LEGAL" and not fin.get("legal_opinion_evidence_id"):
            v.step(14, "legal finality supported by legal opinion", False,
                   "RMFPAY-FIN-003")

    # 15. amount conservation (§11.1)
    fees = rec.get("fees", [])
    payer_fees = sum((amt(f.get("amount")) or Decimal(0))
                     for f in fees if f.get("borne_by") == "PAYER")
    payee_fees = sum((amt(f.get("amount")) or Decimal(0))
                     for f in fees if f.get("borne_by") == "PAYEE")
    fx = rec.get("exchange_rate")
    rate = amt(fx.get("rate")) if fx else Decimal(1)
    total_debited = (g or Decimal(0)) + payer_fees
    net_amount = ((g or Decimal(0)) * rate) - payee_fees
    declared_debited = amt(rec.get("total_debited"))
    declared_net = amt(rec.get("net_amount"))
    cons_ok = True
    if declared_debited is not None and declared_debited != total_debited:
        cons_ok = False
        v.notes.append(f"total_debited declared {declared_debited} != computed {total_debited}")
    if declared_net is not None and declared_net != net_amount:
        cons_ok = False
        v.notes.append(f"net_amount declared {declared_net} != computed {net_amount}")
    # cumulative refund limit (§12.3)
    refunds = sum((amt(a.get("amount")) or Decimal(0))
                  for a in rec.get("adjustments", [])
                  if a.get("adjustment_type") in ("REFUND", "REVERSAL"))
    refundable_principal = g or Decimal(0)   # §3: gross, fees excluded
    if refunds > refundable_principal:
        cons_ok = False
        v.notes.append(f"cumulative refund {refunds} exceeds refundable principal {refundable_principal}")
        v.step(15, "cumulative refund within limit", False, "RMFPAY-REV-002")
    v.step(15, "amount conservation re-computed", cons_ok, "RMFPAY-AMT-002")

    # 16. exchange rate and fees
    if fx:
        v.step(16, "exchange rate fields complete",
               all(fx.get(k) for k in ("source_currency", "target_currency", "rate",
                                       "source", "observed_at", "rounding_mode")),
               "RMFPAY-FX-001")
    for f in fees:
        if not (f.get("borne_by") and f.get("recipient_id") and f.get("amount")
                and f.get("currency")):
            v.step(16, "fee fields complete", False, "RMFPAY-FEE-001")

    # 17. failure records
    if current == "FAILED":
        fr = rec.get("failure_record", {})
        v.step(17, "failure record complete",
               all(fr.get(k) for k in ("failed_at", "stage", "code", "source"))
               and fr.get("funds_moved") is not None, "RMFPAY-ERR-001")

    # 18. refunds / reversals / chargebacks
    for a in rec.get("adjustments", []):
        v.step(18, "adjustment references original payment and is complete",
               all(a.get(k) for k in ("adjustment_id", "adjustment_type",
                                      "original_payment_id", "amount", "currency",
                                      "occurred_at", "reason_code", "external_reference",
                                      "evidence_id")), "RMFPAY-REV-001")
    if current == "REFUNDED_FULL":
        v.step(18, "full refund status consistent with amounts",
               refunds == (g or Decimal(0)), "RMFPAY-REV-002")

    # 19. disputes and material events
    for d in rec.get("disputes", []):
        v.step(19, "dispute record complete",
               all(d.get(k) for k in ("dispute_id", "opened_at", "disputed_amount",
                                      "currency", "reason_code", "status")),
               "RMFPAY-DSP-001")
    for me in rec.get("material_events", []):
        dt, pt = ts(me.get("detected_at")), ts(me.get("published_at"))
        if dt and pt and (pt - dt) > timedelta(hours=24):
            v.step(19, "material event published within 24h", False, "RMFPAY-EVT-001",
                   f"{(pt-dt).total_seconds()/3600:.1f}h")

    # 20. retention >= 7 years
    ry = rec.get("retention_years")
    v.step(20, "retention period at least 7 years",
           ry is not None and ry >= 7, "RMFPAY-RET-001", gap=True)

    # 21. evidence metadata, age, digests, location
    REQUIRED = ["EVD-001", "EVD-002", "EVD-003", "EVD-004", "EVD-005", "EVD-006",
                "EVD-012", "EVD-013", "EVD-014", "EVD-015"]
    if st:
        REQUIRED.append("EVD-007")
    if fin:
        REQUIRED.append("EVD-008")
    if fees or fx:
        REQUIRED.append("EVD-009")
    if rec.get("adjustments"):
        REQUIRED.append("EVD-010")
    if rec.get("disputes"):
        REQUIRED.append("EVD-011")
    if rec.get("material_events"):
        REQUIRED.append("EVD-016")
    ev = {e.get("evidence_id"): e for e in rec.get("evidence", [])}
    missing = [e for e in REQUIRED if e not in ev]
    v.step(21, "mandatory evidence present", not missing, "RMFPAY-EVD-001",
           f"missing={missing}", gap=True)
    meta_ok = all(all(e.get(k) for k in ("provider_id", "generated_at", "acquired_at",
                                         "uri", "sha256"))
                  for e in ev.values())
    v.step(21, "evidence metadata complete", meta_ok, "RMFPAY-EVD-001", gap=True)
    # §14.4 current-status evidence <= 24h
    fresh_ok = True
    if vt:
        for eid in ("EVD-006",):           # status history = current status evidence
            e = ev.get(eid)
            if e:
                gt = ts(e.get("generated_at"))
                if gt and (vt - gt) > timedelta(hours=24):
                    fresh_ok = False
                    v.notes.append(f"{eid} age {(vt-gt).total_seconds()/3600:.1f}h > 24h")
    v.step(21, "current-status evidence within 24h", fresh_ok, "RMFPAY-EVD-003", gap=True)

    # 22. human / machine consistency
    hd = rec.get("human_disclosure", {})
    conflict = False
    for f_, mv in (("payment_id", pi.get("payment_id")),
                   ("amount", pi.get("gross_amount")),
                   ("currency", pi.get("currency")),
                   ("status", current)):
        hv = hd.get(f_)
        if hv is not None and str(hv) != str(mv):
            conflict = True
            v.notes.append(f"human/machine mismatch on {f_}: {hv} vs {mv}")
    v.step(22, "human / machine consistency", not conflict, "RMFPAY-DAT-001")

    # 23. digests
    dg_ok = all(isinstance(e.get("sha256"), str) and len(e["sha256"]) == 64
                for e in ev.values())
    v.step(23, "evidence digests well-formed", dg_ok, "RMFPAY-EVD-002")

    # 24. signature
    sg = rec.get("signature", {})
    v.step(24, "verification signature complete",
           all(sg.get(k) for k in ("signature_format", "algorithm", "key_id",
                                   "signed_at", "public_key_uri", "signed_digest",
                                   "signature_value")), "RMFPAY-SIG-001", gap=True)

    # 25–26. per-requirement results and re-computability
    rr = rec.get("requirement_results", [])
    rr_ok = len(rr) >= 1 and all(
        r.get("requirement_id") and r.get("applicability") and r.get("result")
        and (r.get("result") != "FAIL" or r.get("failure_code"))
        for r in rr)
    v.step(25, "per-requirement results recorded with traceability", rr_ok,
           "RMFPAY-VER-001")

    # SHOULD items (§9.4, §9.5, §9.6)
    if rec.get("status_api_available") is False:
        v.should_unmet("§9.4 status query interface")
    if rec.get("terminal_record_within_60s") is False:
        v.should_unmet("§9.5 terminal record within 60 seconds")
    if rec.get("pending_external_used") is False:
        v.should_unmet("§9.6 PENDING_EXTERNAL_CONFIRMATION on unknown state")

    # §16.6: gap codes = "could not be verified" (curable), not "violated"
    GAP_CODES = {"RMFPAY-EVD-001", "RMFPAY-EVD-003", "RMFPAY-ID-002",
                 "RMFPAY-INS-001", "RMFPAY-AUT-001", "RMFPAY-AUT-002",
                 "RMFPAY-EXE-001", "RMFPAY-SET-001", "RMFPAY-SET-002",
                 "RMFPAY-FIN-001", "RMFPAY-FIN-002", "RMFPAY-FIN-004",
                 "RMFPAY-FX-001", "RMFPAY-FEE-001", "RMFPAY-ERR-001",
                 "RMFPAY-REV-001", "RMFPAY-DSP-001", "RMFPAY-RET-001",
                 "RMFPAY-SIG-001", "RMFPAY-VER-001", "RMFPAY-TIM-001",
                 "RMFPAY-AGT-001", "RMFPAY-DUP-001"}
    violations = [c for c in v.failures if c in v.violation_codes]
    gaps = [c for c in v.failures if c in v.gap_codes and c not in v.violation_codes]
    if violations:
        overall = "FAIL"
    elif gaps:
        overall = "DEFICIENT"
    elif v.unmet_should:
        overall = "CONDITIONAL"
    else:
        overall = "PASS"
    v.violations, v.gaps = violations, gaps
    return overall, v


# --------------------------------------------------------------------------
# §21 test cases
# --------------------------------------------------------------------------

H = "a" * 64
U = "2026-01-01T00:00:00Z"


def base_record():
    return {
        "record_id": "rec-1", "schema_version": "1.0",
        "verification_time": U, "result_expires_at": "2026-01-02T00:00:00Z",
        "digest_algorithm": "sha-256", "retention_years": 7,
        "time_sources": {"verification_time_source": "UTC_SYSTEM",
                         "settlement_time_source": "SETTLEMENT_TIMESTAMP",
                         "max_observed_discrepancy_seconds": 12},
        "standard": {"standard_id": "RM-S-PAY-001", "standard_version": "v1.0-F",
                     "machine_identifier": "rulemark:standard:rm-s-pay-001:v1.0-F",
                     "authoritative_language": "ENGLISH"},
        "conformity_subject": {"conformity_subject_type": "SINGLE_PAYMENT",
                               "conformity_subject_id": "cs-1", "payment_id": "pay-1",
                               "payment_network": "SEPA_INST", "environment": "PRODUCTION",
                               "implementation_name": "impl", "implementation_version": "1.0"},
        "obligated_party": {"obligated_party_id": "psp-1", "legal_name": "Example PSP Ltd",
                            "jurisdiction": "DE",
                            "responsibility_statement_uri": "https://example.com/r",
                            "identity_evidence_id": "EVD-001"},
        "parties": {"payer": {"party_id": "payer-1", "identifier_type": "ACCOUNT_ID",
                              "identity_evidence_id": "EVD-001"},
                    "payee": {"party_id": "payee-1", "identifier_type": "ACCOUNT_ID",
                              "identity_evidence_id": "EVD-001"}},
        "payment_instruction": {"payment_id": "pay-1", "idempotency_key": "idem-1",
                                "created_at": U, "purpose_code": "GOODS",
                                "gross_amount": "100.00", "currency": "USD",
                                "decimals": 2, "instruction_digest": H},
        "authorization": {"authorization_id": "auth-1", "authorizer_id": "payer-1",
                          "authorization_method": "DIGITAL_SIGNATURE", "authorized_at": U,
                          "authorization_scope": "SINGLE_PAYMENT",
                          "instruction_digest": H, "evidence_id": "EVD-004"},
        "execution": {"submitted_at": U, "external_reference": "NET-1", "network": "SEPA",
                      "acceptance_status": "ACCEPTED", "evidence_id": "EVD-005"},
        "status_history": [
            {"status_event_id": "s1", "status": "INITIATED", "occurred_at": U,
             "actor_id": "psp-1", "reason_code": "CREATED", "evidence_id": "EVD-006"},
            {"status_event_id": "s2", "status": "AUTHORIZED", "occurred_at": U,
             "actor_id": "payer-1", "reason_code": "AUTHORISED", "evidence_id": "EVD-006"},
            {"status_event_id": "s3", "status": "SUBMITTED", "occurred_at": U,
             "actor_id": "psp-1", "reason_code": "SUBMITTED", "evidence_id": "EVD-006"},
            {"status_event_id": "s4", "status": "SETTLED", "occurred_at": U,
             "actor_id": "bank", "reason_code": "SETTLED", "evidence_id": "EVD-006"}],
        "settlement": {"settlement_status": "SETTLED", "settled_at": U,
                       "settled_amount": "100.00", "currency": "USD",
                       "external_reference": "SET-1", "source": "BANK",
                       "evidence_id": "EVD-007"},
        "fees": [{"fee_id": "f1", "fee_type": "PROCESSING", "amount": "1.00",
                  "currency": "USD", "borne_by": "PAYER", "recipient_id": "psp-1"}],
        "total_debited": "101.00", "net_amount": "100.00",
        "adjustments": [], "disputes": [], "material_events": [],
        "evidence": [{"evidence_id": e, "evidence_type": "X", "provider_id": "p",
                      "generated_at": U, "acquired_at": U,
                      "uri": "https://example.com/e", "sha256": H,
                      "signature_present": True}
                     for e in ["EVD-001", "EVD-002", "EVD-003", "EVD-004", "EVD-005",
                               "EVD-006", "EVD-007", "EVD-009", "EVD-012", "EVD-013",
                               "EVD-014", "EVD-015"]],
        "requirement_results": [{"requirement_id": "REQ-001", "applicability": "APPLICABLE",
                                 "result": "PASS", "evidence_ids": ["EVD-001"],
                                 "verification_step": 2}],
        "human_disclosure": {"payment_id": "pay-1", "amount": "100.00",
                             "currency": "USD", "status": "SETTLED"},
        "overall_result": {"verification_result": "PASS"},
        "verifier": {"verifier_id": "v1", "legal_name": "Example Auditors",
                     "role": "INDEPENDENT_THIRD_PARTY",
                     "verification_implementation": "ref", "implementation_version": "1.0"},
        "signature": {"signature_format": "JWS", "algorithm": "ES256", "key_id": "k1",
                      "signed_at": U, "public_key_uri": "https://example.com/jwks",
                      "signed_digest": H, "signature_value": "sig=="},
    }


def c1():
    return "21.1 PASS case", base_record(), "PASS", []

def c2():
    r = base_record(); r.pop("settlement")
    r["evidence"] = [e for e in r["evidence"] if e["evidence_id"] != "EVD-007"]
    return "21.2 settlement evidence missing", r, "DEFICIENT", ["RMFPAY-SET-001"]

def c3():
    r = base_record()
    r["authorization"] = {"authorization_id": "", "authorizer_id": "", "authorized_at": None}
    r["evidence"] = [e for e in r["evidence"] if e["evidence_id"] != "EVD-004"]
    return "21.3 authorization missing", r, "DEFICIENT", ["RMFPAY-AUT-001", "RMFPAY-EVD-001"]

def c4():
    r = base_record(); r["human_disclosure"]["amount"] = "205.00"
    return "21.4 human/machine conflict", r, "FAIL", ["RMFPAY-DAT-001"]

def c5():
    r = base_record(); r["status_api_available"] = False
    return "21.5 SHOULD unmet", r, "CONDITIONAL", []

def c6():
    r = base_record(); r["_observed_duplicate_settlements"] = 2
    return "21.6 duplicate payment", r, "FAIL", ["RMFPAY-DUP-002"]

def c7():
    r = base_record()
    r["conformity_subject"]["conformity_subject_type"] = "AGENT_PAYMENT"
    r["parties"]["agent"] = {"agent_id": "ag-1", "principal_id": "payer-1",
                             "authorization_scope": ["goods"],
                             "max_single_payment_amount": "500.00",
                             "allowed_payee_ids": ["payee-1"],
                             "authorization_expires_at": "2026-12-31T00:00:00Z"}
    r["payment_instruction"]["gross_amount"] = "750.00"
    r["total_debited"] = "751.00"; r["net_amount"] = "750.00"
    r["human_disclosure"]["amount"] = "750.00"
    return "21.7 agent over limit", r, "FAIL", ["RMFPAY-AGT-002"]

def c8():
    r = base_record()
    r["status_history"] = [
        {"status_event_id": "s1", "status": "INITIATED", "occurred_at": U,
         "actor_id": "psp-1", "reason_code": "C", "evidence_id": "EVD-006"},
        {"status_event_id": "s2", "status": "FAILED", "occurred_at": U,
         "actor_id": "psp-1", "reason_code": "F", "evidence_id": "EVD-006"},
        {"status_event_id": "s3", "status": "SETTLED", "occurred_at": U,
         "actor_id": "psp-1", "reason_code": "S", "evidence_id": "EVD-006"}]
    r["human_disclosure"]["status"] = "SETTLED"
    return "21.8 prohibited transition", r, "FAIL", ["RMFPAY-STA-002"]

CASES = [c1, c2, c3, c4, c5, c6, c7, c8]


# --------------------------------------------------------------------------
# Adversarial tests beyond §21
# --------------------------------------------------------------------------

def a_irrevocable_after_settled():
    r = base_record()
    r["finality"] = {"finality_type": "OPERATIONAL", "finality_state": "IRREVOCABLE",
                     "rule_name": "SEPA-INST", "rule_version": "2023",
                     "reached_at": U, "evidence_id": "EVD-008",
                     "operational_finality_reached": True,
                     "reversal_windows_expired": True,
                     "window_expiry_evidence_id": "EVD-008",
                     "obligated_party_can_reverse": False}
    r["time_sources"]["finality_time_source"] = "SETTLEMENT_TIMESTAMP"
    r["evidence"].append({"evidence_id": "EVD-008", "evidence_type": "X", "provider_id": "p",
                          "generated_at": U, "acquired_at": U,
                          "uri": "https://example.com/e", "sha256": H,
                          "signature_present": True})
    return "ADV IRREVOCABLE with all §10.6 conditions met", r, "PASS", []

def a_auth_after_execution():
    r = base_record()
    r["authorization"]["authorized_at"] = "2026-01-02T00:00:00Z"
    return "ADV authorization after execution", r, "DEFICIENT", ["RMFPAY-AUT-001"]

def a_missing_time_source():
    r = base_record(); r.pop("time_sources")
    return "ADV time source not declared (§18.8)", r, "FAIL", ["RMFPAY-TIM-001"]

def a_block_time_for_verification():
    r = base_record(); r["time_sources"]["verification_time_source"] = "BLOCK_TIMESTAMP"
    return "ADV verification time uses BLOCK_TIMESTAMP (§18.8 forbids)", r, "FAIL", ["RMFPAY-TIM-001"]

def a_refund_over_principal():
    r = base_record()
    r["adjustments"] = [{"adjustment_id": "adj-1", "adjustment_type": "REFUND",
                         "original_payment_id": "pay-1", "amount": "150.00",
                         "currency": "USD", "occurred_at": U, "reason_code": "R",
                         "external_reference": "X", "evidence_id": "EVD-010"}]
    r["evidence"].append({"evidence_id": "EVD-010", "evidence_type": "X", "provider_id": "p",
                          "generated_at": U, "acquired_at": U,
                          "uri": "https://example.com/e", "sha256": H,
                          "signature_present": True})
    return "ADV cumulative refund exceeds principal", r, "FAIL", ["RMFPAY-REV-002"]

def a_amount_not_conserved():
    r = base_record(); r["total_debited"] = "100.00"     # fee not added
    return "ADV total_debited omits payer fee", r, "FAIL", ["RMFPAY-AMT-002"]

def a_retention_short():
    r = base_record(); r["retention_years"] = 3
    return "ADV retention 3 years (§14.5 min 7)", r, "DEFICIENT", ["RMFPAY-RET-001"]

def a_material_event_late():
    r = base_record()
    r["material_events"] = [{"event_id": "e1", "event_type": "REVERSAL",
                             "affected_payment_id": "pay-1",
                             "detected_at": "2026-01-01T00:00:00Z",
                             "published_at": "2026-01-03T00:00:00Z",
                             "current_status": "REVERSED", "evidence_id": "EVD-016",
                             "requires_reverification": True}]
    r["evidence"].append({"evidence_id": "EVD-016", "evidence_type": "X", "provider_id": "p",
                          "generated_at": U, "acquired_at": U,
                          "uri": "https://example.com/e", "sha256": H,
                          "signature_present": True})
    return "ADV material event published 48h late", r, "FAIL", ["RMFPAY-EVT-001"]

def a_stale_status_evidence():
    r = base_record()
    for e in r["evidence"]:
        if e["evidence_id"] == "EVD-006":
            e["generated_at"] = "2025-12-29T00:00:00Z"
    return "ADV status evidence 72h old (§14.4 limit 24h)", r, "DEFICIENT", ["RMFPAY-EVD-003"]

def a_float_amount():
    r = base_record(); r["payment_instruction"]["gross_amount"] = 100.00
    return "ADV float amount (§18.2 prohibits)", r, "REJECT", []

def a_auth_digest_mismatch():
    r = base_record(); r["authorization"]["instruction_digest"] = "b" * 64
    return "ADV authorization bound to a different instruction", r, "FAIL", ["RMFPAY-AUT-002"]

def a_irrevocable_without_windows():
    r = base_record()
    r["finality"] = {"finality_type": "OPERATIONAL", "finality_state": "IRREVOCABLE",
                     "rule_name": "SEPA-INST", "rule_version": "2023",
                     "reached_at": U, "evidence_id": "EVD-008",
                     "operational_finality_reached": True,
                     "reversal_windows_expired": False,
                     "obligated_party_can_reverse": True}
    r["time_sources"]["finality_time_source"] = "SETTLEMENT_TIMESTAMP"
    r["evidence"].append({"evidence_id": "EVD-008", "evidence_type": "X", "provider_id": "p",
                          "generated_at": U, "acquired_at": U,
                          "uri": "https://example.com/e", "sha256": H,
                          "signature_present": True})
    return "ADV IRREVOCABLE while refund window still open", r, "FAIL", ["RMFPAY-FIN-004"]

def a_settled_amount_mismatch():
    r = base_record()
    r["settlement"]["settled_amount"] = "95.00"      # net_amount is 100.00
    return "ADV settled amount does not reconcile to net_amount", r, "FAIL", ["RMFPAY-AMT-002"]

ADV = [a_irrevocable_after_settled, a_irrevocable_without_windows,
       a_settled_amount_mismatch, a_auth_after_execution, a_missing_time_source,
       a_block_time_for_verification, a_refund_over_principal, a_amount_not_conserved,
       a_retention_short, a_material_event_late, a_stale_status_evidence,
       a_float_amount, a_auth_digest_mismatch]


def main():
    print("=" * 74)
    print("RM-S-PAY-001 — §21 test cases through a reference verifier")
    print("=" * 74)
    all_ok = True
    for fn in CASES:
        name, rec, expect, codes = fn()
        overall, v = verify(rec)
        ok = overall == expect and all(c in v.failures for c in codes)
        all_ok &= ok
        print(f"\n[{'PASS' if ok else 'MISMATCH'}] {name}")
        print(f"   expected : {expect}" + (f"  {codes}" if codes else ""))
        print(f"   actual   : {overall}" + (f"  {v.failures}" if v.failures else ""))
        if v.unmet_should:
            print(f"   unmet SHOULD: {v.unmet_should}")
        for n in v.notes:
            print(f"   note: {n}")
        if not ok:
            miss = [c for c in codes if c not in v.failures]
            if miss:
                print(f"   >>> expected codes not raised: {miss}")

    print("\n" + "=" * 74)
    print("ADVERSARIAL TESTS")
    print("=" * 74)
    for fn in ADV:
        name, rec, expect, codes = fn()
        try:
            overall, v = verify(rec)
        except TypeError as e:
            print(f"\n[OK] {name}\n   rejected at parse: {e}")
            continue
        ok = overall == expect and all(c in v.failures for c in codes)
        print(f"\n[{'OK' if ok else 'GAP'}] {name}")
        print(f"   expected : {expect}" + (f"  {codes}" if codes else ""))
        print(f"   actual   : {overall}" + (f"  {v.failures}" if v.failures else ""))
        for n in v.notes:
            print(f"   note: {n}")

    print("\n" + "=" * 74)
    print("§21:", "all test cases reproduce the standard's stated results"
          if all_ok else "MISMATCH")
    print("=" * 74)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
