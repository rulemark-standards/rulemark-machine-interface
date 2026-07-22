#!/usr/bin/env python3
"""
RM-S-STABLE-001 Reference Verifier
==================================

A minimal reference implementation of the verification procedure defined in
RM-S-STABLE-001 §15.1 (21 steps) and the determination rules of §16.

Purpose: prove that the standard as written can actually be implemented, and that
the test cases in §21 produce the results the standard says they produce.

This is a conformance test harness, not a production verifier.

Usage:
    python3 rm_s_stable_001_verifier.py            # run the §21 test cases
    python3 rm_s_stable_001_verifier.py record.json
"""

import json
import sys
from decimal import Decimal, InvalidOperation, getcontext

getcontext().prec = 40  # §9 requires re-computable valuation


# --------------------------------------------------------------------------
# Result container
# --------------------------------------------------------------------------

class Verification:
    def __init__(self):
        self.step_log = []       # (step number, description, outcome)
        self.failures = []       # failure codes raised, in order
        self.gap_codes = set()       # §16.6 curable gaps
        self.violation_codes = set() # §16.3 affirmative violations
        self.unmet_should = []   # SHOULD items not satisfied
        self.notes = []

    def step(self, n, desc, ok, code=None, detail="", gap=False):
        """gap=True: the item could not be verified (data absent) -> §16.6 DEFICIENT
           gap=False: the item was verified and is wrong          -> §16.3 FAIL"""
        self.step_log.append((n, desc, "OK" if ok else "FAIL", detail))
        if not ok and code:
            if code not in self.failures:
                self.failures.append(code)
            (self.gap_codes if gap else self.violation_codes).add(code)
        return ok

    def should_unmet(self, name):
        self.unmet_should.append(name)


def amt(v):
    """§18.3: monetary values are strings; floats are prohibited."""
    if isinstance(v, float):
        raise TypeError("float amount encountered; §18.3 prohibits floating point")
    if v is None:
        return None
    try:
        return Decimal(str(v))
    except InvalidOperation:
        return None


# --------------------------------------------------------------------------
# §15.1 — the 21 steps, in order
# --------------------------------------------------------------------------

def verify(rec):
    v = Verification()
    s = rec.get("subject", {})

    # 1. confirm the standard version
    v.step(1, "confirm standard version",
           rec.get("standard_id") == "RM-S-STABLE-001" and bool(rec.get("standard_version")),
           "RMFSTABLE-ID-001")

    # 2. confirm the stablecoin canonical identity  (§5.1, §1.4)
    tok = s.get("token", {})
    nets = s.get("networks", [])
    ident_ok = bool(rec.get("subject_id")) and bool(tok.get("token_name")) \
        and bool(tok.get("token_symbol")) and len(nets) >= 1 \
        and all(n.get("chain_id") and n.get("contract_address") and n.get("contract_version")
                for n in nets)
    v.step(2, "confirm canonical identity", ident_ok, "RMFSTABLE-ID-001")

    # 3. confirm the issuer and responsible parties (§5.3)
    iss = s.get("issuer", {})
    v.step(3, "confirm issuer and responsible parties",
           bool(iss.get("issuer_legal_name")) and bool(iss.get("issuer_identifier")),
           "RMFSTABLE-ID-002", gap=True)

    # 4. confirm the verification point (§6.1)
    vp = s.get("verification_point")
    v.step(4, "confirm verification point",
           bool(vp) and str(vp).endswith("Z"), "RMFSTABLE-SUP-001")

    # 5. compute per-chain supply (§5.2, §6.2)
    per_chain = Decimal(0)
    chains_ok = len(nets) >= 1
    for n in nets:
        a = amt((n.get("issued_amount") or {}).get("amount"))
        if a is None:
            chains_ok = False
        else:
            per_chain += a
    v.step(5, "compute per-chain supply", chains_ok, "RMFSTABLE-SUP-001",
           f"sum={per_chain}", gap=(len(nets) == 0))

    # 6. compute effective circulating supply (§6.3)
    #    effective = total issued − burned − redemption-settled − declared exclusions
    total_supply = amt((s.get("total_supply") or {}).get("amount"))
    circ = amt((s.get("circulating_supply") or {}).get("amount"))
    supply_ok = total_supply is not None and circ is not None
    if supply_ok and chains_ok and per_chain != total_supply:
        # §6.2: the verifier MUST independently compute from chain data
        supply_ok = False
        v.notes.append(f"per-chain sum {per_chain} != declared total_supply {total_supply}")
    v.step(6, "compute effective circulating supply", supply_ok, "RMFSTABLE-SUP-001")

    # 6b. cross-chain double counting (§6.6)
    locked = sum((amt((n.get("cross_chain_locked") or {}).get("amount")) or Decimal(0))
                 for n in nets)
    v.step(6, "check cross-chain double counting",
           locked <= (total_supply or Decimal(0)), "RMFSTABLE-SUP-002")

    # 7. compute outstanding liabilities (§6.7)
    liab = amt((s.get("outstanding_liabilities") or {}).get("amount"))
    v.step(7, "compute outstanding liabilities", liab is not None, "RMFSTABLE-LIA-001")

    # 8. verify reserve asset ownership (§7.3)
    assets = s.get("reserve_assets", [])
    own_ok = len(assets) >= 1 and all(
        a.get("custodian") and a.get("account_id") and a.get("valuation_source")
        for a in assets)
    v.step(8, "verify reserve asset ownership", own_ok, "RMFSTABLE-RES-002", gap=True)

    # 8b. undisclosed pledge or lien (§7.4)
    lien = any(a.get("lien") or a.get("pledge") for a in assets)
    v.step(8, "check pledge / lien", not lien, "RMFSTABLE-RES-004")

    # 9. verify reserve segregation (§8.1–8.3)
    seg = s.get("segregation", {})
    v.step(9, "verify reserve segregation",
           bool(seg.get("legal_segregation_evidence_id")), "RMFSTABLE-SEG-001", gap=True)

    # 10. verify custody status (§8.4)
    cust = s.get("custodians", [])
    cust_ok = len(cust) >= 1 and all(
        c.get("legal_name") and c.get("custody_jurisdiction") and c.get("account_control")
        for c in cust)
    v.step(10, "verify custody status", cust_ok, "RMFSTABLE-CUS-001", gap=True)

    # 10b. undisclosed rehypothecation (§8.5)
    rehypo = any(c.get("rehypothecation_allowed") and not c.get("rehypothecation_disclosed")
                 for c in cust)
    v.step(10, "check rehypothecation disclosure", not rehypo, "RMFSTABLE-CUS-002")

    # 11. re-compute reserve asset value (§9.2)
    recomputed = Decimal(0)
    val_ok = len(assets) >= 1
    for a in assets:
        vv = amt((a.get("verified_value") or {}).get("amount"))
        if vv is None:
            val_ok = False
        else:
            recomputed += vv
    declared_reserve = amt((s.get("eligible_reserve_value") or {}).get("amount"))
    if val_ok and declared_reserve is not None and recomputed != declared_reserve:
        val_ok = False
        v.notes.append(f"recomputed reserve {recomputed} != declared {declared_reserve}")
    if len(assets) == 0:
        # no per-asset detail published -> cannot verify (curable gap)
        v.step(11, "reserve asset detail available for re-computation", False,
               "RMFSTABLE-VAL-001", "no per-asset detail", gap=True)
    else:
        v.step(11, "re-compute reserve asset value", val_ok, "RMFSTABLE-VAL-001",
               f"recomputed={recomputed}")

    # 12. re-compute the reserve coverage ratio (§7.1, §16.1(6))
    ratio_ok = True
    ratio = None
    if declared_reserve is not None and liab and liab > 0:
        ratio = declared_reserve / liab
        declared_ratio = amt(s.get("reserve_coverage_ratio"))
        # the standard's hard boundary: coverage below 100% is FAIL, however small
        if ratio < Decimal(1):
            ratio_ok = False
        if declared_ratio is not None and abs(declared_ratio - ratio) > Decimal("0.000001"):
            v.notes.append(f"declared ratio {declared_ratio} != recomputed {ratio}")
    else:
        ratio_ok = False
    v.step(12, "re-compute reserve coverage ratio", ratio_ok, "RMFSTABLE-RES-001",
           f"ratio={ratio}")

    # 13. verify redemption terms (§10.1, §10.4)
    red = s.get("redemption", {})
    v.step(13, "verify redemption disclosure",
           red.get("direct_redemption_available") is not None
           and bool(red.get("settlement_asset")), "RMFSTABLE-RED-001", gap=True)
    v.step(13, "verify redemption time quantified",
           bool(red.get("max_processing_time")), "RMFSTABLE-RED-002", gap=True)

    # 14. verify the attestation report (§11.1, §11.2, §14.4)
    atts = s.get("attestations", [])
    att_ok = len(atts) >= 1 and all(
        a.get("attestor_legal_name") and a.get("report_date") and a.get("verification_point")
        for a in atts)
    v.step(14, "verify attestation present and fresh", att_ok, "RMFSTABLE-ATT-001", gap=True)
    scope_ok = all("liabilities" in [x.lower() for x in a.get("scope", [])] for a in atts) \
        if atts else False
    v.step(14, "verify attestation scope includes liabilities", scope_ok,
           "RMFSTABLE-ATT-002")

    # 14b. §11.7 attestation firm independence
    undisclosed = any(a.get("independence_disclosed") is not True for a in atts)
    not_independent = any(a.get("controlled_by_issuer") is True
                          or a.get("common_control") is True for a in atts)
    if undisclosed:
        v.notes.append("attestation firm independence not disclosed (§11.7)")
    if not_independent:
        v.notes.append("attestation firm not independent of issuer (§11.7)")
    # undisclosed = curable gap; actually not independent = affirmative violation
    v.step(14, "attestation firm independence disclosed", not undisclosed,
           "RMFSTABLE-ATT-003", gap=True)
    v.step(14, "attestation firm independent of issuer", not not_independent,
           "RMFSTABLE-ATT-003", gap=False)

    # 15. verify contract permissions (§12.1, §12.2)
    perms = s.get("contract_permissions", [])
    perm_ok = len(perms) >= 1 and all(
        p.get("role") and p.get("control_mechanism") for p in perms)
    single_key = any(str(p.get("control_mechanism", "")).lower() in ("single_key", "eoa", "")
                     for p in perms)
    v.step(15, "verify contract permissions disclosed", perm_ok, "RMFSTABLE-EVD-001", gap=True)
    v.step(15, "verify no undisclosed single-key control", not single_key,
           "RMFSTABLE-SEC-001")

    # 16. check material events (§13.2)
    for ev in s.get("material_events", []):
        if ev.get("disclosed_late") is True:
            v.step(16, "material event disclosed within 24h", False, "RMFSTABLE-EVT-001")
    v.step(16, "check material events", True, None)

    # 17. verify machine / human consistency (§18.5)
    hd = rec.get("human_disclosure", {})
    conflict = False
    for field in ("circulating_supply", "outstanding_liabilities", "reserve_coverage_ratio"):
        hv = hd.get(field)
        if hv is None:
            continue
        mv = s.get(field)
        mv = mv.get("amount") if isinstance(mv, dict) else mv
        if amt(hv) is not None and amt(mv) is not None and amt(hv) != amt(mv):
            conflict = True
            v.notes.append(f"human/machine mismatch on {field}: {hv} vs {mv}")
    v.step(17, "verify human / machine consistency", not conflict, "RMFSTABLE-DAT-001")

    # 18. verify evidence digests and signatures (§14.2, §14.3, §14.5)
    # §14.1 Required column: Mandatory always
    REQUIRED_EVIDENCE = ["EVD-001", "EVD-002", "EVD-003", "EVD-004", "EVD-005",
                         "EVD-006", "EVD-007", "EVD-008", "EVD-009", "EVD-010",
                         "EVD-011", "EVD-013", "EVD-014"]
    # §14.1 conditional: EVD-012 where a material event occurred;
    #                    EVD-015 where bankruptcy remoteness is claimed (§8.7)
    if s.get("material_events"):
        REQUIRED_EVIDENCE.append("EVD-012")
    if s.get("bankruptcy_remoteness_claimed"):
        REQUIRED_EVIDENCE.append("EVD-015")
    ev_ids = {e.get("evidence_id") for e in rec.get("evidence", [])}
    missing = [e for e in REQUIRED_EVIDENCE if e not in ev_ids]
    v.step(18, "required evidence present", not missing, "RMFSTABLE-EVD-001",
           f"missing={missing}", gap=True)

    digest_ok = all(isinstance(e.get("sha256"), str) and len(e["sha256"]) == 64
                    for e in rec.get("evidence", []))
    v.step(18, "evidence digests well-formed", digest_ok, "RMFSTABLE-EVD-002")

    sig = rec.get("signature")
    v.step(18, "verification record signed", bool(sig), "RMFSTABLE-SIG-001", gap=True)

    # 18b. §14.4 evidence freshness: supply <= 24h, attestation <= 35 days
    from datetime import datetime, timezone
    def parse(t):
        try:
            return datetime.fromisoformat(str(t).replace("Z", "+00:00"))
        except Exception:
            return None
    vpt = parse(vp)
    fresh_ok = True
    if vpt:
        for e in rec.get("evidence", []):
            it = parse(e.get("issued_at"))
            if not it:
                fresh_ok = False
                continue
            age_h = (vpt - it).total_seconds() / 3600
            if e.get("evidence_id") == "EVD-003" and age_h > 24:
                fresh_ok = False
                v.notes.append(f"EVD-003 supply evidence age {age_h:.1f}h > 24h")
            if e.get("evidence_id") == "EVD-011" and age_h > 35 * 24:
                fresh_ok = False
                v.notes.append(f"EVD-011 attestation age {age_h/24:.1f}d > 35d")
    v.step(18, "evidence freshness within §14.4 limits", fresh_ok, "RMFSTABLE-EVD-003", gap=True)

    # 18c. §16.5 result validity period must not exceed 35 days
    ea = parse(rec.get("expires_at"))
    val_ok2 = True
    if vpt and ea:
        days = (ea - vpt).total_seconds() / 86400
        if days > 35:
            val_ok2 = False
            v.notes.append(f"result validity {days:.1f}d exceeds the 35-day maximum (§16.5)")
    if vpt and ea:
        # §16.5: expiry MUST NOT exceed the earliest expiry of mandatory evidence
        earliest = None
        for e in rec.get("evidence", []):
            it = parse(e.get("issued_at"))
            if not it:
                continue
            if e.get("evidence_id") == "EVD-003":
                exp = it.replace() + __import__("datetime").timedelta(hours=24)
            elif e.get("evidence_id") == "EVD-011":
                exp = it + __import__("datetime").timedelta(days=35)
            else:
                continue
            earliest = exp if earliest is None or exp < earliest else earliest
        if earliest and ea > earliest:
            val_ok2 = False
            v.notes.append(
                f"result expiry {ea.date()} is later than earliest evidence expiry "
                f"{earliest.date()} (§16.5)")
    v.step(18, "result validity period within §16.5", val_ok2, "RMFSTABLE-VER-002")

    # SHOULD items (§16.2) — unmet SHOULDs drive CONDITIONAL, not FAIL
    if s.get("liquidity_stress_disclosed") is False:
        v.should_unmet("§7.7 liquidity stress disclosure")
    if s.get("annual_audit_provided") is False:
        v.should_unmet("§11.5 annual financial statement audit")
    if s.get("attestation_materiality_disclosed") is False:
        v.should_unmet("§11.6 attestation materiality and limitations")
    if s.get("proxy_upgrade_disclosed") is False:
        v.should_unmet("§12.5 proxy upgrade pattern disclosure")

    # 19–20. compute individual and overall results (§16)
    # §16.6: codes that mean "could not be verified" (curable gap) rather than
    # "affirmatively violated on the available evidence".
    _UNUSED_GAP = {"RMFSTABLE-EVD-001",   # (superseded by per-step gap flags)
                 "RMFSTABLE-EVD-003",   # evidence expired
                 "RMFSTABLE-ID-002",    # responsible party cannot be confirmed
                 "RMFSTABLE-RES-002",   # ownership cannot be confirmed
                 "RMFSTABLE-CUS-001",   # custody cannot be confirmed
                 "RMFSTABLE-SEG-001",   # segregation cannot be proven
                 "RMFSTABLE-VAL-001",   # valuation cannot be re-computed
                 "RMFSTABLE-RED-001",   # redemption undisclosed
                 "RMFSTABLE-RED-002",   # redemption time not quantified
                 "RMFSTABLE-ATT-001",   # attestation missing
                 "RMFSTABLE-ATT-003",   # attestor independence undisclosed
                 "RMFSTABLE-SEC-001",   # permissions undisclosed
                 "RMFSTABLE-SUP-001",   # supply cannot be re-computed
                 "RMFSTABLE-LIA-001",   # liabilities cannot be confirmed
                 "RMFSTABLE-SIG-001",   # record not signed
                 "RMFSTABLE-VER-001", "RMFSTABLE-VER-002"}
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

    # 21. sign the verification record — represented by presence of a signature
    return overall, v


# --------------------------------------------------------------------------
# §21 test cases
# --------------------------------------------------------------------------

H = "a" * 64
U = "2026-01-01T00:00:00Z"

def base_record():
    """§21.1 — the PASS case: coverage 102%, everything present and consistent."""
    return {
        "canonical_id": "rulemark:record:rm-s-stable-001:test:0001",
        "standard_id": "RM-S-STABLE-001",
        "standard_version": "v1.0-F",
        "record_type": "stablecoin_trust_verification",
        "status": "ACTIVE",
        "subject_id": "stablecoin:example:usd:eth:0xabc",
        "issued_at": U, "updated_at": U, "expires_at": "2026-01-02T00:00:00Z",
        "sha256": H, "signature": "SIG==", "signer_id": "rulemark:verifier:001",
        "verification_result": "PASS",
        "verification_timestamp": U,
        "verifier_id": "rulemark:verifier:001",
        "evidence": [{"evidence_id": e, "evidence_type": "x", "issuer": "y",
                      "source": "z", "issued_at": U, "sha256": H, "status": "valid"}
                     for e in ["EVD-001","EVD-002","EVD-003","EVD-004","EVD-005",
                               "EVD-006","EVD-007","EVD-008","EVD-009","EVD-010",
                               "EVD-011","EVD-013","EVD-014"]],
        "human_disclosure": {
            "circulating_supply": "100000000.00",
            "outstanding_liabilities": "100000000.00",
            "reserve_coverage_ratio": "1.02",
        },
        "subject": {
            "issuer": {"issuer_legal_name": "Example Issuer Ltd",
                       "issuer_identifier": "LEI-EXAMPLE"},
            "token": {"token_name": "Example USD", "token_symbol": "EUSD"},
            "networks": [{"network": "Ethereum", "chain_id": "1",
                          "contract_address": "0xabc", "contract_version": "1.0",
                          "issued_amount": {"amount": "100000000.00",
                                            "currency": "USD", "decimals": 2}}],
            "reference_currency": "USD",
            "verification_point": U,
            "total_supply": {"amount": "100000000.00", "currency": "USD", "decimals": 2},
            "circulating_supply": {"amount": "100000000.00", "currency": "USD", "decimals": 2},
            "outstanding_liabilities": {"amount": "100000000.00", "currency": "USD", "decimals": 2},
            "eligible_reserve_value": {"amount": "102000000.00", "currency": "USD", "decimals": 2},
            "reserve_coverage_ratio": "1.02",
            "reserve_assets": [{
                "asset_type": "US Treasury Bill", "issuer": "US Treasury", "currency": "USD",
                "nominal_value": {"amount": "102000000.00", "currency": "USD", "decimals": 2},
                "book_value":    {"amount": "102000000.00", "currency": "USD", "decimals": 2},
                "verified_value":{"amount": "102000000.00", "currency": "USD", "decimals": 2},
                "liquidity_class": "within_7d", "custodian": "BNY Mellon",
                "account_id": "ACC-1", "valuation_source": "Bloomberg",
                "lien": False, "pledge": False}],
            "segregation": {"legal_segregation_evidence_id": "EVD-007"},
            "custodians": [{"legal_name": "BNY Mellon", "custody_jurisdiction": "US",
                            "account_control": "issuer_directed",
                            "rehypothecation_allowed": False}],
            "redemption": {"direct_redemption_available": True,
                           "settlement_asset": "USD",
                           "max_processing_time": "2 business days"},
            "attestations": [{"attestor_legal_name": "Example Attestor LLP",
                              "report_date": U, "verification_point": U,
                              "scope": ["reserves", "liabilities", "coverage ratio"],
                              "independence_disclosed": True,
                              "controlled_by_issuer": False}],
            "contract_permissions": [{"role": "mint", "control_mechanism": "multisig"},
                                     {"role": "burn", "control_mechanism": "multisig"}],
            "material_events": [],
        },
    }


def case_21_1():
    return "21.1 PASS case", base_record(), "PASS", []

def case_21_2():
    r = base_record()
    r["subject"]["eligible_reserve_value"]["amount"] = "98500000.00"
    r["subject"]["reserve_assets"][0]["verified_value"]["amount"] = "98500000.00"
    r["subject"]["reserve_coverage_ratio"] = "0.985"
    r["human_disclosure"]["reserve_coverage_ratio"] = "0.985"
    return "21.2 reserve shortfall", r, "FAIL", ["RMFSTABLE-RES-001"]

def case_21_3():
    r = base_record()
    r["evidence"] = [e for e in r["evidence"] if e["evidence_id"] != "EVD-006"]
    r["subject"]["custodians"] = [{"legal_name": "BNY Mellon"}]   # incomplete custody
    return "21.3 missing evidence", r, "DEFICIENT", ["RMFSTABLE-CUS-001", "RMFSTABLE-EVD-001"]

def case_21_4():
    r = base_record()
    r["subject"]["circulating_supply"]["amount"] = "510000000.00"
    r["human_disclosure"]["circulating_supply"] = "500000000.00"
    # keep supply arithmetic otherwise consistent so DAT-001 is isolated
    r["subject"]["total_supply"]["amount"] = "510000000.00"
    r["subject"]["networks"][0]["issued_amount"]["amount"] = "510000000.00"
    r["subject"]["outstanding_liabilities"]["amount"] = "510000000.00"
    r["human_disclosure"]["outstanding_liabilities"] = "510000000.00"
    r["subject"]["eligible_reserve_value"]["amount"] = "520200000.00"
    r["subject"]["reserve_assets"][0]["verified_value"]["amount"] = "520200000.00"
    return "21.4 human/machine conflict", r, "FAIL", ["RMFSTABLE-DAT-001"]

def case_21_5():
    r = base_record()
    r["subject"]["liquidity_stress_disclosed"] = False
    return "21.5 SHOULD unmet", r, "CONDITIONAL", []


CASES = [case_21_1, case_21_2, case_21_3, case_21_4, case_21_5]

# --------------------------------------------------------------------------
# Adversarial tests — beyond §21, probing boundaries and claimed protections
# --------------------------------------------------------------------------

def adv_coverage_exact_100():
    r = base_record()
    for k in ("eligible_reserve_value",):
        r["subject"][k]["amount"] = "100000000.00"
    r["subject"]["reserve_assets"][0]["verified_value"]["amount"] = "100000000.00"
    r["subject"]["reserve_coverage_ratio"] = "1.0"
    r["human_disclosure"]["reserve_coverage_ratio"] = "1.0"
    return "ADV coverage exactly 100.000%", r, "PASS", []

def adv_coverage_hair_under():
    r = base_record()
    r["subject"]["eligible_reserve_value"]["amount"] = "99999999.99"
    r["subject"]["reserve_assets"][0]["verified_value"]["amount"] = "99999999.99"
    r["subject"]["reserve_coverage_ratio"] = "0.9999999999"
    r["human_disclosure"]["reserve_coverage_ratio"] = "0.9999999999"
    return "ADV coverage 1 cent under 100%", r, "FAIL", ["RMFSTABLE-RES-001"]

def adv_stale_supply():
    r = base_record()
    for e in r["evidence"]:
        if e["evidence_id"] == "EVD-003":
            e["issued_at"] = "2025-12-30T00:00:00Z"   # 48h before verification point
    return "ADV supply evidence 48h old (§14.4 limit 24h)", r, "FAIL", ["RMFSTABLE-EVD-003"]

def adv_stale_attestation():
    r = base_record()
    for e in r["evidence"]:
        if e["evidence_id"] == "EVD-011":
            e["issued_at"] = "2025-11-01T00:00:00Z"   # ~61 days
    return "ADV attestation 61 days old (§14.4 limit 35d)", r, "FAIL", ["RMFSTABLE-EVD-003"]

def adv_validity_too_long():
    r = base_record()
    r["expires_at"] = "2026-03-15T00:00:00Z"          # ~73 days
    return "ADV result validity 73 days (§16.5 max 35d)", r, "FAIL", ["RMFSTABLE-VER-002"]

def adv_undisclosed_rehypo():
    r = base_record()
    r["subject"]["custodians"][0]["rehypothecation_allowed"] = True
    r["subject"]["custodians"][0]["rehypothecation_disclosed"] = False
    return "ADV undisclosed rehypothecation", r, "FAIL", ["RMFSTABLE-CUS-002"]

def adv_single_key():
    r = base_record()
    r["subject"]["contract_permissions"][0]["control_mechanism"] = "single_key"
    return "ADV mint controlled by single key", r, "FAIL", ["RMFSTABLE-SEC-001"]

def adv_pledged_reserve():
    r = base_record()
    r["subject"]["reserve_assets"][0]["pledge"] = True
    return "ADV reserve asset pledged", r, "FAIL", ["RMFSTABLE-RES-004"]

def adv_attestation_no_liabilities():
    r = base_record()
    r["subject"]["attestations"][0]["scope"] = ["reserves"]
    return "ADV attestation scope omits liabilities", r, "FAIL", ["RMFSTABLE-ATT-002"]

def adv_reserve_recompute_mismatch():
    r = base_record()
    r["subject"]["reserve_assets"][0]["verified_value"]["amount"] = "90000000.00"
    return "ADV asset sum != declared reserve total", r, "FAIL", ["RMFSTABLE-VAL-001"]

def adv_float_amount():
    r = base_record()
    r["subject"]["total_supply"]["amount"] = 100000000.00   # float, §18.3 prohibits
    return "ADV float amount used (§18.3 prohibits)", r, "REJECT", []

def adv_attestor_controlled():
    r = base_record()
    r["subject"]["attestations"][0]["controlled_by_issuer"] = True
    return "ADV attestation firm controlled by issuer", r, "FAIL", ["RMFSTABLE-ATT-003"]

def adv_attestor_independence_undisclosed():
    r = base_record()
    r["subject"]["attestations"][0].pop("independence_disclosed")
    return "ADV attestor independence not disclosed", r, "DEFICIENT", ["RMFSTABLE-ATT-003"]

def adv_result_outlives_evidence():
    r = base_record()
    # supply evidence expires 24h after issue; declare a 30-day result validity
    r["expires_at"] = "2026-01-31T00:00:00Z"
    return "ADV result outlives its supply evidence (§16.5)", r, "FAIL", ["RMFSTABLE-VER-002"]

ADVERSARIAL = [adv_attestor_controlled, adv_attestor_independence_undisclosed,
               adv_result_outlives_evidence, adv_coverage_exact_100, adv_coverage_hair_under, adv_stale_supply,
               adv_stale_attestation, adv_validity_too_long, adv_undisclosed_rehypo,
               adv_single_key, adv_pledged_reserve, adv_attestation_no_liabilities,
               adv_reserve_recompute_mismatch, adv_float_amount]



def main():
    if len(sys.argv) > 1:
        rec = json.load(open(sys.argv[1], encoding="utf-8"))
        overall, v = verify(rec)
        print(f"RESULT: {overall}")
        if v.failures:
            print("Failure codes:", ", ".join(v.failures))
        for n in v.notes:
            print("  note:", n)
        sys.exit(0 if overall in ("PASS", "CONDITIONAL") else 1)

    print("=" * 72)
    print("RM-S-STABLE-001 — running the §21 test cases through a reference verifier")
    print("=" * 72)
    all_ok = True
    for fn in CASES:
        name, rec, expect, expect_codes = fn()
        overall, v = verify(rec)
        ok = (overall == expect)
        codes_ok = all(c in v.failures for c in expect_codes)
        status = "PASS" if (ok and codes_ok) else "MISMATCH"
        if not (ok and codes_ok):
            all_ok = False
        print(f"\n[{status}] {name}")
        print(f"   expected : {expect}" + (f"  {expect_codes}" if expect_codes else ""))
        print(f"   actual   : {overall}" + (f"  {v.failures}" if v.failures else ""))
        if v.unmet_should:
            print(f"   unmet SHOULD: {v.unmet_should}")
        for n in v.notes:
            print(f"   note: {n}")
        if not codes_ok:
            missing = [c for c in expect_codes if c not in v.failures]
            print(f"   >>> expected failure codes not raised: {missing}")
    print("\n" + "=" * 72)
    print("ADVERSARIAL TESTS — beyond §21")
    print("=" * 72)
    for fn in ADVERSARIAL:
        name, rec, expect, expect_codes = fn()
        try:
            overall, v = verify(rec)
        except TypeError as e:
            overall, v = "REJECT", None
            print(f"\n[OK] {name}\n   rejected at parse: {e}")
            continue
        ok = (overall == expect)
        codes_ok = all(c in v.failures for c in expect_codes)
        mark = "OK" if (ok and codes_ok) else "GAP"
        print(f"\n[{mark}] {name}")
        print(f"   expected : {expect}" + (f"  {expect_codes}" if expect_codes else ""))
        print(f"   actual   : {overall}" + (f"  {v.failures}" if v.failures else ""))
        for n in v.notes:
            print(f"   note: {n}")
        if expect == "FAIL" and not expect_codes and overall == "FAIL":
            print(f"   >>> failed, but which code? raised: {v.failures}")

    print("\n" + "=" * 72)
    print("OVERALL (§21):", "all test cases reproduce the standard's stated results"
          if all_ok else "MISMATCH — the standard and its test cases disagree")
    print("=" * 72)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
