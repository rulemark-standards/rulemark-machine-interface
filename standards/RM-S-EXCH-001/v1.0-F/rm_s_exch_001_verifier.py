#!/usr/bin/env python3
"""RM-S-EXCH-001 Reference Verifier — implements §15.1 (31 steps) and §16."""
import sys
from decimal import Decimal, getcontext
from datetime import datetime, timedelta
getcontext().prec = 60

REQUIRED = ["EVD-001","EVD-002","EVD-003","EVD-004","EVD-005","EVD-006","EVD-007",
            "EVD-008","EVD-009","EVD-010","EVD-015","EVD-016","EVD-017"]
MAX_AGE_H = {"EVD-004":24, "EVD-005":24, "EVD-006":24, "EVD-007":24,
             "EVD-011":35*24, "EVD-013":35*24}

class V:
    def __init__(self):
        self.log=[]; self.failures=[]; self.gap=set(); self.viol=set()
        self.unmet=[]; self.notes=[]
    def step(self,n,d,ok,code=None,det="",gap=False):
        self.log.append((n,d,ok,det))
        if not ok and code:
            if code not in self.failures: self.failures.append(code)
            (self.gap if gap else self.viol).add(code)
        return ok
    def should(self,n): self.unmet.append(n)

def ts(v):
    try: return datetime.fromisoformat(str(v).replace("Z","+00:00"))
    except Exception: return None
def q(v):
    if isinstance(v,float): raise TypeError("float quantity; §18.2 prohibits")
    return Decimal(str(v)) if v is not None else None

def verify(rec):
    v=V(); cs=rec.get("conformity_subject",{}); ents=rec.get("in_scope_entities",[])
    assets=rec.get("assets",[]); addrs=rec.get("reserve_addresses",[])
    lc=rec.get("liability_commitment",{}); seg=rec.get("segregation",{})
    wd=rec.get("withdrawals",{}); ops=rec.get("privileged_operations",[])
    ev={e.get("evidence_id"):e for e in rec.get("evidence",[])}
    vp=ts(rec.get("verification_point"))
    public_only = rec.get("assessment_basis")=="PUBLIC_INFORMATION_ONLY"
    def has(e): return e in ev

    st=rec.get("standard",{})
    v.step(1,"standard identity",st.get("standard_id")=="RM-S-EXCH-001"
           and bool(st.get("standard_version")),"RMSEXCH-ID-001")
    v.step(2,"subject identity",
           all(cs.get(f) for f in ("platform_name","canonical_domain"))
           and "licence_number" in cs and bool(cs.get("reserve_address_set_sha256")),
           "RMSEXCH-ID-001",gap=True)
    oe=rec.get("operating_entity",{})
    v.step(2,"operating entity",
           all(oe.get(f) for f in ("legal_name","jurisdiction","registration_number")),
           "RMSEXCH-ID-002",gap=True)

    # 3. in-scope completeness (§6.1, §6.2)
    known=set(rec.get("_entities_holding_assets",[e.get("entity_id") for e in ents]))
    listed={e.get("entity_id") for e in ents}
    v.step(3,"in-scope entity list complete",known<=listed,"RMSEXCH-SCOPE-001",
           f"omitted={sorted(known-listed)}")
    v.step(3,"completeness declaration + group evidence",
           rec.get("completeness_declaration_signed") is True and has("EVD-002"),
           "RMSEXCH-SCOPE-002",gap=not has("EVD-002"))

    # 4. verification point
    v.step(4,"verification point (single UTC value)",vp is not None,"RMSEXCH-ID-001")

    # 5-6. assets and addresses
    v.step(5,"in-scope asset list",len(assets)>=1,"RMSEXCH-ID-001",gap=True)
    v.step(6,"every address attributed to an in-scope entity",
           all(a.get("holding_entity_id") in listed for a in addrs) and len(addrs)>=1,
           "RMSEXCH-RES-001",gap=(len(addrs)==0))

    # 7. proof of control (§7.2)
    bad=[]
    for a in addrs:
        m=a.get("control_proof_method"); ref=a.get("control_proof_reference")
        pt=ts(a.get("control_proof_time"))
        ok = m in ("SIGNATURE","SPEND") and bool(ref) and pt is not None
        if ok and vp and abs((vp-pt).total_seconds())>24*3600: ok=False
        if not ok: bad.append(a.get("address"))
    v.step(7,"proof of control bound to verification point",not bad,
           "RMSEXCH-RES-002",f"unproven={bad}",gap=(len(addrs)>0 and all(
               not a.get("control_proof_method") for a in addrs)))

    # 8. exclusivity (§7.3)
    seen=[a.get("address") for a in addrs]
    dup=[x for x in set(seen) if seen.count(x)>1]
    shared=[a.get("address") for a in addrs if a.get("shared_outside_scope") is True]
    v.step(8,"no double counting / undisclosed sharing",not dup and not shared,
           "RMSEXCH-RES-003",f"dup={dup} shared={shared}")

    # 9. borrowed (§7.4)
    und_borrow=[b for b in rec.get("borrowed_assets",[]) if b.get("disclosed") is not True]
    counted_borrow=[b for b in rec.get("borrowed_assets",[]) if b.get("counted_as_reserve") is True]
    v.step(9,"borrowed assets disclosed and excluded",
           not und_borrow and not counted_borrow,"RMSEXCH-RES-004")

    # 10. deployed (§6.4)
    und_dep=[d for d in rec.get("deployed_assets",[]) if d.get("disclosed") is not True]
    v.step(10,"deployed customer assets disclosed",not und_dep,"RMSEXCH-SCOPE-004")

    # 11. third-party depository (§6.3)
    if rec.get("third_party_depository_used") is True:
        v.step(11,"depository confirmation issued directly to verifier",
               has("EVD-011") and ev["EVD-011"].get("issued_directly_to_verifier") is True,
               "RMSEXCH-SCOPE-003",gap=not has("EVD-011"))

    # 12. reserve recomputation (§7.5)
    for a in assets:
        declared=q(a.get("reserve_balance"))
        chain=sum((q(x.get("balance")) or Decimal(0)) for x in addrs
                  if x.get("asset")==a.get("asset"))
        if declared is not None and chain != declared:
            v.step(12,f"reserve recomputed for {a.get('asset')}",False,
                   "RMSEXCH-RES-005",f"declared={declared} chain={chain}")

    # 13-16. liabilities
    v.step(13,"liability categories complete",
           rec.get("liability_categories_complete") is True,"RMSEXCH-LIA-001",gap=True)
    v.step(14,"liability commitment published and total derivable",
           bool(lc.get("commitment_root")) and lc.get("total_derivable") is True,
           "RMSEXCH-LIA-002",gap=not bool(lc.get("commitment_root")))
    v.step(15,"customer inclusion proof available and method published",
           lc.get("inclusion_proof_available") is True and bool(lc.get("verification_method_uri")),
           "RMSEXCH-LIA-003",gap=True)
    v.step(16,"no total-reducing record, no netting of negatives",
           lc.get("total_reducible") is False and lc.get("negatives_netted") is False,
           "RMSEXCH-LIA-004")

    # 17. per-asset coverage (§9.1, §9.2, §9.3)
    for a in assets:
        r=q(a.get("reserve_balance")); l=q(a.get("customer_liability"))
        name=a.get("asset")
        if l is None or l<=0: continue
        if r is None or r==0:
            v.step(17,f"{name}: liabilities with no reserve",False,"RMSEXCH-COV-002")
            continue
        cov=r/l
        if cov < Decimal(1):
            v.step(17,f"{name}: coverage {cov:.6f} below 100%",False,"RMSEXCH-COV-001")
        dec=a.get("coverage_ratio")
        if dec is not None:
            recomputed=cov.quantize(Decimal("0.000001"), rounding="ROUND_DOWN")
            if Decimal(str(dec))!=recomputed:
                v.step(17,f"{name}: declared ratio matches recomputation",False,
                       "RMSEXCH-RES-005",f"declared={dec} recomputed={recomputed}")

    # 18. cross-asset substitution (§9.4)
    v.step(18,"no cross-asset substitution claimed",
           rec.get("cross_asset_substitution_claimed") is not True,"RMSEXCH-COV-003")

    # 19-20. segregation
    v.step(19,"legal segregation disclosed",bool(seg.get("legal_basis")),
           "RMSEXCH-SEG-001",gap=True)
    v.step(19,"operational segregation disclosed",
           seg.get("separate_addresses") is not None
           and (seg.get("separate_addresses") is True or bool(seg.get("commingling_accounting"))),
           "RMSEXCH-SEG-002",gap=True)
    if seg.get("proprietary_use") is None:
        # disclosure absent -> cannot verify (curable gap)
        v.step(19,"proprietary use disclosure present",False,"RMSEXCH-SEG-003",gap=True)
    elif seg.get("proprietary_use") is True and seg.get("proprietary_use_disclosed") is not True:
        # use occurs and is undisclosed -> affirmative violation
        v.step(19,"proprietary use disclosed",False,"RMSEXCH-SEG-003")
    v.step(20,"insolvency position disclosed",bool(seg.get("insolvency_position")),
           "RMSEXCH-SEG-004",gap=True)

    # 21-22. withdrawals
    v.step(21,"max processing time quantified per asset",
           all(a.get("max_withdrawal_processing_time") for a in assets),
           "RMSEXCH-WDR-001",gap=True)
    v.step(21,"30-day withdrawal performance record",
           bool(wd.get("performance_30d")),"RMSEXCH-WDR-002",gap=True)
    susp=[s for s in wd.get("suspensions",[]) if s.get("in_effect_at_vp") is True]
    undis=[s for s in susp if s.get("disclosed") is not True]
    v.step(22,"withdrawal suspensions disclosed",not undis,"RMSEXCH-WDR-003")
    if susp: v.notes.append(f"suspension in effect at verification point: {[s.get('asset') for s in susp]}")
    v.step(22,"no undisclosed selective processing",
           wd.get("undisclosed_selective_processing") is not True,"RMSEXCH-WDR-004")

    # 23-24. control
    v.step(23,"privileged operations disclosed",
           len(ops)>=1 and all(o.get("role") and o.get("control_mechanism") for o in ops),
           "RMSEXCH-OPS-001",gap=(len(ops)==0))
    single=[o for o in ops if str(o.get("control_mechanism","")).upper() in ("SINGLE_KEY","","NONE")]
    v.step(23,"no single undisclosed key moves customer assets",not single,"RMSEXCH-OPS-002")
    v.step(24,"beneficial ownership disclosed or lawfully withheld",
           bool(oe.get("ubo_disclosure")) or bool(oe.get("ubo_withholding_basis")),
           "RMSEXCH-OPS-003",gap=True)
    rp=[r for r in rec.get("related_party_exposure",[]) if r.get("disclosed") is not True]
    v.step(24,"related-party exposure disclosed",not rp,"RMSEXCH-OPS-004")

    # 25. material events
    for e in rec.get("material_events",[]):
        d=ts(e.get("detected_at")); p=ts(e.get("published_at")); r=ts(e.get("recorded_at"))
        if (d and r and (r-d)>timedelta(hours=24)) or (d and p and (p-d)>timedelta(hours=24)):
            v.step(25,"material event within 24h",False,"RMSEXCH-EVT-001")

    # 26. evidence
    req=list(REQUIRED)
    if rec.get("third_party_depository_used") is True: req.append("EVD-011")
    if rec.get("deployed_assets"): req.append("EVD-012")
    if rec.get("material_events"): req.append("EVD-014")
    missing=[e for e in req if e not in ev]
    v.step(26,"mandatory evidence present",not missing,"RMSEXCH-EVD-001",
           f"missing={missing}",gap=True)
    v.step(26,"evidence metadata complete",
           all(all(e.get(k) for k in ("provider_id","generated_at","acquired_at","uri","sha256"))
               for e in ev.values()),"RMSEXCH-EVD-001",gap=True)
    stale=[]
    if vp:
        for eid,h in MAX_AGE_H.items():
            e=ev.get(eid)
            if not e: continue
            g=ts(e.get("generated_at"))
            if g and (vp-g).total_seconds()>h*3600:
                stale.append(f"{eid}:{(vp-g).total_seconds()/3600:.0f}h>{h}h")
    v.step(26,"evidence within maximum age",not stale,"RMSEXCH-EVD-003",
           f"stale={stale}",gap=True)
    indep=[eid for eid in ("EVD-011","EVD-013") if eid in ev
           and ev[eid].get("provider_independence_disclosed") is not True]
    ctrl=[eid for eid in ("EVD-011","EVD-013") if eid in ev
          and ev[eid].get("provider_controlled_by_scope_entity") is True]
    v.step(26,"provider independence disclosed",not indep,"RMSEXCH-EVD-004",gap=True)
    v.step(26,"provider independent of in-scope entities",not ctrl,"RMSEXCH-EVD-004")

    # 27. human/machine
    hd=rec.get("human_disclosure",{}); conflict=False
    for a in assets:
        h=hd.get(a.get("asset"))
        if h and str(h)!=str(a.get("coverage_ratio")):
            conflict=True; v.notes.append(f"human/machine coverage mismatch on {a.get('asset')}")
    v.step(27,"human / machine consistency",not conflict,"RMSEXCH-DAT-001")

    # 28. digests
    v.step(28,"digests well-formed",
           all(isinstance(e.get("sha256"),str) and len(e["sha256"])==64 for e in ev.values()),
           "RMSEXCH-EVD-002")

    # 29-30. traceability and validity
    rr=rec.get("requirement_results",[])
    v.step(29,"per-requirement traceability",
           len(rr)>=1 and all(r.get("requirement_id") and r.get("result")
               and (r["result"]!="FAIL" or r.get("failure_code")) for r in rr),
           "RMSEXCH-VER-001",gap=True)
    ea=ts(rec.get("result_expires_at"))
    if vp and ea:
        if (ea-vp).days>35:
            v.step(30,"validity within 35 days",False,"RMSEXCH-VER-002",f"{(ea-vp).days}d")
        earliest=None
        for eid,h in MAX_AGE_H.items():
            e=ev.get(eid)
            if not e: continue
            g=ts(e.get("generated_at"))
            if g:
                x=g+timedelta(hours=h)
                earliest = x if earliest is None or x<earliest else earliest
        if earliest and ea>earliest:
            v.step(30,"expiry within earliest evidence expiry",False,"RMSEXCH-VER-002",
                   f"{ea} > {earliest}")

    # 31. signature
    sg=rec.get("signature",{})
    v.step(31,"verification record signed",
           all(sg.get(k) for k in ("algorithm","key_id","signed_at","public_key_uri","signature_value")),
           "RMSEXCH-SIG-001",gap=True)

    # SHOULD
    if rec.get("independent_liability_attestation") is False: v.should("§8.5 independent liability attestation")
    if rec.get("test_withdrawal_performed") is False: v.should("§11.5 test withdrawal")

    if public_only: v.viol -= v.gap
    viol=[c for c in v.failures if c in v.viol]
    gaps=[c for c in v.failures if c in v.gap and c not in v.viol]
    overall = "FAIL" if viol else ("DEFICIENT" if gaps else ("CONDITIONAL" if v.unmet else "PASS"))
    v.violations, v.gaps = viol, gaps
    return overall, v


# ---------------------------------------------------------------- test cases
H="a"*64; U="2026-01-01T00:00:00Z"

def base():
    return {
      "record_id":"r1","schema_version":"1.0","verification_point":U,
      "result_expires_at":"2026-01-02T00:00:00Z","digest_algorithm":"sha-256",
      "standard":{"standard_id":"RM-S-EXCH-001","standard_version":"v1.0-F"},
      "conformity_subject":{"platform_name":"Example Exchange","canonical_domain":"ex.example",
        "licence_number":None,"reserve_address_set_sha256":H},
      "operating_entity":{"legal_name":"Example Exchange Ltd","jurisdiction":"SG",
        "registration_number":"2020-1","ubo_disclosure":"disclosed"},
      "in_scope_entities":[{"entity_id":"E1"},{"entity_id":"E2"}],
      "_entities_holding_assets":["E1","E2"],
      "completeness_declaration_signed":True,
      "assets":[
        {"asset":"BTC","reserve_balance":"1234500000000","customer_liability":"1230000000000",
         "unit":"satoshi","decimals":8,"coverage_ratio":"1.003658",
         "max_withdrawal_processing_time":"24 hours"},
        {"asset":"USDT","reserve_balance":"5056000000","customer_liability":"5000000000",
         "unit":"micro","decimals":6,"coverage_ratio":"1.011200",
         "max_withdrawal_processing_time":"12 hours"}],
      "reserve_addresses":[
        {"network":"bitcoin","address":"bc1a","asset":"BTC","holding_entity_id":"E1",
         "balance":"1234500000000","control_proof_method":"SIGNATURE",
         "control_proof_reference":"sig1","control_proof_time":U},
        {"network":"ethereum","address":"0x1","asset":"USDT","holding_entity_id":"E2",
         "balance":"5056000000","control_proof_method":"SPEND",
         "control_proof_reference":"0xtx","control_proof_time":U}],
      "borrowed_assets":[],"deployed_assets":[],"third_party_depository_used":False,
      "liability_categories_complete":True,
      "liability_commitment":{"commitment_root":H,"total_derivable":True,
        "inclusion_proof_available":True,"verification_method_uri":"https://ex.example/por",
        "total_reducible":False,"negatives_netted":False},
      "segregation":{"legal_basis":"trust structure","separate_addresses":True,
        "proprietary_use":False,"insolvency_position":"customer assets excluded from estate"},
      "withdrawals":{"performance_30d":{"BTC":{"requests":100,"within":99,"exceeded":1,"refused":0}},
        "suspensions":[],"undisclosed_selective_processing":False},
      "privileged_operations":[{"role":"withdrawal_signer","control_mechanism":"MULTISIG"},
                               {"role":"balance_adjust","control_mechanism":"DUAL_AUTH"}],
      "related_party_exposure":[],"material_events":[],
      "evidence":[{"evidence_id":e,"evidence_type":"x","provider_id":"p",
        "provider_independence_disclosed":True,"provider_controlled_by_scope_entity":False,
        "generated_at":U,"acquired_at":U,"uri":"https://ex.example/e","sha256":H}
        for e in REQUIRED],
      "requirement_results":[{"requirement_id":"REQ-001","applicability":"APPLICABLE","result":"PASS"}],
      "human_disclosure":{"BTC":"1.003658","USDT":"1.011200"},
      "overall_result":{"verification_result":"PASS"},
      "verifier":{"verifier_id":"v1"},
      "signature":{"algorithm":"ES256","key_id":"k1","signed_at":U,
        "public_key_uri":"https://ex.example/jwks","signature_value":"sig=="},
      "independent_liability_attestation":True,"test_withdrawal_performed":True}

def c1(): return "21.1 PASS", base(), "PASS", []
def c2():
    r=base(); r["_entities_holding_assets"].append("E3")
    return "21.2 undisclosed affiliate", r, "FAIL", ["RMSEXCH-SCOPE-001"]
def c3():
    r=base(); r["reserve_addresses"][0]["control_proof_method"]=None
    r["reserve_addresses"][0]["control_proof_reference"]=None
    return "21.3 balance without control", r, "FAIL", ["RMSEXCH-RES-002"]
def c4():
    r=base()
    r["assets"][1]["reserve_balance"]="3050000000"; r["assets"][1]["coverage_ratio"]="0.610000"
    r["reserve_addresses"][1]["balance"]="3050000000"
    r["assets"][0]["reserve_balance"]="1869600000000"; r["assets"][0]["coverage_ratio"]="1.520000"
    r["reserve_addresses"][0]["balance"]="1869600000000"
    r["human_disclosure"]={"BTC":"1.520000","USDT":"0.610000"}
    r["cross_asset_substitution_claimed"]=True
    return "21.4 cross-asset concealment", r, "FAIL", ["RMSEXCH-COV-001","RMSEXCH-COV-003"]
def c5():
    r=base(); r["liability_commitment"]={"commitment_root":"","total_derivable":False,
      "inclusion_proof_available":False,"verification_method_uri":"",
      "total_reducible":False,"negatives_netted":False}
    return "21.5 no liability commitment", r, "DEFICIENT", ["RMSEXCH-LIA-002","RMSEXCH-LIA-003"]
def c6():
    r=base()
    for e in r["evidence"]:
        if e["evidence_id"]=="EVD-005": e["generated_at"]="2025-12-28T00:00:00Z"
    return "21.6 stale reserve snapshot", r, "FAIL", ["RMSEXCH-EVD-003"]
def c7():
    r=base(); r["independent_liability_attestation"]=False
    return "21.7 SHOULD unmet", r, "CONDITIONAL", []
def c8():
    r=base(); r["assessment_basis"]="PUBLIC_INFORMATION_ONLY"
    for a in r["reserve_addresses"]:
        a["control_proof_method"]=None; a["control_proof_reference"]=None; a["control_proof_time"]=None
    r["liability_commitment"]={"commitment_root":"","total_derivable":False,
      "inclusion_proof_available":False,"verification_method_uri":"",
      "total_reducible":False,"negatives_netted":False}
    r["segregation"]={"legal_basis":"","separate_addresses":None,"proprietary_use":None,
      "insolvency_position":""}
    r["withdrawals"]={"performance_30d":None,"suspensions":[],
      "undisclosed_selective_processing":None}
    r["privileged_operations"]=[]
    r["evidence"]=[e for e in r["evidence"] if e["evidence_id"] in
                   ("EVD-001","EVD-003","EVD-005","EVD-016")]
    return "21.8 public information only", r, "DEFICIENT", ["RMSEXCH-EVD-001"]

CASES=[c1,c2,c3,c4,c5,c6,c7,c8]

def a_dup():
    r=base(); r["reserve_addresses"].append(dict(r["reserve_addresses"][0]))
    r["assets"][0]["reserve_balance"]="2469000000000"
    r["assets"][0]["coverage_ratio"]="2.007317"; r["human_disclosure"]["BTC"]="2.007317"
    return "ADV same address counted twice", r, "FAIL", ["RMSEXCH-RES-003"]
def a_borrow():
    r=base(); r["borrowed_assets"]=[{"asset":"BTC","quantity":"1","disclosed":False,
                                     "counted_as_reserve":True}]
    return "ADV undisclosed borrowed assets", r, "FAIL", ["RMSEXCH-RES-004"]
def a_deployed():
    r=base(); r["deployed_assets"]=[{"asset":"USDT","quantity":"1","disclosed":False}]
    return "ADV undisclosed staking of customer assets", r, "FAIL", ["RMSEXCH-SCOPE-004"]
def a_no_reserve():
    r=base(); r["assets"].append({"asset":"ETH","reserve_balance":"0",
      "customer_liability":"1000000","unit":"wei","decimals":18,"coverage_ratio":"0",
      "max_withdrawal_processing_time":"24 hours"})
    r["human_disclosure"]["ETH"]="0"
    return "ADV liabilities with no reserve", r, "FAIL", ["RMSEXCH-COV-002"]
def a_hair_under():
    r=base(); r["assets"][0]["reserve_balance"]="1229999999999"
    r["reserve_addresses"][0]["balance"]="1229999999999"
    r["assets"][0]["coverage_ratio"]="0.999999"; r["human_disclosure"]["BTC"]="0.999999"
    return "ADV coverage one satoshi under 100%", r, "FAIL", ["RMSEXCH-COV-001"]
def a_exact_100():
    r=base(); r["assets"][0]["reserve_balance"]="1230000000000"
    r["reserve_addresses"][0]["balance"]="1230000000000"
    r["assets"][0]["coverage_ratio"]="1.000000"; r["human_disclosure"]["BTC"]="1.000000"
    return "ADV coverage exactly 100%", r, "PASS", []
def a_suspension():
    r=base(); r["withdrawals"]["suspensions"]=[{"asset":"USDT","in_effect_at_vp":True,
                                                "disclosed":False}]
    return "ADV undisclosed withdrawal suspension", r, "FAIL", ["RMSEXCH-WDR-003"]
def a_single_key():
    r=base(); r["privileged_operations"][0]["control_mechanism"]="SINGLE_KEY"
    return "ADV single key can move customer assets", r, "FAIL", ["RMSEXCH-OPS-002"]
def a_netting():
    r=base(); r["liability_commitment"]["negatives_netted"]=True
    return "ADV negative balances netted", r, "FAIL", ["RMSEXCH-LIA-004"]
def a_proprietary():
    r=base(); r["segregation"]["proprietary_use"]=True
    r["segregation"]["proprietary_use_disclosed"]=False
    return "ADV undisclosed proprietary use", r, "FAIL", ["RMSEXCH-SEG-003"]
def a_attestor_controlled():
    r=base(); r["evidence"].append({"evidence_id":"EVD-013","evidence_type":"x",
      "provider_id":"affiliate","provider_independence_disclosed":True,
      "provider_controlled_by_scope_entity":True,"generated_at":U,"acquired_at":U,
      "uri":"https://ex.example/e","sha256":H})
    return "ADV attestation firm controlled by the group", r, "FAIL", ["RMSEXCH-EVD-004"]
def a_validity_long():
    r=base(); r["result_expires_at"]="2026-03-01T00:00:00Z"
    return "ADV validity 59 days (max 35, and evidence bound)", r, "FAIL", ["RMSEXCH-VER-002"]
def a_reserve_mismatch():
    r=base(); r["assets"][0]["reserve_balance"]="9999999999999"
    return "ADV declared reserve != sum of addresses", r, "FAIL", ["RMSEXCH-RES-005"]
def a_float():
    r=base(); r["assets"][0]["reserve_balance"]=1234.5
    return "ADV float quantity (§18.2 prohibits)", r, "REJECT", []
def a_event_late():
    r=base(); r["material_events"]=[{"event_id":"e1","event_type":"COVERAGE_BREACH",
      "detected_at":"2026-01-01T00:00:00Z","recorded_at":"2026-01-01T06:00:00Z",
      "published_at":"2026-01-03T00:00:00Z"}]
    r["evidence"].append({"evidence_id":"EVD-014","evidence_type":"x","provider_id":"p",
      "provider_independence_disclosed":True,"provider_controlled_by_scope_entity":False,
      "generated_at":U,"acquired_at":U,"uri":"https://ex.example/e","sha256":H})
    return "ADV material event published 48h late", r, "FAIL", ["RMSEXCH-EVT-001"]

def a_ratio_mismatch():
    r=base(); r["assets"][0]["coverage_ratio"]="1.500000"
    r["human_disclosure"]["BTC"]="1.500000"
    return "ADV declared coverage ratio does not match recomputation", r, "FAIL", ["RMSEXCH-RES-005"]

ADV=[a_ratio_mismatch,a_dup,a_borrow,a_deployed,a_no_reserve,a_hair_under,a_exact_100,a_suspension,
     a_single_key,a_netting,a_proprietary,a_attestor_controlled,a_validity_long,
     a_reserve_mismatch,a_float,a_event_late]

def main():
    print("="*74); print("RM-S-EXCH-001 — §21 test cases"); print("="*74)
    allok=True
    for fn in CASES:
        n,r,exp,codes=fn(); o,v=verify(r)
        ok=o==exp and all(c in v.failures for c in codes); allok&=ok
        print(f"\n[{'PASS' if ok else 'MISMATCH'}] {n}")
        print(f"   expected : {exp}"+(f"  {codes}" if codes else ""))
        print(f"   actual   : {o}"+(f"  {v.failures}" if v.failures else ""))
        if not ok:
            m=[c for c in codes if c not in v.failures]
            if m: print(f"   >>> not raised: {m}")
    print("\n"+"="*74); print("ADVERSARIAL"); print("="*74)
    for fn in ADV:
        n,r,exp,codes=fn()
        try: o,v=verify(r)
        except TypeError as e:
            print(f"\n[OK] {n}\n   rejected at parse: {e}"); continue
        ok=o==exp and all(c in v.failures for c in codes)
        print(f"\n[{'OK' if ok else 'GAP'}] {n}")
        print(f"   expected : {exp}"+(f"  {codes}" if codes else ""))
        print(f"   actual   : {o}"+(f"  {v.failures}" if v.failures else ""))
    print("\n"+"="*74)
    print("§21:", "all test cases reproduce the standard's stated results" if allok else "MISMATCH")
    print("="*74); sys.exit(0 if allok else 1)

if __name__=="__main__": main()
