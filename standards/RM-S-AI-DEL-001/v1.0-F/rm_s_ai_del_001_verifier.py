#!/usr/bin/env python3
"""RM-S-AI-DEL-001 Reference Verifier — implements §15.1 (34 steps) and §16."""
import sys, hashlib
from decimal import Decimal, getcontext
from datetime import datetime, timedelta
getcontext().prec = 40

REQUIRED = ["EVD-001","EVD-002","EVD-003","EVD-004","EVD-005","EVD-006","EVD-007",
            "EVD-008","EVD-009","EVD-010","EVD-011","EVD-016","EVD-017","EVD-018","EVD-019"]

class V:
    def __init__(self):
        self.log=[];self.failures=[];self.gap=set();self.viol=set();self.unmet=[];self.notes=[]
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
    if isinstance(v,float): raise TypeError("float quantity; §18.3 prohibits")
    return Decimal(str(v)) if v is not None else None

def in_force(cred, at, revocations):
    """A credential is in force at time `at`."""
    ef, ex = ts(cred.get("effective_at")), ts(cred.get("expires_at"))
    if not ef or not ex or not at: return False
    if not (ef <= at <= ex): return False
    rev = revocations.get(cred.get("authorization_id"))
    if rev:
        rt = ts(rev.get("effective_time")); prop = rev.get("propagation_seconds", 0)
        if rt and at >= rt + timedelta(seconds=prop): return False
    return True

def scope_test(action, scope):
    """§7.1 deterministic scope test -> True/False"""
    for e in scope.get("action_types", []):
        if e.get("action_type") != action.get("action_type"): continue
        cp = e.get("counterparties", {})
        mode = cp.get("mode")
        if mode == "ENUMERATED":
            if action.get("counterparty") not in cp.get("values", []): continue
        elif mode == "RULE":
            if not action.get("_rule_match"): continue
        elif mode != "UNRESTRICTED":
            continue
        qy = e.get("quantity")
        if qy:
            amt = q(action.get("quantity"))
            mx = q(qy.get("per_action_max"))
            if amt is not None and mx is not None and amt > mx:
                return False, e, "PER_ACTION"
        return True, e, None
    return False, None, "NO_MATCH"

def verify(rec):
    v=V(); cs=rec.get("conformity_subject",{}); ag=rec.get("agent",{})
    cred=rec.get("authorization",{}); scope=rec.get("authority_scope",{})
    chain=rec.get("delegation_chain",[]); rv=rec.get("revocation",{})
    alog=rec.get("action_log",{}); actions=rec.get("actions",[])
    hcs={h.get("action_entry_id"):h for h in rec.get("human_checkpoints",[])}
    ev={e.get("evidence_id"):e for e in rec.get("evidence",[])}
    vp=ts(rec.get("verification_point")); ws=ts(rec.get("assessment_window_start"))
    public_only = rec.get("assessment_basis")=="PUBLIC_INFORMATION_ONLY"
    revs={rv.get("authorization_id"):rv} if rv.get("revoked") else {}
    def has(e): return e in ev

    st=rec.get("standard",{})
    v.step(1,"standard identity",st.get("standard_id")=="RM-S-AI-DEL-001"
           and bool(st.get("standard_version")),"RMSAIDEL-ID-001")

    # 2. delegator / operator separation (§1.5, §4.3)
    dg=rec.get("delegator",{}); op=rec.get("operator",{})
    v.step(2,"delegator and operator identified separately",
           bool(dg.get("delegator_id")) and bool(op.get("operator_id"))
           and isinstance(cs.get("delegator_is_operator"),bool),
           "RMSAIDEL-ID-002",gap=True)

    # 3. agent instance identity (§12.1)
    v.step(3,"agent instance identifier unique and not reused",
           bool(ag.get("agent_instance_id")) and ag.get("identifier_reused") is not True,
           "RMSAIDEL-IDN-001")
    v.step(3,"agent identity fields present",
           all(ag.get(f) for f in ("agent_version","config_sha256")),
           "RMSAIDEL-ID-001",gap=True)

    # 4. verification point and assessment window (§11.6)
    v.step(4,"verification point present",vp is not None,"RMSAIDEL-ID-001")
    if vp and ws:
        days=(vp-ws).days
        ef=ts(cred.get("effective_at"))
        required = 90 if not ef else min(90,(vp-ef).days)
        if days < required:
            v.step(4,"assessment window covers required period",False,
                   "RMSAIDEL-LOG-006",f"{days}d < {required}d")

    # 5. credential existence and content (§6.1, §6.2)
    if not cred.get("authorization_id"):
        v.step(5,"authorization credential in force",False,"RMSAIDEL-AUT-001",gap=True)
    else:
        need=["authorization_id","delegator_id","agent_instance_id","agent_config_sha256",
              "issued_at","effective_at","expires_at","signature"]
        miss=[f for f in need if not cred.get(f)]
        v.step(5,"credential required fields",not miss,"RMSAIDEL-AUT-002",
               f"missing={miss}",gap=True)
        if vp and not in_force(cred,vp,revs):
            v.step(5,"credential in force at verification point",False,"RMSAIDEL-AUT-001")

    # 6. signature (§6.3)
    v.step(6,"delegator signature verifiable and covers scope",
           cred.get("signature_verified") is True and cred.get("signature_covers_scope") is True
           and has("EVD-004"),"RMSAIDEL-AUT-003",gap=not has("EVD-004"))

    # 7. validity period (§6.4)
    ef,ex=ts(cred.get("effective_at")),ts(cred.get("expires_at"))
    if not ex:
        v.step(7,"credential has an expiry",False,"RMSAIDEL-AUT-004")
    elif ef and (ex-ef).days>365:
        v.step(7,"validity period within 365 days",False,"RMSAIDEL-AUT-004",f"{(ex-ef).days}d")

    # 8. configuration binding (§6.5)
    v.step(8,"configuration digest matches the credential binding",
           ag.get("config_sha256")==cred.get("agent_config_sha256"),
           "RMSAIDEL-AUT-005",
           f"observed={ag.get('config_sha256','')[:12]} bound={cred.get('agent_config_sha256','')[:12]}")

    # 9. instance binding (§6.6)
    v.step(9,"credential bound to this instance only",
           cred.get("agent_instance_id")==ag.get("agent_instance_id")
           and cred.get("used_by_other_instances") is not True,"RMSAIDEL-AUT-006")

    # 10. scope machine-testable and enumerated (§7.1, §7.2)
    v.step(10,"scope is machine-testable",
           scope.get("machine_testable") is True and len(scope.get("action_types",[]))>=1,
           "RMSAIDEL-SCP-001",gap=True)
    v.step(10,"scope grants by enumeration",
           scope.get("grant_mode")=="ENUMERATION","RMSAIDEL-SCP-002")

    # 11. tool inventory consistency (§7.3)
    tools=ag.get("tools",[]); in_scope={e.get("action_type") for e in scope.get("action_types",[])}
    uncovered=[t.get("name") for t in tools
               if t.get("external_effect") is True
               and t.get("action_type") not in in_scope and t.get("disabled") is not True]
    v.step(11,"every externally effective tool in scope or disabled",not uncovered,
           "RMSAIDEL-SCP-003",f"uncovered={uncovered}")

    # 12. quantitative limits declared (§7.4)
    nolim=[e.get("action_type") for e in scope.get("action_types",[])
           if e.get("quantity") and not (e["quantity"].get("per_action_max")
                                         and e["quantity"].get("cumulative_max"))]
    v.step(12,"quantity-bearing types declare both maxima",not nolim,
           "RMSAIDEL-SCP-004",f"missing={nolim}")

    # 13. counterparty restriction (§7.5)
    nocp=[e.get("action_type") for e in scope.get("action_types",[])
          if (e.get("counterparties") or {}).get("mode") not in
             ("ENUMERATED","RULE","UNRESTRICTED")]
    v.step(13,"counterparty restriction stated for every type",not nocp,
           "RMSAIDEL-SCP-005",f"missing={nocp}")

    # 14. checkpoint declaration (§8.1)
    nohc=[e.get("action_type") for e in scope.get("action_types",[])
          if not isinstance((e.get("human_checkpoint") or {}).get("required"),bool)]
    v.step(14,"checkpoint declared for every type",not nohc,
           "RMSAIDEL-HUM-001",f"missing={nohc}",gap=True)

    # 15. log continuity (§11.1, §11.2)
    fieldmiss=[a.get("entry_id") for a in actions
               if not all(a.get(f) for f in ("entry_id","action_time","action_type",
                                             "counterparty","authorization_id","outcome",
                                             "agent_attribution"))]
    v.step(15,"log entries complete",not fieldmiss,"RMSAIDEL-LOG-001",
           f"incomplete={fieldmiss}",gap=(len(actions)==0))
    broken=[]
    for i,a in enumerate(actions):
        if i==0: continue
        prev=actions[i-1]
        expect=hashlib.sha256(str(prev.get("entry_id","")).encode()).hexdigest()
        if a.get("previous_entry_sha256") not in (expect, prev.get("_digest")):
            broken.append(a.get("entry_id"))
    v.step(15,"hash chain continuous",not broken and alog.get("hash_chain") is True,
           "RMSAIDEL-LOG-002",f"broken={broken}")

    # 16. anchoring (§11.3)
    anchors=[ts(x) for x in alog.get("anchors",[]) if ts(x)]
    ok_anchor=bool(anchors); why=""
    if vp and anchors:
        latest=max(anchors)
        if (vp-latest).total_seconds()>24*3600:
            ok_anchor=False; why=f"last anchor {(vp-latest).total_seconds()/3600:.0f}h before vp"
        srt=sorted(a for a in anchors if not ws or a>=ws)
        prev = ws or (srt[0] if srt else None)
        for a in srt:
            if prev and (a-prev).total_seconds()>16*24*3600:
                ok_anchor=False; why=why or "gap in window"
            prev=a
    v.step(16,"anchoring covers the window and reaches the verification point",
           ok_anchor,"RMSAIDEL-LOG-003",why,gap=not anchors)

    # 17. counterparty reconciliation (§11.4)
    cp_records=rec.get("counterparty_records",[])
    logged={a.get("counterparty_reference") for a in actions}
    unlogged=[c.get("reference") for c in cp_records if c.get("reference") not in logged]
    v.step(17,"counterparty records reconcile to the log",not unlogged,
           "RMSAIDEL-LOG-004",f"absent_from_log={unlogged}",
           gap=(not cp_records and not has("EVD-010")))

    # 18-19. replay actions against scope, and cumulative limits (§7.6, §7.7)
    creds_by_id={cred.get("authorization_id"):cred}
    for c in chain: creds_by_id[c.get("authorization_id")]=c
    cumulative={}
    for a in actions:
        at=ts(a.get("action_time"))
        c=creds_by_id.get(a.get("authorization_id"))
        if not c or not at or not in_force(c,at,revs):
            # covered by step 23 as after-revocation/expiry, or out of scope here
            if c and at:
                exp=ts(c.get("expires_at"))
                if exp and at>exp:
                    v.step(23,f"action {a.get('entry_id')} after expiry",False,"RMSAIDEL-REV-005")
                    continue
                r=revs.get(c.get("authorization_id"))
                if r:
                    rt=ts(r.get("effective_time")); prop=r.get("propagation_seconds",0)
                    if rt and at>=rt+timedelta(seconds=prop):
                        v.step(23,f"action {a.get('entry_id')} after revocation",False,
                               "RMSAIDEL-REV-004")
                        continue
            v.step(18,f"action {a.get('entry_id')} covered by a credential in force",False,
                   "RMSAIDEL-SCP-006")
            continue
        sc = c.get("scope") or scope
        ok,entry,why = scope_test(a,sc)
        if not ok and why=="PER_ACTION":
            v.step(19,f"action {a.get('entry_id')} within per-action maximum",False,
                   "RMSAIDEL-SCP-007")
        elif not ok:
            v.step(18,f"action {a.get('entry_id')} within scope",False,"RMSAIDEL-SCP-006")
        elif entry and entry.get("quantity"):
            k=(a.get("authorization_id"),a.get("action_type"))
            cumulative[k]=cumulative.get(k,Decimal(0))+(q(a.get("quantity")) or Decimal(0))
    for (aid,atype),total in cumulative.items():
        c=creds_by_id.get(aid); sc=(c.get("scope") if c else None) or scope
        for e in sc.get("action_types",[]):
            if e.get("action_type")==atype and e.get("quantity"):
                mx=q(e["quantity"].get("cumulative_max"))
                if mx is not None and total>mx:
                    v.step(19,f"cumulative {atype} within maximum",False,"RMSAIDEL-SCP-007",
                           f"total={total} max={mx}")

    # 20-21. human checkpoints (§8.2, §8.3, §8.4)
    approvals_used={}
    for a in actions:
        c=creds_by_id.get(a.get("authorization_id")); sc=(c.get("scope") if c else None) or scope
        need=False
        for e in sc.get("action_types",[]):
            if e.get("action_type")==a.get("action_type"):
                need=(e.get("human_checkpoint") or {}).get("required") is True
        if not need: continue
        h=hcs.get(a.get("entry_id"))
        at=ts(a.get("action_time"))
        if not h or not h.get("approver_id") or not h.get("approval_time"):
            v.step(20,f"approval evidence for {a.get('entry_id')}",False,"RMSAIDEL-HUM-002",gap=True)
            continue
        apt=ts(h.get("approval_time"))
        if apt and at and apt>at:
            v.step(20,f"approval for {a.get('entry_id')} precedes the action",False,
                   "RMSAIDEL-HUM-002",f"approved {(apt-at).total_seconds()/60:.0f}min after")
        aid=h.get("approval_id")
        approvals_used.setdefault(aid,[]).append(a.get("entry_id"))
        if h.get("approver_id")==ag.get("agent_instance_id") or h.get("approver_is_agent") is True:
            v.step(21,f"approver for {a.get('entry_id')} is not the agent itself",False,
                   "RMSAIDEL-HUM-004")
    for aid,entries in approvals_used.items():
        if len(entries)>1 and not rec.get("batch_checkpoint_defined"):
            v.step(21,"one approval per action outside a defined batch checkpoint",False,
                   "RMSAIDEL-HUM-003",f"approval {aid} used for {entries}")

    # 22. revocation mechanism (§9.1, §9.2, §9.3)
    v.step(22,"revocation mechanism disclosed",bool(rv.get("mechanism")),
           "RMSAIDEL-REV-001",gap=True)
    v.step(22,"revocation status checked at required interval",
           rv.get("status_check_performed") is True and bool(rv.get("check_method")),
           "RMSAIDEL-REV-002",gap=True)
    prop=rv.get("propagation_seconds")
    v.step(22,"propagation time disclosed and within 3600s",
           prop is not None and prop<=3600,"RMSAIDEL-REV-003",f"prop={prop}")

    # 24-25. delegation chain (§10)
    if chain:
        if cred.get("sub_delegation_permitted") is not True and rec.get("agent_sub_delegated") is True:
            v.step(24,"sub-delegation expressly permitted",False,"RMSAIDEL-DEL-001")
        unver=[c.get("authorization_id") for c in chain
               if c.get("independently_retrievable") is not True
               or c.get("signature_verified") is not True]
        v.step(24,"every chain credential independently verifiable",not unver,
               "RMSAIDEL-DEL-004",f"unverifiable={unver}",gap=True)
        maxd=cred.get("max_delegation_depth")
        v.step(25,"maximum depth declared and chain within 3 levels",
               maxd is not None and len(chain)<=3 and len(chain)<=maxd,
               "RMSAIDEL-DEL-003",f"depth={len(chain)} max={maxd}")
        # monotonicity
        ordered=chain+[cred]
        for i in range(1,len(ordered)):
            up,dn=ordered[i-1],ordered[i]
            us=(up.get("scope") or {}); ds=(dn.get("scope") or scope)
            ut={e.get("action_type"):e for e in us.get("action_types",[])}
            for e in ds.get("action_types",[]):
                ue=ut.get(e.get("action_type"))
                if not ue:
                    v.step(25,f"action type {e.get('action_type')} present upstream",False,
                           "RMSAIDEL-DEL-002"); continue
                uq,dq=ue.get("quantity"),e.get("quantity")
                if uq and dq:
                    um,dm=q(uq.get("per_action_max")),q(dq.get("per_action_max"))
                    if um is not None and dm is not None and dm>um:
                        v.step(25,f"{e.get('action_type')} per-action max within upstream",False,
                               "RMSAIDEL-DEL-002",f"{dm} > {um}")
                ucp=(ue.get("counterparties") or {}); dcp=(e.get("counterparties") or {})
                if ucp.get("mode")=="ENUMERATED" and dcp.get("mode")=="ENUMERATED":
                    extra=set(dcp.get("values",()))-set(ucp.get("values",()))
                    if extra:
                        v.step(25,f"{e.get('action_type')} counterparties within upstream",False,
                               "RMSAIDEL-DEL-002",f"extra={sorted(extra)}")
                elif ucp.get("mode")=="ENUMERATED" and dcp.get("mode")=="UNRESTRICTED":
                    v.step(25,f"{e.get('action_type')} counterparties within upstream",False,
                           "RMSAIDEL-DEL-002","downstream unrestricted")
            uex,dex=ts(up.get("expires_at")),ts(dn.get("expires_at"))
            if uex and dex and dex>uex:
                v.step(25,"downstream expiry within upstream expiry",False,"RMSAIDEL-DEL-005")
            if revs.get(up.get("authorization_id")) and in_force(dn,vp,revs):
                v.step(23,"downstream invalidated by upstream revocation",False,"RMSAIDEL-REV-006")
        ids=[c.get("agent_instance_id") for c in ordered if c.get("agent_instance_id")]
        if len(ids)!=len(set(ids)):
            v.step(25,"no cycle in delegation chain",False,"RMSAIDEL-DEL-006")

    # 26. attribution, config changes, impersonation (§12.2-§12.4)
    unattr=[a.get("entry_id") for a in actions if not a.get("agent_attribution")]
    v.step(26,"every action attributable to this agent instance",not unattr,
           "RMSAIDEL-IDN-002",f"unattributed={unattr}")
    if ag.get("config_changed_in_window") is True and not has("EVD-014"):
        v.step(26,"configuration change recorded",False,"RMSAIDEL-IDN-003",gap=True)
    v.step(26,"no concealment of agent nature",
           not (ag.get("presents_as_human") is True
                and cred.get("acting_in_delegator_name_permitted") is not True),
           "RMSAIDEL-IDN-004")

    # 27. material events (§13.2)
    for e in rec.get("material_events",[]):
        d=ts(e.get("detected_at")); r=ts(e.get("recorded_at")); n=ts(e.get("notified_at"))
        if (d and r and (r-d)>timedelta(hours=24)) or (d and n and (n-d)>timedelta(hours=24)):
            v.step(27,"material event recorded and notified within 24h",False,"RMSAIDEL-EVT-001")

    # 28. retention (§11.5)
    ry=rec.get("retention_years")
    v.step(28,"log retention at least 7 years",ry is not None and ry>=7,
           "RMSAIDEL-LOG-005",gap=True)

    # 29. evidence (§14)
    req=list(REQUIRED)
    if any((e.get("human_checkpoint") or {}).get("required") for e in scope.get("action_types",[])):
        req.append("EVD-012")
    if chain: req.append("EVD-013")
    if ag.get("config_changed_in_window") is True: req.append("EVD-014")
    if rec.get("material_events"): req.append("EVD-015")
    missing=[e for e in req if e not in ev]
    v.step(29,"mandatory evidence present",not missing,"RMSAIDEL-EVD-001",
           f"missing={missing}",gap=True)
    v.step(29,"evidence metadata complete",
           all(all(e.get(k) for k in ("provider_id","generated_at","acquired_at","uri","sha256"))
               for e in ev.values()),"RMSAIDEL-EVD-001",gap=True)
    wrongauth=[e.get("evidence_id") for e in ev.values()
               if e.get("applies_to_authorization_id")
               and e["applies_to_authorization_id"]!=cred.get("authorization_id")
               and e["applies_to_authorization_id"] not in [c.get("authorization_id") for c in chain]]
    stale=[]
    if vp:
        for eid,h in (("EVD-005",0),("EVD-007",24),("EVD-009",24),("EVD-010",35*24)):
            e=ev.get(eid)
            if not e: continue
            g=ts(e.get("generated_at"))
            if g and (vp-g).total_seconds()>h*3600:
                stale.append(f"{eid}:{(vp-g).total_seconds()/3600:.0f}h>{h}h")
    v.step(29,"evidence fresh and bound to this authorization",not stale and not wrongauth,
           "RMSAIDEL-EVD-003",f"stale={stale} wrong_auth={wrongauth}",gap=True)
    nd=[eid for eid in ("EVD-009","EVD-010") if eid in ev
        and ev[eid].get("provider_independence_disclosed") is not True]
    ctrl=[eid for eid in ("EVD-009","EVD-010") if eid in ev
          and ev[eid].get("provider_controlled_by_operator") is True]
    v.step(29,"provider independence disclosed",not nd,"RMSAIDEL-EVD-004",gap=True)
    v.step(29,"provider independent of operator",not ctrl,"RMSAIDEL-EVD-004")

    # 30. human/machine consistency
    hd=rec.get("human_disclosure",{}); conflict=False
    for f_,mv in (("agent_instance_id",ag.get("agent_instance_id")),
                  ("agent_config_sha256",ag.get("config_sha256")),
                  ("authorization_id",cred.get("authorization_id"))):
        if hd.get(f_) is not None and str(hd[f_])!=str(mv):
            conflict=True; v.notes.append(f"human/machine mismatch on {f_}")
    v.step(30,"human / machine consistency",not conflict,"RMSAIDEL-DAT-001")

    # 31. digests
    v.step(31,"evidence digests well-formed",
           all(isinstance(e.get("sha256"),str) and len(e["sha256"])==64 for e in ev.values()),
           "RMSAIDEL-EVD-002")

    # 32-33. traceability and validity
    rr=rec.get("requirement_results",[])
    v.step(32,"per-requirement traceability",
           len(rr)>=1 and all(r.get("requirement_id") and r.get("result")
               and (r["result"]!="FAIL" or r.get("failure_code")) for r in rr),
           "RMSAIDEL-VER-001",gap=True)
    ea=ts(rec.get("result_expires_at"))
    if vp and ea:
        if (ea-vp).days>90:
            v.step(33,"validity within 90 days",False,"RMSAIDEL-VER-002",f"{(ea-vp).days}d")
        if ex and ea>ex:
            v.step(33,"expiry within credential expiry",False,"RMSAIDEL-VER-002")
        earliest=None
        for eid,h in (("EVD-007",24),("EVD-009",24),("EVD-010",35*24)):
            e=ev.get(eid)
            if not e: continue
            g=ts(e.get("generated_at"))
            if g:
                x=g+timedelta(hours=h)
                earliest = x if earliest is None or x<earliest else earliest
        if earliest and ea>earliest:
            v.step(33,"expiry within earliest evidence expiry",False,"RMSAIDEL-VER-002")

    # 34. signature
    sg=rec.get("signature",{})
    v.step(34,"verification record signed",
           all(sg.get(k) for k in ("algorithm","key_id","signed_at","public_key_uri","signature_value")),
           "RMSAIDEL-SIG-001",gap=True)

    if alog.get("realtime_written") is False: v.should("§11.7 real-time log writing")

    if public_only: v.viol -= v.gap
    viol=[c for c in v.failures if c in v.viol]
    gaps=[c for c in v.failures if c in v.gap and c not in v.viol]
    overall = "FAIL" if viol else ("DEFICIENT" if gaps else ("CONDITIONAL" if v.unmet else "PASS"))
    v.violations, v.gaps = viol, gaps
    return overall, v


# ---------------------------------------------------------------- test cases
import hashlib as _h
H="a"*64; U="2026-01-01T00:00:00Z"; W="2025-10-03T00:00:00Z"
CFG="c"*64

def _entry(i, prev_id, t, atype, cp, qty=None, auth="auth:1"):
    return {"entry_id":f"e{i}",
            "previous_entry_sha256": None if prev_id is None else _h.sha256(prev_id.encode()).hexdigest(),
            "action_time":t,"action_type":atype,"counterparty":cp,
            "quantity":qty,"unit":"USD","authorization_id":auth,
            "outcome":"OK","agent_attribution":"agent:example:0001",
            "counterparty_reference":f"cpref{i}"}

def base():
    acts=[_entry(1,None,"2025-11-01T00:00:00Z","PAYMENT","merchant:A","100.00"),
          _entry(2,"e1","2025-12-01T00:00:00Z","PAYMENT","merchant:B","200.00"),
          _entry(3,"e2","2025-12-15T00:00:00Z","MESSAGE","support:X")]
    return {
      "record_id":"r1","schema_version":"1.0","verification_point":U,
      "assessment_window_start":W,"result_expires_at":"2026-01-02T00:00:00Z",
      "digest_algorithm":"sha-256","retention_years":7,
      "standard":{"standard_id":"RM-S-AI-DEL-001","standard_version":"v1.0-F"},
      "conformity_subject":{"delegator_is_operator":False},
      "delegator":{"delegator_id":"entity:principal","jurisdiction":"SG"},
      "operator":{"operator_id":"entity:operator","jurisdiction":"SG"},
      "agent":{"agent_instance_id":"agent:example:0001","agent_version":"1.4.2",
        "config_sha256":CFG,"identifier_reused":False,"presents_as_human":False,
        "config_changed_in_window":False,
        "tools":[{"name":"pay","action_type":"PAYMENT","external_effect":True},
                 {"name":"notify","action_type":"MESSAGE","external_effect":True},
                 {"name":"scratch","external_effect":False}]},
      "authorization":{"authorization_id":"auth:1","delegator_id":"entity:principal",
        "agent_instance_id":"agent:example:0001","agent_config_sha256":CFG,
        "issued_at":"2025-09-01T00:00:00Z","effective_at":"2025-10-01T00:00:00Z",
        "expires_at":"2026-06-01T00:00:00Z","signature":"sig",
        "signature_verified":True,"signature_covers_scope":True,
        "sub_delegation_permitted":False,"max_delegation_depth":0,
        "used_by_other_instances":False},
      "authority_scope":{"machine_testable":True,"grant_mode":"ENUMERATION",
        "action_types":[
          {"action_type":"PAYMENT",
           "counterparties":{"mode":"ENUMERATED","values":["merchant:A","merchant:B"]},
           "human_checkpoint":{"required":True,"approver_role":"finance_manager"},
           "quantity":{"unit":"USD","decimals":2,"per_action_max":"500.00",
                       "cumulative_max":"5000.00","cumulative_period_hours":720}},
          {"action_type":"MESSAGE",
           "counterparties":{"mode":"ENUMERATED","values":["support:X"]},
           "human_checkpoint":{"required":False}}]},
      "delegation_chain":[],
      "revocation":{"mechanism":"revocation list","check_method":"CRL poll",
        "status_check_performed":True,"propagation_seconds":300,"revoked":False},
      "action_log":{"hash_chain":True,"realtime_written":True,
        "anchors":["2025-10-04T00:00:00Z","2025-10-20T00:00:00Z","2025-11-05T00:00:00Z",
                   "2025-11-21T00:00:00Z","2025-12-07T00:00:00Z","2025-12-23T00:00:00Z",
                   "2025-12-31T12:00:00Z"]},
      "actions":acts,
      "counterparty_records":[{"reference":"cpref1"},{"reference":"cpref2"},{"reference":"cpref3"}],
      "human_checkpoints":[
        {"action_entry_id":"e1","approval_id":"ap1","approver_id":"human:cfo",
         "approval_time":"2025-10-31T23:00:00Z"},
        {"action_entry_id":"e2","approval_id":"ap2","approver_id":"human:cfo",
         "approval_time":"2025-11-30T23:00:00Z"}],
      "material_events":[],
      "evidence":[{"evidence_id":e,"evidence_type":"x","provider_id":"p",
        "provider_independence_disclosed":True,"provider_controlled_by_operator":False,
        "generated_at":U,"acquired_at":U,"uri":"https://ex/e","sha256":H,
        "applies_to_authorization_id":"auth:1"} for e in REQUIRED+["EVD-012"]],
      "requirement_results":[{"requirement_id":"REQ-001","applicability":"APPLICABLE","result":"PASS"}],
      "human_disclosure":{"agent_instance_id":"agent:example:0001",
        "agent_config_sha256":CFG,"authorization_id":"auth:1"},
      "overall_result":{"verification_result":"PASS"},
      "verifier":{"verifier_id":"v1"},
      "signature":{"algorithm":"ES256","key_id":"k1","signed_at":U,
        "public_key_uri":"https://ex/jwks","signature_value":"sig=="}}

def c1(): return "21.1 PASS", base(), "PASS", []
def c2():
    r=base(); r["agent"]["config_sha256"]="d"*64
    r["human_disclosure"]["agent_config_sha256"]="d"*64
    return "21.2 config changed after issuance", r, "FAIL", ["RMSAIDEL-AUT-005"]
def c3():
    r=base(); r["actions"][1]["counterparty"]="merchant:C"
    return "21.3 out-of-scope counterparty", r, "FAIL", ["RMSAIDEL-SCP-006"]
def c4():
    r=base()
    acts=[_entry(i,None if i==1 else f"e{i-1}",f"2025-11-{i:02d}T00:00:00Z",
                 "PAYMENT","merchant:A","400.00") for i in range(1,20)]
    r["actions"]=acts
    r["counterparty_records"]=[{"reference":f"cpref{i}"} for i in range(1,20)]
    r["human_checkpoints"]=[{"action_entry_id":f"e{i}","approval_id":f"ap{i}",
        "approver_id":"human:cfo","approval_time":f"2025-10-{i:02d}T00:00:00Z"}
        for i in range(1,20)]
    return "21.4 cumulative limit evaded", r, "FAIL", ["RMSAIDEL-SCP-007"]
def c5():
    r=base(); r["human_checkpoints"][0]["approval_time"]="2025-11-01T00:40:00Z"
    return "21.5 approval after the action", r, "FAIL", ["RMSAIDEL-HUM-002"]
def c6():
    r=base()
    r["authorization"]["sub_delegation_permitted"]=True
    r["authorization"]["max_delegation_depth"]=2
    up={"authorization_id":"auth:0","agent_instance_id":"agent:upstream",
        "effective_at":"2025-09-01T00:00:00Z","expires_at":"2026-06-01T00:00:00Z",
        "independently_retrievable":True,"signature_verified":True,
        "scope":{"action_types":[
          {"action_type":"PAYMENT",
           "counterparties":{"mode":"ENUMERATED","values":["merchant:A","merchant:B"]},
           "quantity":{"per_action_max":"500.00","cumulative_max":"5000.00"}}]}}
    r["delegation_chain"]=[up]
    r["authority_scope"]["action_types"][0]["quantity"]["per_action_max"]="2000.00"
    r["evidence"].append({"evidence_id":"EVD-013","evidence_type":"x","provider_id":"p",
      "provider_independence_disclosed":True,"provider_controlled_by_operator":False,
      "generated_at":U,"acquired_at":U,"uri":"https://ex/e","sha256":H,
      "applies_to_authorization_id":"auth:0"})
    return "21.6 sub-delegation exceeds upstream", r, "FAIL", ["RMSAIDEL-DEL-002"]
def c7():
    r=base(); r["counterparty_records"].append({"reference":"cpref99"})
    return "21.7 action absent from the log", r, "FAIL", ["RMSAIDEL-LOG-004"]
def c8():
    r=base(); r["action_log"]["realtime_written"]=False
    return "21.8 SHOULD unmet", r, "CONDITIONAL", []
def c9():
    r=base(); r["assessment_basis"]="PUBLIC_INFORMATION_ONLY"
    r["evidence"]=[e for e in r["evidence"] if e["evidence_id"] in ("EVD-002","EVD-005","EVD-018")]
    r["actions"]=[]; r["counterparty_records"]=[]
    r["action_log"]={"hash_chain":True,"anchors":[],"realtime_written":True}
    r["human_checkpoints"]=[]
    r["revocation"]={"mechanism":"","check_method":"","status_check_performed":None,
                     "propagation_seconds":300,"revoked":False}
    r["signature"]={}
    return "21.9 public information only", r, "DEFICIENT", ["RMSAIDEL-EVD-001"]

CASES=[c1,c2,c3,c4,c5,c6,c7,c8,c9]

def a_no_expiry():
    r=base(); r["authorization"]["expires_at"]=None
    return "ADV open-ended credential", r, "FAIL", ["RMSAIDEL-AUT-004"]
def a_too_long():
    r=base(); r["authorization"]["expires_at"]="2027-06-01T00:00:00Z"
    return "ADV validity 608 days (max 365)", r, "FAIL", ["RMSAIDEL-AUT-004"]
def a_shared_cred():
    r=base(); r["authorization"]["used_by_other_instances"]=True
    return "ADV credential shared across instances", r, "FAIL", ["RMSAIDEL-AUT-006"]
def a_nl_scope():
    r=base(); r["authority_scope"]["machine_testable"]=False
    return "ADV scope in natural language only", r, "DEFICIENT", ["RMSAIDEL-SCP-001"]
def a_exclusion():
    r=base(); r["authority_scope"]["grant_mode"]="EXCLUSION"
    return "ADV scope granted by exclusion", r, "FAIL", ["RMSAIDEL-SCP-002"]
def a_hidden_tool():
    r=base(); r["agent"]["tools"].append({"name":"transfer","action_type":"TRANSFER",
                                          "external_effect":True})
    return "ADV tool outside the scope", r, "FAIL", ["RMSAIDEL-SCP-003"]
def a_no_cum():
    r=base(); r["authority_scope"]["action_types"][0]["quantity"].pop("cumulative_max")
    return "ADV no cumulative maximum declared", r, "FAIL", ["RMSAIDEL-SCP-004"]
def a_over_per_action():
    r=base(); r["actions"][0]["quantity"]="900.00"
    return "ADV single action over per-action max", r, "FAIL", ["RMSAIDEL-SCP-007"]
def a_blanket():
    r=base(); r["human_checkpoints"][1]["approval_id"]="ap1"
    return "ADV one approval reused across actions", r, "FAIL", ["RMSAIDEL-HUM-003"]
def a_self_approve():
    r=base(); r["human_checkpoints"][0]["approver_id"]="agent:example:0001"
    return "ADV agent approves its own checkpoint", r, "FAIL", ["RMSAIDEL-HUM-004"]
def a_after_revocation():
    r=base(); r["revocation"].update({"revoked":True,"authorization_id":"auth:1",
        "effective_time":"2025-11-15T00:00:00Z"})
    return "ADV actions after revocation", r, "FAIL", ["RMSAIDEL-REV-004"]
def a_after_expiry():
    r=base(); r["authorization"]["expires_at"]="2025-11-15T00:00:00Z"
    return "ADV action after expiry", r, "FAIL", ["RMSAIDEL-REV-005"]
def a_prop_too_long():
    r=base(); r["revocation"]["propagation_seconds"]=86400
    return "ADV revocation propagation 24h (max 3600s)", r, "FAIL", ["RMSAIDEL-REV-003"]
def a_broken_chain():
    r=base(); r["actions"][2]["previous_entry_sha256"]="f"*64
    return "ADV log hash chain broken", r, "FAIL", ["RMSAIDEL-LOG-002"]
def a_no_anchor():
    r=base(); r["action_log"]["anchors"]=["2025-11-01T00:00:00Z"]
    return "ADV last anchor 61 days before verification", r, "FAIL", ["RMSAIDEL-LOG-003"]
def a_unattributed():
    r=base(); r["actions"][0]["agent_attribution"]=None
    return "ADV action not attributable to the agent", r, "FAIL", ["RMSAIDEL-IDN-002"]
def a_impersonation():
    r=base(); r["agent"]["presents_as_human"]=True
    return "ADV agent presents as human without permission", r, "FAIL", ["RMSAIDEL-IDN-004"]
def a_cycle():
    r=base()
    r["authorization"]["sub_delegation_permitted"]=True
    r["authorization"]["max_delegation_depth"]=2
    r["delegation_chain"]=[{"authorization_id":"auth:0",
        "agent_instance_id":"agent:example:0001",
        "effective_at":"2025-09-01T00:00:00Z","expires_at":"2026-06-01T00:00:00Z",
        "independently_retrievable":True,"signature_verified":True,
        "scope":r["authority_scope"]}]
    r["evidence"].append({"evidence_id":"EVD-013","evidence_type":"x","provider_id":"p",
      "provider_independence_disclosed":True,"provider_controlled_by_operator":False,
      "generated_at":U,"acquired_at":U,"uri":"https://ex/e","sha256":H,
      "applies_to_authorization_id":"auth:0"})
    return "ADV delegation cycle", r, "FAIL", ["RMSAIDEL-DEL-006"]
def a_wrong_auth_evidence():
    r=base()
    for e in r["evidence"]:
        if e["evidence_id"]=="EVD-007": e["applies_to_authorization_id"]="auth:other"
    return "ADV evidence bound to a different authorization", r, "DEFICIENT", ["RMSAIDEL-EVD-003"]
def a_anchor_by_operator():
    r=base()
    for e in r["evidence"]:
        if e["evidence_id"]=="EVD-009": e["provider_controlled_by_operator"]=True
    return "ADV anchoring service controlled by the operator", r, "FAIL", ["RMSAIDEL-EVD-004"]
def a_float():
    r=base(); r["actions"][0]["quantity"]=100.0
    return "ADV float quantity (§18.3 prohibits)", r, "REJECT", []
def a_short_window():
    r=base(); r["assessment_window_start"]="2025-12-20T00:00:00Z"
    return "ADV assessment window 12 days (min 90)", r, "FAIL", ["RMSAIDEL-LOG-006"]
def a_validity_long():
    r=base(); r["result_expires_at"]="2026-05-01T00:00:00Z"
    return "ADV result validity 120 days (max 90)", r, "FAIL", ["RMSAIDEL-VER-002"]

ADV=[a_no_expiry,a_too_long,a_shared_cred,a_nl_scope,a_exclusion,a_hidden_tool,
     a_no_cum,a_over_per_action,a_blanket,a_self_approve,a_after_revocation,
     a_after_expiry,a_prop_too_long,a_broken_chain,a_no_anchor,a_unattributed,
     a_impersonation,a_cycle,a_wrong_auth_evidence,a_anchor_by_operator,a_float,
     a_short_window,a_validity_long]

def main():
    print("="*76); print("RM-S-AI-DEL-001 — §21 test cases"); print("="*76)
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
    print("\n"+"="*76); print("ADVERSARIAL"); print("="*76)
    for fn in ADV:
        n,r,exp,codes=fn()
        try: o,v=verify(r)
        except TypeError as e:
            print(f"\n[OK] {n}\n   rejected at parse: {e}"); continue
        ok=o==exp and all(c in v.failures for c in codes)
        print(f"\n[{'OK' if ok else 'GAP'}] {n}")
        print(f"   expected : {exp}"+(f"  {codes}" if codes else ""))
        print(f"   actual   : {o}"+(f"  {v.failures}" if v.failures else ""))
    print("\n"+"="*76)
    print("§21:", "all test cases reproduce the standard's stated results" if allok else "MISMATCH")
    print("="*76); sys.exit(0 if allok else 1)

if __name__=="__main__": main()
