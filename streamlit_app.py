"""
WEBSITE 2 — FinTech App (Streamlit)
Run: streamlit run website2.py --server.port 5002
Agent:   PayCheck-AI
Role:    CONSUMER + PROVIDER
         ✅ Discovers BankPortal + sends fraud checks
         ✅ Contract validation    — Layer 3
         ✅ Reputation scoring     — Layer 4
         ✅ Heartbeat              — pings peers every 30s
         ✅ Has its own AIP Node   — can receive tasks too
AIP Node runs on: http://localhost:6002
"""

import json, time, uuid, hashlib, threading, urllib.request, urllib.error
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import streamlit as st

# ══════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title            = "FinTech App — PayCheck-AI",
    page_icon             = "💳",
    layout                = "wide",
    initial_sidebar_state = "collapsed"
)

st.markdown("""
<style>
  [data-testid="stAppViewContainer"]{background:#0d0a1a}
  [data-testid="stHeader"]{background:#0d0a1a}
  h1,h2,h3,p,div{color:#e2e8f0}
  .aip-banner{background:#0f0a1a;border:1px solid #7c3aed;border-radius:10px;
    padding:14px 20px;margin-bottom:16px;font-size:0.85rem;color:#a855f7}
  .flow-box{background:#050510;border:1px solid #1e1b4b;border-radius:10px;padding:16px}
  .flow-step{display:flex;align-items:center;gap:10px;padding:8px 0;
    border-bottom:1px solid #0f0f1f;font-size:0.82rem}
  .flow-step:last-child{border-bottom:none}
  .result-block{background:rgba(239,68,68,0.05);border:2px solid #ef4444;
    border-radius:12px;padding:20px;text-align:center;margin-top:12px}
  .result-allow{background:rgba(34,197,94,0.05);border:2px solid #22c55e;
    border-radius:12px;padding:20px;text-align:center;margin-top:12px}
  .hist-item{background:#0a0a14;border:1px solid #1e1b4b;border-radius:8px;
    padding:12px 16px;margin-bottom:8px;font-size:0.82rem}
  .receipt-box{background:#020617;border:1px solid #1e1b4b;border-radius:6px;
    padding:10px;font-family:monospace;font-size:0.7rem;color:#475569;margin-top:8px}
  .contract-box{background:#020617;border:1px solid #1e1b4b;border-radius:8px;
    padding:12px;font-size:0.8rem;margin-bottom:8px}
  .peer-card{background:#0f0a1a;border:1px solid #1e1b4b;border-radius:8px;
    padding:12px;margin-bottom:8px;font-size:0.82rem}
  .event-row{padding:6px 0;border-bottom:1px solid #0f172a;
    font-size:0.78rem;display:flex;gap:12px}
  .tag-block{background:rgba(239,68,68,0.15);color:#ef4444;padding:3px 10px;
    border-radius:20px;font-size:0.75rem;font-weight:700;display:inline-block}
  .tag-allow{background:rgba(34,197,94,0.15);color:#22c55e;padding:3px 10px;
    border-radius:20px;font-size:0.75rem;font-weight:700;display:inline-block}
  .heartbeat-dot{display:inline-block;width:8px;height:8px;border-radius:50%;
    background:#22c55e;box-shadow:0 0 6px #22c55e;margin-right:6px}
  .offline-dot{display:inline-block;width:8px;height:8px;border-radius:50%;
    background:#ef4444;margin-right:6px}
  [data-testid="metric-container"]{background:#0f0a1a;border:1px solid #2d1b4e;
    border-radius:10px;padding:12px}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# MODULE-LEVEL STORES
# ══════════════════════════════════════════════════════════════
import sys
_mod = sys.modules[__name__]

if not hasattr(_mod, "_INIT_DONE"):
    _mod._INIT_DONE         = True
    _mod._sent_log          = []     # tasks this agent SENT
    _mod._received_log      = []     # tasks this agent RECEIVED
    _mod._event_store       = []     # reputation events
    _mod._peer_store        = {}     # heartbeat results
    _mod._score_store       = [100]  # reputation score
    _mod._blacklist         = set()
    _mod._vouch_store       = []
    _mod._dispute_store     = []
    _mod._contract_errors   = []
    _mod._aip_running       = False
    _mod._heartbeat_running = False

    _id = f"agt://RazorPay/PayCheck-AI/{uuid.uuid4().hex[:8]}"
    _mod._agent_id    = _id
    _mod._secret_key  = hashlib.sha256(f"{_id}{time.time()}".encode()).hexdigest()
    _mod._fingerprint = hashlib.sha256(
        f"PUBLIC:{_mod._secret_key}".encode()
    ).hexdigest()[:32]

BANK_AIP_NODE = "http://localhost:6001"

# ══════════════════════════════════════════════════════════════
# LAYER 3 — CONTRACT
# ══════════════════════════════════════════════════════════════
PAYCHECK_CONTRACT = {
    "task_type":   "PAYMENT_INITIATION",
    "version":     "1.0",
    "description": "Initiate and validate UPI/card payment requests",
    "input_schema": {
        "txn_id":        {"type": "str",   "required": True},
        "amount":        {"type": "float", "required": True, "min": 1},
        "merchant":      {"type": "str",   "required": True},
        "country":       {"type": "str",   "required": True},
        "user_location": {"type": "str",   "required": True}
    },
    "output_schema": {
        "status":    {"type": "str",  "required": True},
        "approved":  {"type": "bool", "required": True},
        "task_id":   {"type": "str",  "required": True},
        "elapsed_ms":{"type": "float","required": True}
    },
    "error_codes": {
        "SCHEMA_MISMATCH":    "Input does not match contract",
        "MISSING_FIELD":      "Required field missing",
        "BANK_OFFLINE":       "FraudGuard-AI unreachable",
        "BLACKLISTED_CALLER": "Caller is blacklisted"
    },
    "sla_ms":         3000,
    "price_per_call": 0.001
}

def validate_input(payload: dict) -> tuple:
    schema = PAYCHECK_CONTRACT["input_schema"]
    for field, defn in schema.items():
        if defn.get("required", True) and field not in payload:
            return False, f"MISSING_FIELD: '{field}' is required"
        if field in payload:
            val = payload[field]
            typ = defn.get("type")
            type_map = {"float": (float, int), "str": str, "int": int, "bool": bool}
            if typ and typ in type_map:
                if not isinstance(val, type_map[typ]):
                    try:
                        float(val) if typ == "float" else str(val)
                    except:
                        return False, f"INVALID_TYPE: '{field}' must be {typ}"
            if "min" in defn:
                try:
                    if float(val) < defn["min"]:
                        return False, f"RANGE_ERROR: '{field}' must be >= {defn['min']}"
                except: pass
    return True, "OK"

# ══════════════════════════════════════════════════════════════
# LAYER 4 — REPUTATION ENGINE
# ══════════════════════════════════════════════════════════════
SCORE_TABLE = {
    "TASK_SUCCESS":    +5,
    "TASK_FAST":       +2,
    "TASK_FAIL":      -10,
    "TASK_LATE":       -3,
    "CONTRACT_BREACH":-25,
    "DISPUTE_UPHELD": -30,
    "FIRST_TASK":     +10,
    "VOUCH_RECEIVED":  +8,
    "HEARTBEAT_OK":    +1,
}

TRUST_LEVELS = {
    150: ("CERTIFIED",   "#22c55e"),
    100: ("VERIFIED",    "#3b82f6"),
    50:  ("PROBATION",   "#f59e0b"),
    0:   ("BLACKLISTED", "#ef4444"),
}

def get_trust_level(score: int) -> tuple:
    for threshold, info in sorted(TRUST_LEVELS.items(), reverse=True):
        if score >= threshold:
            return info
    return ("BLACKLISTED", "#ef4444")

def record_event(event_type: str, detail: str = "", by: str = "SYSTEM"):
    delta     = SCORE_TABLE.get(event_type, 0)
    old_score = _mod._score_store[0]
    new_score = max(0, min(200, old_score + delta))
    _mod._score_store[0] = new_score

    event = {
        "event_id":   uuid.uuid4().hex[:10],
        "event_type": event_type,
        "delta":      delta,
        "old_score":  old_score,
        "new_score":  new_score,
        "detail":     detail,
        "by":         by,
        "time":       datetime.utcnow().strftime("%H:%M:%S")
    }
    _mod._event_store.append(event)

    if new_score <= 10:
        _mod._blacklist.add(_mod._agent_id)
    return event

# ══════════════════════════════════════════════════════════════
# DISCOVER + DELEGATE (outbound — calls FraudGuard-AI)
# ══════════════════════════════════════════════════════════════
def discover_fraud_agent() -> dict:
    try:
        with urllib.request.urlopen(f"{BANK_AIP_NODE}/agents", timeout=2) as r:
            agents = json.loads(r.read())
            for a in agents:
                for cap in a.get("capabilities", []):
                    if cap.get("task_type") == "FRAUD_DETECTION":
                        return a
    except:
        return None

def delegate_fraud_check(txn: dict) -> dict:
    """Build AIP/1.0 DELEGATE message and send to FraudGuard-AI"""
    task_id = uuid.uuid4().hex[:12]
    start_t = time.time()

    # Layer 3 — validate before sending
    is_valid, err_msg = validate_input(txn)
    if not is_valid:
        _mod._contract_errors.append({
            "time":   datetime.utcnow().strftime("%H:%M:%S"),
            "error":  "SCHEMA_MISMATCH",
            "detail": err_msg,
            "payload": txn
        })
        record_event("CONTRACT_BREACH", detail=err_msg, by="SELF")
        return {"success": False, "error": err_msg, "task_id": task_id}

    aip_msg = {
        "method":      "DELEGATE",
        "aip_version": "AIP/1.0",
        "message_id":  uuid.uuid4().hex,
        "timestamp":   datetime.utcnow().isoformat(),
        "sender_id":   _mod._agent_id,
        "receiver_id": "agt://HDFC-Bank/FraudGuard-AI",
        "payload": {
            "task_id":      task_id,
            "task_type":    "FRAUD_DETECTION",
            "payload":      json.dumps(txn),
            "agreed_price": 0.003,
            "deadline_ms":  PAYCHECK_CONTRACT["sla_ms"]
        },
        "signature": hashlib.sha256(
            json.dumps({"task_id": task_id, **txn}, sort_keys=True).encode()
        ).hexdigest()[:32]
    }

    try:
        data = json.dumps(aip_msg).encode()
        req  = urllib.request.Request(
            f"{BANK_AIP_NODE}/delegate",
            data    = data,
            headers = {"Content-Type": "application/json"},
            method  = "POST"
        )
        with urllib.request.urlopen(req, timeout=4) as r:
            receipt  = json.loads(r.read())
            elapsed  = (time.time() - start_t) * 1000

            # Layer 4 — record events
            is_first = len(_mod._sent_log) == 0
            record_event("TASK_SUCCESS",
                         detail=f"{txn.get('merchant','?')} ₹{txn.get('amount','?')}",
                         by="FraudGuard-AI")
            if is_first:
                record_event("FIRST_TASK", detail="First delegation bonus")
            if elapsed <= PAYCHECK_CONTRACT["sla_ms"]:
                record_event("TASK_FAST", detail=f"{elapsed:.0f}ms")
            else:
                record_event("TASK_LATE", detail=f"{elapsed:.0f}ms > SLA")

            return {
                "success":    True,
                "receipt":    receipt,
                "task_id":    task_id,
                "elapsed_ms": round(elapsed, 1)
            }

    except urllib.error.URLError as e:
        record_event("TASK_FAIL", detail=f"BankPortal offline: {e.reason}")
        return {"success": False, "error": f"BankPortal offline: {e.reason}", "task_id": task_id}
    except Exception as e:
        record_event("TASK_FAIL", detail=str(e))
        return {"success": False, "error": str(e), "task_id": task_id}

# ══════════════════════════════════════════════════════════════
# LAYER 2 — OWN AIP HTTP NODE (port 6002)
# So BankPortal can also call THIS agent
# ══════════════════════════════════════════════════════════════
def start_aip_node():
    if _mod._aip_running:
        return
    _mod._aip_running = True

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            if self.path == "/agents":
                self._respond(200, [{
                    "agent_id":    _mod._agent_id,
                    "agent_name":  "PayCheck-AI",
                    "owner":       "RazorPay",
                    "trust_level": get_trust_level(_mod._score_store[0])[0],
                    "score":       _mod._score_store[0],
                    "fingerprint": _mod._fingerprint,
                    "capabilities": [PAYCHECK_CONTRACT]
                }])
            elif self.path == "/contract":
                self._respond(200, PAYCHECK_CONTRACT)
            elif self.path == "/reputation":
                score = _mod._score_store[0]
                level, _ = get_trust_level(score)
                self._respond(200, {
                    "agent_id":     _mod._agent_id,
                    "score":        score,
                    "trust_level":  level,
                    "total_tasks":  len(_mod._sent_log),
                    "recent_events": _mod._event_store[-5:]
                })
            elif self.path == "/ping":
                self._respond(200, {
                    "status":      "alive",
                    "agent":       "PayCheck-AI",
                    "score":       _mod._score_store[0],
                    "trust_level": get_trust_level(_mod._score_store[0])[0],
                    "timestamp":   datetime.utcnow().isoformat()
                })
            else:
                self._respond(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))

            if self.path == "/delegate":
                sender    = body.get("sender_id", "unknown")
                payload   = body.get("payload", {})
                task_data = json.loads(payload.get("payload", "{}"))
                task_id   = payload.get("task_id", uuid.uuid4().hex[:12])

                # Layer 4 — blacklist check
                if sender in _mod._blacklist:
                    self._respond(403, {"error": "BLACKLISTED_CALLER"})
                    return

                # Layer 3 — validate input
                is_valid, err_msg = validate_input(task_data)
                if not is_valid:
                    _mod._contract_errors.append({
                        "time":   datetime.utcnow().strftime("%H:%M:%S"),
                        "sender": sender,
                        "error":  "SCHEMA_MISMATCH",
                        "detail": err_msg
                    })
                    self._respond(400, {"error": "SCHEMA_MISMATCH", "detail": err_msg})
                    return

                # Simple payment approval logic
                amount   = float(task_data.get("amount", 0))
                approved = amount < 100000  # block > 1L
                status   = "APPROVED" if approved else "REJECTED"

                receipt_payload = {
                    "task_id":      task_id,
                    "status":       "COMPLETED",
                    "result": {
                        "status":     status,
                        "approved":   approved,
                        "task_id":    task_id,
                        "elapsed_ms": 10.0,
                        "reason":     "Amount within limit" if approved else "Amount exceeds limit"
                    },
                    "cost_charged": 0.001,
                    "executed_at":  datetime.utcnow().isoformat(),
                    "agent":        "PayCheck-AI"
                }
                sig = hashlib.sha256(
                    json.dumps(receipt_payload, sort_keys=True).encode()
                ).hexdigest()

                _mod._received_log.append({
                    "from":      sender,
                    "task_id":   task_id,
                    "task_data": task_data,
                    "result":    receipt_payload["result"],
                    "time":      datetime.utcnow().strftime("%H:%M:%S"),
                    "signature": sig[:24]
                })

                record_event("TASK_SUCCESS", detail=f"Received from {sender[:20]}", by=sender)
                self._respond(200, {
                    "method":      "RECEIPT",
                    "sender_id":   _mod._agent_id,
                    "payload":     receipt_payload,
                    "signature":   sig,
                    "aip_version": "AIP/1.0"
                })

            elif self.path == "/vouch":
                voucher  = body.get("voucher_id")
                reason   = body.get("reason", "")
                strength = body.get("strength", 10)
                record = {
                    "vouch_id":   uuid.uuid4().hex[:10],
                    "voucher_id": voucher,
                    "reason":     reason,
                    "strength":   strength,
                    "time":       datetime.utcnow().strftime("%H:%M:%S")
                }
                _mod._vouch_store.append(record)
                record_event("VOUCH_RECEIVED",
                             detail=f"Vouched by {voucher} strength={strength}",
                             by=voucher)
                self._respond(200, {"accepted": True, "vouch_id": record["vouch_id"]})

            else:
                self._respond(404, {"error": "not found"})

        def _respond(self, code, data):
            try:
                body = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type",   "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except: pass

    server = HTTPServer(("localhost", 6002), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("  🔌 PayCheck-AI AIP Node running on port 6002")

# ══════════════════════════════════════════════════════════════
# HEARTBEAT — pings BankPortal every 30s
# ══════════════════════════════════════════════════════════════
KNOWN_PEERS = [
    {"url": "http://localhost:6001", "name": "FraudGuard-AI (BankPortal)"},
    {"url": "http://localhost:6003", "name": "TaxAdvisor-AI"},
]

def heartbeat_loop():
    if _mod._heartbeat_running:
        return
    _mod._heartbeat_running = True

    while True:
        for peer in KNOWN_PEERS:
            try:
                req = urllib.request.Request(
                    f"{peer['url']}/ping",
                    headers={"X-Agent-ID": _mod._agent_id,
                             "X-Score":    str(_mod._score_store[0])},
                    method="GET"
                )
                with urllib.request.urlopen(req, timeout=2) as r:
                    resp = json.loads(r.read())
                    _mod._peer_store[peer["url"]] = {
                        "name":      peer["name"],
                        "status":    "ONLINE",
                        "score":     resp.get("score", "?"),
                        "trust":     resp.get("trust_level", "?"),
                        "last_seen": datetime.utcnow().strftime("%H:%M:%S"),
                        "agent":     resp.get("agent", peer["name"])
                    }
                    record_event("HEARTBEAT_OK",
                                 detail=f"{peer['name']} alive",
                                 by="HEARTBEAT")
            except:
                _mod._peer_store[peer["url"]] = {
                    "name":      peer["name"],
                    "status":    "OFFLINE",
                    "last_seen": datetime.utcnow().strftime("%H:%M:%S")
                }
        time.sleep(30)

# ══════════════════════════════════════════════════════════════
# START BACKGROUND SERVICES
# ══════════════════════════════════════════════════════════════
start_aip_node()
threading.Thread(target=heartbeat_loop, daemon=True).start()

# ══════════════════════════════════════════════════════════════
# UI
# ══════════════════════════════════════════════════════════════
score         = _mod._score_store[0]
trust, tcolor = get_trust_level(score)

# ── Header ────────────────────────────────────────────────────
st.markdown(f"""
<div style="background:linear-gradient(135deg,#1a0533,#0d0d1a);
     padding:20px 28px;border-radius:12px;border-bottom:2px solid #7c3aed;
     display:flex;align-items:center;margin-bottom:24px">
  <div>
    <div style="font-size:1.8rem;font-weight:800;color:#a855f7">💳 FinTech App</div>
    <div style="color:#94a3b8;font-size:0.85rem;margin-top:4px">
      PayCheck-AI — AIP/1.0 · Layer 1+2+3+4 Active
    </div>
  </div>
  <div style="margin-left:auto;display:flex;gap:10px;align-items:center">
    <div style="background:rgba(34,197,94,0.15);border:1px solid #22c55e;
         color:#22c55e;padding:6px 14px;border-radius:20px;font-size:0.78rem">
      ● AIP Node :6002
    </div>
    <div style="background:rgba(168,85,247,0.15);border:1px solid #7c3aed;
         color:#a855f7;padding:6px 14px;border-radius:20px;font-size:0.78rem">
      ♥ Heartbeat ON
    </div>
    <div style="background:rgba(59,130,246,0.15);border:1px solid #2563eb;
         color:{tcolor};padding:6px 14px;border-radius:20px;font-size:0.78rem">
      ★ {trust}
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📤 Send Transaction",
    "📋 Contract (L3)",
    "⭐ Reputation (L4)",
    "🌐 Peers & Heartbeat",
    "📥 Received Tasks"
])

# ══════════════════════════════════════════════════════════════
# TAB 1 — SEND TRANSACTION
# ══════════════════════════════════════════════════════════════
with tab1:

    # Metrics
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Reputation Score",  score)
    m2.metric("Tasks Sent",        len(_mod._sent_log))
    m3.metric("Trust Level",       trust)
    m4.metric("Contract Errors",   len(_mod._contract_errors))
    m5.metric("AIP Node",          "localhost:6002")

    # Connection status
    try:
        agent_info = discover_fraud_agent()
        if agent_info:
            agent_score = agent_info.get("score", "?")
            agent_trust = agent_info.get("trust_level", "?")
            st.markdown(f"""
            <div class="aip-banner">
              ✅ <strong>FraudGuard-AI discovered</strong>
              &nbsp;|&nbsp; localhost:6001
              &nbsp;|&nbsp; Score: <strong>{agent_score}</strong>
              &nbsp;|&nbsp; Trust: <strong>{agent_trust}</strong>
              &nbsp;|&nbsp; ₹0.003/call
              &nbsp;|&nbsp; SLA: 200ms
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background:#1a0a0a;border:1px solid #ef4444;border-radius:10px;
                 padding:14px 20px;margin-bottom:16px;font-size:0.85rem;color:#ef4444">
              ❌ BankPortal offline — start website1.py first
              &nbsp;|&nbsp; Expected at localhost:6001
            </div>
            """, unsafe_allow_html=True)
    except:
        st.error("Could not check BankPortal status")

    # Form + Result side by side
    col_form, col_result = st.columns([1, 1])

    with col_form:
        st.markdown("### 📤 Submit Transaction")

        txn_id   = st.text_input("Transaction ID",   value="TXN9823")
        merchant = st.text_input("Merchant Name",    value="Amazon India")
        amount   = st.number_input("Amount (₹)",     value=5000.0, min_value=1.0)
        country  = st.selectbox("Country (card location)",
                                ["India","Nigeria","Russia","USA","UK","Unknown"])
        user_loc = st.selectbox("User Location",
                                ["Mumbai","Delhi","Chennai","Bangalore","Hyderabad"])

        # Quick presets
        st.markdown("**Quick Tests:**")
        p1,p2,p3,p4 = st.columns(4)
        preset = None
        if p1.button("🍕 Swiggy"):     preset = ("TXN001","Swiggy",450.0,"India","Mumbai")
        if p2.button("🚨 Nigeria"):    preset = ("TXN002","Unknown Vendor",87500.0,"Nigeria","Mumbai")
        if p3.button("📦 Amazon"):     preset = ("TXN003","Amazon India",2399.0,"India","Delhi")
        if p4.button("⚠️ Crypto"):     preset = ("TXN004","Crypto Exchange",100000.0,"Russia","Chennai")

        if preset:
            txn_id, merchant, amount, country, user_loc = preset

        send_clicked = st.button("⚡ Send via AIP Protocol", type="primary",
                                 use_container_width=True)

    with col_result:
        st.markdown("### ⚡ AIP Message Flow")

        # Flow diagram (always visible)
        bank_online = agent_info is not None if 'agent_info' in dir() else False
        st.markdown(f"""
        <div class="flow-box">
          <div class="flow-step">
            <span style="font-size:1rem">🤖</span>
            <span style="color:#94a3b8;flex:1">PayCheck-AI (this app)</span>
            <span style="font-family:monospace;font-size:0.72rem;color:#6d28d9">
              {_mod._agent_id[:30]}...
            </span>
          </div>
          <div class="flow-step">
            <span style="font-size:1rem">✅</span>
            <span style="color:#94a3b8;flex:1">Layer 3 — validate input</span>
            <span style="font-family:monospace;font-size:0.72rem;color:#22c55e">
              contract enforced
            </span>
          </div>
          <div class="flow-step">
            <span style="font-size:1rem">📤</span>
            <span style="color:#94a3b8;flex:1">DELEGATE → localhost:6001</span>
            <span style="font-family:monospace;font-size:0.72rem;color:#6d28d9">
              AIP/1.0 signed
            </span>
          </div>
          <div class="flow-step">
            <span style="font-size:1rem">📥</span>
            <span style="color:#94a3b8;flex:1">RECEIPT ← FraudGuard-AI</span>
            <span style="font-family:monospace;font-size:0.72rem;color:#6d28d9">
              {'✅ connected' if bank_online else '❌ offline'}
            </span>
          </div>
          <div class="flow-step">
            <span style="font-size:1rem">⭐</span>
            <span style="color:#94a3b8;flex:1">Layer 4 — update reputation</span>
            <span style="font-family:monospace;font-size:0.72rem;color:#a855f7">
              score={score}
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # Result placeholder
        result_placeholder = st.empty()

    # ── Handle Send ───────────────────────────────────────────
    if send_clicked:
        txn_payload = {
            "txn_id":        txn_id,
            "amount":        float(amount),
            "merchant":      merchant,
            "country":       country,
            "user_location": user_loc
        }

        with st.spinner("Sending via AIP Protocol..."):
            result  = delegate_fraud_check(txn_payload)
            elapsed = result.get("elapsed_ms", 0)

        # Store in sent log
        _mod._sent_log.append({
            "txn":     txn_payload,
            "result":  result,
            "elapsed": elapsed,
            "time":    datetime.utcnow().strftime("%H:%M:%S"),
            "task_id": result.get("task_id", "?")
        })

        if result["success"]:
            receipt     = result["receipt"]
            fraud_result= receipt.get("payload", {}).get("result", {})
            blocked     = fraud_result.get("block", False)
            risk_pct    = int(fraud_result.get("risk_score", 0) * 100)
            sig         = receipt.get("signature", "???")[:24]
            color       = "#ef4444" if blocked else "#22c55e"
            verdict     = "🚫 BLOCKED" if blocked else "✅ ALLOWED"
            css_class   = "result-block" if blocked else "result-allow"

            with col_result:
                st.markdown(f"""
                <div class="{css_class}">
                  <div style="font-size:1.8rem;font-weight:900">{verdict}</div>
                  <div style="font-size:3rem;font-weight:900;color:{color}">{risk_pct}%</div>
                  <div style="font-size:0.8rem;color:#94a3b8">Risk Score</div>
                  <div style="font-size:0.85rem;color:#94a3b8;margin-top:8px">
                    {fraud_result.get("reason","Analysis complete")}
                  </div>
                  <div class="receipt-box">
                    AIP/1.0 RECEIPT | task_id: {result["task_id"]}
                    | sig: {sig}...
                    | {elapsed}ms | ₹0.003 charged
                    | Layer3: ✅ validated | Layer4: +score
                  </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            with col_result:
                st.error(f"❌ {result['error']}")

    # ── Contract Errors ───────────────────────────────────────
    if _mod._contract_errors:
        st.markdown("### ⚠️ Contract Validation Failures (Layer 3)")
        for err in reversed(_mod._contract_errors[-5:]):
            st.markdown(f"""
            <div style="background:#1a0a1a;border:1px solid rgba(239,68,68,0.4);
                 border-radius:8px;padding:12px;margin-bottom:8px;font-size:0.8rem">
              <span style="color:#ef4444;font-weight:700">{err["error"]}</span>
              &nbsp;|&nbsp; {err["time"]}
              &nbsp;|&nbsp; <span style="color:#64748b">{err["detail"]}</span>
            </div>
            """, unsafe_allow_html=True)

    # ── Sent History ──────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📋 Transaction History")

    col_rr, _ = st.columns([1, 5])
    with col_rr:
        if st.button("🔄 Refresh", key="ref_hist"): st.rerun()

    if not _mod._sent_log:
        st.markdown("""
        <div style="text-align:center;padding:40px;background:#0f0a1a;
             border-radius:12px;border:1px solid #1e1b4b">
          <div style="font-size:2.5rem">📡</div>
          <div style="color:#334155;margin-top:8px">No transactions yet</div>
        </div>""", unsafe_allow_html=True)
    else:
        for item in reversed(_mod._sent_log[-20:]):
            ok      = item["result"]["success"]
            receipt = item["result"].get("receipt", {}) if ok else {}
            r       = receipt.get("payload", {}).get("result", {}) if ok else {}
            blocked = r.get("block", False)
            score_v = int(r.get("risk_score", 0) * 100) if ok else "?"
            color   = "#ef4444" if blocked else "#22c55e"

            st.markdown(f"""
            <div class="hist-item">
              <div style="display:flex;align-items:center;gap:16px">
                <span style="color:#475569;font-family:monospace;width:65px">
                  {item["time"]}
                </span>
                <span style="font-weight:700;flex:1">{item["txn"]["merchant"]}</span>
                <span style="color:#a855f7;width:100px">
                  ₹{float(item["txn"]["amount"]):,.0f}
                </span>
                <span style="color:{color};width:50px;text-align:center">
                  {score_v}%
                </span>
                <span style="color:#475569;font-size:0.7rem;width:60px">
                  {item["elapsed"]}ms
                </span>
                <span class="{'tag-block' if blocked else 'tag-allow'}">
                  {'🚫 BLOCK' if blocked else '✅ ALLOW' if ok else '❌ ERR'}
                </span>
              </div>
            </div>
            """, unsafe_allow_html=True)

    auto = st.checkbox("Auto-refresh 2s", value=False, key="auto_tab1")
    if auto:
        time.sleep(2)
        st.rerun()

# ══════════════════════════════════════════════════════════════
# TAB 2 — CONTRACT (LAYER 3)
# ══════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### 📋 Layer 3 — PayCheck-AI Contract")
    st.markdown("""
    <div style="background:#0a0a1a;border:1px solid #2d1b4e;border-radius:10px;
         padding:14px;margin-bottom:16px;font-size:0.83rem;color:#94a3b8">
      PayCheck-AI enforces this contract on all incoming tasks.
      It also validates payloads BEFORE sending to FraudGuard-AI — prevents wasted calls.
    </div>
    """, unsafe_allow_html=True)

    col_in, col_out = st.columns(2)

    with col_in:
        st.markdown("#### 📥 Input Schema")
        for field, defn in PAYCHECK_CONTRACT["input_schema"].items():
            req   = "required" if defn.get("required", True) else "optional"
            color = "#a855f7" if req == "required" else "#64748b"
            extra = f" min={defn['min']}" if "min" in defn else ""
            st.markdown(f"""
            <div class="contract-box">
              <span style="color:{color};font-weight:700">{field}</span>
              &nbsp;<span style="color:#475569">{defn["type"]}</span>
              &nbsp;<span style="color:#334155;font-size:0.75rem">{req}{extra}</span>
            </div>
            """, unsafe_allow_html=True)

    with col_out:
        st.markdown("#### 📤 Output Schema")
        for field, defn in PAYCHECK_CONTRACT["output_schema"].items():
            st.markdown(f"""
            <div class="contract-box">
              <span style="color:#22c55e;font-weight:700">{field}</span>
              &nbsp;<span style="color:#475569">{defn["type"]}</span>
              &nbsp;<span style="color:#334155;font-size:0.75rem">required</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("#### ❌ Error Codes")
    ec1, ec2 = st.columns(2)
    codes = list(PAYCHECK_CONTRACT["error_codes"].items())
    for i, (code, desc) in enumerate(codes):
        col = ec1 if i % 2 == 0 else ec2
        with col:
            st.markdown(f"""
            <div class="contract-box">
              <span style="color:#f59e0b;font-weight:700">{code}</span>
              <br><span style="color:#475569">{desc}</span>
            </div>
            """, unsafe_allow_html=True)

    s1, s2, s3 = st.columns(3)
    s1.metric("SLA",          f"{PAYCHECK_CONTRACT['sla_ms']}ms")
    s2.metric("Price / Call", f"₹{PAYCHECK_CONTRACT['price_per_call']}")
    s3.metric("Version",      PAYCHECK_CONTRACT["version"])

    # Live tester
    st.markdown("---")
    st.markdown("#### 🧪 Test Contract Validation")
    t1, t2 = st.columns(2)
    with t1:
        tt_id  = st.text_input("txn_id",        value="TXN001", key="ct1")
        tt_amt = st.text_input("amount",         value="5000",   key="ct2")
        tt_cty = st.text_input("country",        value="India",  key="ct3")
        tt_loc = st.text_input("user_location",  value="Mumbai", key="ct4")
        tt_mrc = st.text_input("merchant",       value="Swiggy", key="ct5")
    with t2:
        if st.button("✅ Validate Payload"):
            test_p = {
                "txn_id":        tt_id,
                "amount":        float(tt_amt) if tt_amt.replace(".","").isdigit() else tt_amt,
                "country":       tt_cty,
                "user_location": tt_loc,
                "merchant":      tt_mrc
            }
            valid, msg = validate_input(test_p)
            if valid:
                st.success(f"✅ VALID — {msg}")
            else:
                st.error(f"❌ INVALID — {msg}")
            st.json(test_p)

# ══════════════════════════════════════════════════════════════
# TAB 3 — REPUTATION (LAYER 4)
# ══════════════════════════════════════════════════════════════
with tab3:
    score         = _mod._score_store[0]
    trust, tcolor = get_trust_level(score)

    st.markdown("### ⭐ Layer 4 — Reputation Engine")

    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Score",        score)
    r2.metric("Trust Level",  trust)
    r3.metric("Blacklisted",  "YES 🚫" if _mod._agent_id in _mod._blacklist else "NO ✅")
    r4.metric("Total Events", len(_mod._event_store))

    pct = min(score / 200 * 100, 100)
    st.markdown(f"""
    <div style="margin:16px 0">
      <div style="display:flex;justify-content:space-between;
           font-size:0.75rem;color:#64748b;margin-bottom:4px">
        <span>0 — BLACKLISTED</span>
        <span>50 — PROBATION</span>
        <span>100 — VERIFIED</span>
        <span>150 — CERTIFIED</span>
        <span>200</span>
      </div>
      <div style="height:12px;background:#1e293b;border-radius:6px">
        <div style="height:100%;width:{pct}%;background:{tcolor};border-radius:6px"></div>
      </div>
      <div style="text-align:center;margin-top:6px;font-size:1.1rem;
           font-weight:700;color:{tcolor}">
        {score} / 200 — {trust}
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("#### 📊 Score Table")
    sc1, sc2 = st.columns(2)
    with sc1:
        st.markdown("**Good Events ↑**")
        for evt, delta in {k:v for k,v in SCORE_TABLE.items() if v>0}.items():
            st.markdown(f"""
            <div class="event-row">
              <span style="color:#22c55e;width:170px">{evt}</span>
              <span style="color:#22c55e;font-weight:700">+{delta}</span>
            </div>""", unsafe_allow_html=True)
    with sc2:
        st.markdown("**Bad Events ↓**")
        for evt, delta in {k:v for k,v in SCORE_TABLE.items() if v<0}.items():
            st.markdown(f"""
            <div class="event-row">
              <span style="color:#ef4444;width:170px">{evt}</span>
              <span style="color:#ef4444;font-weight:700">{delta}</span>
            </div>""", unsafe_allow_html=True)

    st.markdown("#### 📜 Recent Events")
    events = _mod._event_store[-30:]
    if not events:
        st.info("No events yet — send a transaction to see events")
    else:
        for ev in reversed(events):
            delta = ev["delta"]
            color = "#22c55e" if delta > 0 else "#ef4444"
            sign  = "+" if delta > 0 else ""
            st.markdown(f"""
            <div class="event-row" style="padding:8px 0">
              <span style="color:#475569;width:60px;font-family:monospace">{ev["time"]}</span>
              <span style="color:#94a3b8;width:180px">{ev["event_type"]}</span>
              <span style="color:{color};font-weight:700;width:50px">{sign}{delta}</span>
              <span style="color:#334155;font-size:0.75rem">
                {ev["old_score"]} → {ev["new_score"]} | {ev["detail"][:50]}
              </span>
            </div>
            """, unsafe_allow_html=True)

    # Vouches
    st.markdown("---")
    st.markdown("#### 🤝 Vouch Records")
    if not _mod._vouch_store:
        st.info("No vouches yet")
    else:
        for v in _mod._vouch_store:
            st.markdown(f"""
            <div class="peer-card">
              <span style="color:#a855f7">🤝 Vouched by:</span> {v["voucher_id"][:30]}...
              &nbsp;|&nbsp; Strength: {v["strength"]}
              &nbsp;|&nbsp; {v["time"]}
              <br><span style="color:#64748b;font-size:0.75rem">{v["reason"]}</span>
            </div>
            """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# TAB 4 — PEERS & HEARTBEAT
# ══════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### 🌐 Peer Network & Heartbeat")
    st.caption("PayCheck-AI pings all known peers every 30 seconds")

    if st.button("🔄 Refresh Peers", key="ref_peers"): st.rerun()

    if not _mod._peer_store:
        st.markdown("""
        <div style="text-align:center;padding:40px;background:#0f0a1a;
             border-radius:12px;border:1px solid #1e1b4b">
          <div style="font-size:2rem">📡</div>
          <div style="color:#334155;margin-top:8px">
            Waiting for first heartbeat (every 30s)...
          </div>
        </div>""", unsafe_allow_html=True)
    else:
        for url, info in _mod._peer_store.items():
            online = info["status"] == "ONLINE"
            dot    = "heartbeat-dot" if online else "offline-dot"
            color  = "#22c55e" if online else "#ef4444"
            st.markdown(f"""
            <div class="peer-card">
              <div style="display:flex;align-items:center;gap:10px">
                <span class="{dot}"></span>
                <span style="font-weight:700">{info["name"]}</span>
                <span style="color:{color};font-size:0.78rem">{info["status"]}</span>
                <span style="color:#475569;font-size:0.75rem;margin-left:auto">
                  Last seen: {info["last_seen"]}
                </span>
              </div>
              <div style="color:#64748b;font-size:0.75rem;margin-top:6px">
                {url}
                {'  |  Score: ' + str(info.get("score","?")) if online else ""}
                {'  |  Trust: ' + str(info.get("trust","?")) if online else ""}
              </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("#### ⏱️ Heartbeat Log (last 10)")
    hb_events = [e for e in _mod._event_store if e["event_type"] == "HEARTBEAT_OK"][-10:]
    if not hb_events:
        st.info("No heartbeat events yet")
    else:
        for ev in reversed(hb_events):
            st.markdown(f"""
            <div class="event-row">
              <span style="color:#475569;font-family:monospace">{ev["time"]}</span>
              &nbsp;|&nbsp;
              <span class="heartbeat-dot"></span>
              <span style="color:#22c55e">{ev["detail"]}</span>
              &nbsp;|&nbsp;
              <span style="color:#a855f7">+{ev["delta"]} pts</span>
            </div>
            """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# TAB 5 — RECEIVED TASKS (this agent as PROVIDER)
# ══════════════════════════════════════════════════════════════
with tab5:
    st.markdown("### 📥 Tasks Received (PayCheck-AI as Provider)")
    st.markdown("""
    <div style="background:#0a0a1a;border:1px solid #2d1b4e;border-radius:10px;
         padding:14px;margin-bottom:16px;font-size:0.83rem;color:#94a3b8">
      PayCheck-AI also has its own AIP node on port 6002.
      Other agents can discover and delegate PAYMENT_INITIATION tasks to it.
      These are tasks this agent RECEIVED and processed.
    </div>
    """, unsafe_allow_html=True)

    if st.button("🔄 Refresh", key="ref_recv"): st.rerun()

    recv = _mod._received_log
    if not recv:
        st.markdown("""
        <div style="text-align:center;padding:40px;background:#0f0a1a;
             border-radius:12px;border:1px solid #1e1b4b">
          <div style="font-size:2rem">📡</div>
          <div style="color:#334155;margin-top:8px">
            No incoming tasks yet — other agents can call localhost:6002
          </div>
        </div>""", unsafe_allow_html=True)
    else:
        for t in reversed(recv[-20:]):
            approved = t["result"].get("approved", False)
            color    = "#22c55e" if approved else "#ef4444"
            verdict  = "✅ APPROVED" if approved else "🚫 REJECTED"

            st.markdown(f"""
            <div class="{'task-allow' if approved else 'task-block'}"
                 style="background:#0f0a1a;border:2px solid {color}40;
                 border-radius:10px;padding:14px;margin-bottom:10px">
              <div style="display:flex;align-items:center;gap:16px">
                <span style="font-family:monospace;font-size:0.72rem;color:#475569">
                  {t["time"]}
                </span>
                <div style="flex:1">
                  <div style="font-weight:700">
                    {t["task_data"].get("merchant","Unknown")} —
                    ₹{float(t["task_data"].get("amount",0)):,.0f}
                  </div>
                  <div style="color:#64748b;font-size:0.75rem;margin-top:2px">
                    From: {t["from"][:40]}...
                  </div>
                  <div class="receipt-box">
                    AIP/1.0 RECEIPT | task_id: {t["task_id"]}
                    | sig: {t["signature"]}...
                    | {t["result"].get("reason","")}
                  </div>
                </div>
                <span style="color:{color};font-weight:700">{verdict}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)