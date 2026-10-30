"""Incident agent: persistent run API + receipt-driven state machine. Pure ASGI, SQLite, no redirects."""
import asyncio, hashlib, json, os, re, secrets, sqlite3, threading, time

import inc_plan
from inc_trace import build_otlp

PROFILE = "ga5-incident-agent/v2"
MAX_BODY = 4 * 1024 * 1024
MAX_RESP = 700 * 1024
TP_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(x):
    return hashlib.sha256(canon(x).encode()).hexdigest()


def hid(n):
    while True:
        v = secrets.token_hex(n)
        if int(v, 16):
            return v


def now():
    return time.time_ns()


class Err(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


class DB:
    def __init__(self, path):
        self.c = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA synchronous=NORMAL")
        self.c.execute("CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, req_hash TEXT, state TEXT, first TEXT)")
        self.c.execute("CREATE TABLE IF NOT EXISTS receipts(receipt_id TEXT PRIMARY KEY, run_id TEXT, hash TEXT, resp TEXT)")
        self.lk = threading.RLock()

    def get_run(self, rid):
        with self.lk:
            r = self.c.execute("SELECT req_hash,state,first FROM runs WHERE run_id=?", (rid,)).fetchone()
        return (r[0], json.loads(r[1]), json.loads(r[2])) if r else None

    def put_run(self, rid, h, st, first):
        with self.lk:
            self.c.execute("INSERT INTO runs VALUES(?,?,?,?)", (rid, h, json.dumps(st), json.dumps(first)))

    def get_receipt(self, rcid):
        with self.lk:
            r = self.c.execute("SELECT run_id,hash,resp FROM receipts WHERE receipt_id=?", (rcid,)).fetchone()
        return (r[0], r[1], json.loads(r[2])) if r else None

    def commit_receipt(self, rid, st, rcid, h, resp):
        with self.lk:
            self.c.execute("BEGIN IMMEDIATE")
            try:
                self.c.execute("UPDATE runs SET state=? WHERE run_id=?", (json.dumps(st), rid))
                self.c.execute("INSERT INTO receipts VALUES(?,?,?,?)", (rcid, rid, h, json.dumps(resp)))
                self.c.execute("COMMIT")
            except Exception:
                self.c.execute("ROLLBACK")
                raise


# ---------------- request validation ----------------
def _s(x, lo=1, hi=500):
    return isinstance(x, str) and lo <= len(x) <= hi


def validate_incident(b):
    if not isinstance(b, dict):
        raise Err(400, "body must be an object")
    if b.get("profile") != PROFILE:
        raise Err(400, "unsupported profile")
    if not _s(b.get("runId"), 1, 200) or not _s(b.get("agentName"), 1, 200) or not _s(b.get("publicMarker"), 1, 500):
        raise Err(422, "invalid runId/agentName/publicMarker")
    if not isinstance(b.get("sensitive"), dict):
        raise Err(422, "sensitive must be an object")
    inc = b.get("incident")
    if not isinstance(inc, dict) or not _s(inc.get("transcript"), 1, 2_000_000):
        raise Err(422, "invalid incident")
    ar = inc.get("allowedRootCauses")
    if not isinstance(ar, list) or not ar or not all(_s(x, 1, 300) for x in ar):
        raise Err(422, "invalid allowedRootCauses")
    cat = b.get("toolCatalog")
    if not isinstance(cat, list) or not cat:
        raise Err(422, "invalid toolCatalog")
    names = set()
    for t in cat:
        if not isinstance(t, dict) or not _s(t.get("name"), 1, 200) or t["name"] in names:
            raise Err(422, "invalid toolCatalog entry")
        if "inputSchema" in t and not isinstance(t["inputSchema"], dict):
            raise Err(422, "invalid inputSchema")
        names.add(t["name"])
    p = b.get("policy")
    if not isinstance(p, dict):
        raise Err(422, "invalid policy")
    md = p.get("maximumDiagnostics")
    if not isinstance(md, int) or isinstance(md, bool) or md < 1:
        raise Err(422, "invalid maximumDiagnostics")
    for k in ("effectTools", "approvalRequiredFor", "doNotExport"):
        if not isinstance(p.get(k), list) or not all(isinstance(x, str) for x in p[k]):
            raise Err(422, f"invalid policy.{k}")
    if not p["effectTools"] or any(x not in names for x in p["effectTools"]):
        raise Err(422, "effectTools must be in toolCatalog")
    if all(n in p["effectTools"] for n in names):
        raise Err(422, "toolCatalog has no diagnostic tool")
    return b


def validate_receipt(b):
    if not isinstance(b, dict) or not _s(b.get("receiptId"), 1, 300):
        raise Err(422, "invalid receipt")
    outs, apps = b.get("outcomes", []), b.get("approvals", [])
    if not isinstance(outs, list) or not isinstance(apps, list) or not (outs or apps):
        raise Err(422, "receipt needs outcomes or approvals")
    seen = set()
    for o in outs:
        if not isinstance(o, dict) or not all(_s(o.get(k), 1, 300) for k in ("actionId", "callId", "nonce")):
            raise Err(422, "invalid outcome")
        if not isinstance(o.get("attempt"), int) or isinstance(o.get("attempt"), bool) or o["attempt"] < 1:
            raise Err(422, "invalid attempt")
        if not isinstance(o.get("status"), int) or isinstance(o.get("status"), bool) or o["status"] < 0 or o["status"] > 599:
            raise Err(422, "invalid status")
        if o["status"] == 0 and o.get("errorType") != "timeout":
            raise Err(422, "status 0 needs errorType timeout")
        if "errorType" in o and not isinstance(o["errorType"], str):
            raise Err(422, "invalid errorType")
        if o["actionId"] in seen:
            raise Err(422, "duplicate outcome")
        seen.add(o["actionId"])
    for a in apps:
        if not isinstance(a, dict) or not all(_s(a.get(k), 1, 300) for k in ("approvalId", "decision", "nonce")):
            raise Err(422, "invalid approval")
    return b


# ---------------- state machine ----------------
def new_ids(run, tag):
    h = hashlib.sha256(f"{run}|{tag}".encode()).hexdigest()
    return h[:16]


def make_dispatch(st, aid, extra=None):
    a = st["actions"][aid]
    cur = a["attempts"][-1]
    t = st["trace"]
    d = {"actionId": aid, "callId": a["callId"], "phase": a["phase"], "toolName": a["toolName"],
         "arguments": a["arguments"], "evidence": a["evidence"], "attempt": cur["attempt"],
         "traceparent": f"00-{t['traceId']}-{cur['spanId']}-01"}
    if t.get("tracestate"):
        d["tracestate"] = t["tracestate"]
    if a.get("approvalId"):
        d["approvalId"] = a["approvalId"]
        d["approvalNonce"] = st["approvals"][a["approvalId"]]["nonce"]
    st["actionLog"].append(d)
    return d


def add_action(st, tag, phase, c):
    run = st["runId"]
    aid, cid = "act_" + new_ids(run, tag + "a"), "call_" + new_ids(run, tag + "c")
    st["actions"][aid] = {"callId": cid, "phase": phase, "toolName": c["toolName"], "arguments": c["arguments"],
                          "evidence": c["evidence"], "state": "pending", "execSpanId": hid(8),
                          "attempts": [{"attempt": 1, "spanId": hid(8), "dispatchTs": now()}]}
    st["order"].append(aid)
    return aid


def base_view(st):
    return {"runId": st["runId"], "diagnosis": st["diagnosis"]}


def waiting(st, dispatches, approvals):
    v = base_view(st)
    v.update({"status": "waiting", "dispatches": dispatches, "approvals": approvals})
    return v


def finalize(st, status):
    st["status"], st["phase"], st["endTs"] = status, "done", now()
    return finalize_view(st)


def advance(st, new_disp):
    """Decide the next response after state changed. Mutates st."""
    pend = [a for a in st["order"] if st["actions"][a]["state"] == "pending"]
    if pend:
        return waiting(st, new_disp, [])
    eff = st["plan"]["effect"]
    if st["phase"] == "diagnostics":
        if any(st["actions"][a]["state"] == "failed" for a in st["order"]):
            st["suppressed"] = [eff["toolName"]]
            return finalize(st, "failed")
        aid = "act_" + new_ids(st["runId"], "effa")
        st["effectActionId"] = aid
        if eff["toolName"] in st["policy"]["approvalRequiredFor"]:
            apid = "apr_" + new_ids(st["runId"], "apr")
            req = {"approvalId": apid, "actionId": aid, "toolName": eff["toolName"], "argumentsDigest": sha(eff["arguments"])}
            st["approvals"][apid] = {"actionId": aid, "status": "pending", "req": req, "ts0": now(), "nonce": None, "receiptId": None, "ts": None}
            st["phase"] = "approval"
            return waiting(st, [], [req])
        return dispatch_effect(st, None)
    if st["phase"] == "approval":
        ap = next(iter(st["approvals"].values()))
        if ap["status"] == "approved":
            return dispatch_effect(st, next(iter(st["approvals"])))
        st["suppressed"] = [eff["toolName"]]
        return finalize(st, "failed")
    if st["phase"] == "effect":
        return finalize(st, "completed" if st["actions"][st["effectActionId"]]["state"] == "ok" else "failed")
    raise Err(422, "invalid state")


def dispatch_effect(st, apid):
    eff = st["plan"]["effect"]
    aid = st["effectActionId"]
    run = st["runId"]
    st["actions"][aid] = {"callId": "call_" + new_ids(run, "effc"), "phase": "effect", "toolName": eff["toolName"],
                          "arguments": eff["arguments"], "evidence": eff["evidence"], "state": "pending",
                          "execSpanId": hid(8), "approvalId": apid,
                          "attempts": [{"attempt": 1, "spanId": hid(8), "dispatchTs": now()}]}
    st["order"].append(aid)
    st["phase"] = "effect"
    return waiting(st, [make_dispatch(st, aid)], [])


def apply_receipt(st, b):
    """Validate everything first, then mutate. Raises Err before any mutation."""
    if st["status"] != "waiting":
        raise Err(422, "run already finished")
    outs, apps = b.get("outcomes", []), b.get("approvals", [])
    for o in outs:
        a = st["actions"].get(o["actionId"])
        if not a or a["callId"] != o["callId"] or a["state"] != "pending" or a["attempts"][-1]["attempt"] != o["attempt"]:
            raise Err(422, "outcome does not match a pending call")
    for x in apps:
        ap = st["approvals"].get(x["approvalId"])
        if not ap or ap["status"] != "pending":
            raise Err(422, "no such pending approval")
        if x["decision"] not in ("approved", "denied", "rejected"):
            raise Err(422, "invalid decision")
    ts = now()
    new_disp = []
    for o in outs:
        a = st["actions"][o["actionId"]]
        cur = a["attempts"][-1]
        rc = {"receiptId": b["receiptId"], "actionId": o["actionId"], "callId": o["callId"], "attempt": o["attempt"],
              "status": o["status"], "resultClass": o.get("resultClass"), "nonce": o["nonce"]}
        if o.get("errorType"):
            rc["errorType"] = o["errorType"]
        st["receiptLog"].append(rc)
        cur["receipt"] = dict(rc, ts=ts)
        if 200 <= o["status"] < 300:
            a["state"] = "ok"
        elif o["status"] == 503 and o["attempt"] == 1:
            a["attempts"].append({"attempt": 2, "spanId": hid(8), "dispatchTs": now()})
            new_disp.append(make_dispatch(st, o["actionId"]))
        else:
            a["state"] = "failed"
    for x in apps:
        ap = st["approvals"][x["approvalId"]]
        ap.update(status="approved" if x["decision"] == "approved" else "denied", nonce=x["nonce"],
                  receiptId=b["receiptId"], ts=ts)
        st["receiptLog"].append({"receiptId": b["receiptId"], "approvalId": x["approvalId"], "decision": x["decision"], "nonce": x["nonce"]})
    return advance(st, new_disp)


# ---------------- planning ----------------
def make_plan(req, planner, model):
    t0 = time.monotonic()
    fb = None
    last = None
    for attempt in range(2):
        left = 14.0 - (time.monotonic() - t0)
        if left < 3:
            break
        try:
            raw = planner(inc_plan.model_prompt(req, fb), model, min(left - 1, 11.0))
            return inc_plan.validate_plan(raw, req)
        except ValueError as e:
            fb, last = str(e)[:300], e
        except Exception as e:  # network / parse
            last = e
            fb = None
    raise Err(502, "planner unavailable")


def parse_tp(headers, body):
    tp = headers.get("traceparent") or body.get("traceparent")
    ts = headers.get("tracestate") or body.get("tracestate")
    if isinstance(tp, str):
        m = TP_RE.match(tp.strip())
        if m and int(m.group(1), 16) and int(m.group(2), 16):
            return m.group(1), m.group(2), (ts.strip() if isinstance(ts, str) and ts.strip() else None)
    return hid(16), None, None


class Service:
    def __init__(self, db, planner=None, model=None):
        self.db = db
        self.planner = planner or inc_plan.call_llm
        self.model = model or os.environ.get("MODEL", "gpt-4.1-mini")
        self.locks = {}
        self.sem = asyncio.Semaphore(8)

    def lock(self, key):
        return self.locks.setdefault(key, asyncio.Lock())

    async def create(self, body, headers):
        req = validate_incident(body)
        rid = req["runId"]
        h = sha(req)
        async with self.lock("run:" + rid):
            row = self.db.get_run(rid)
            if row:
                if row[0] != h:
                    raise Err(409, "runId already used with different content")
                return 200, row[2]
            async with self.sem:
                t_plan0 = now()
                plan = await asyncio.to_thread(make_plan, req, self.planner, self.model)
                t_plan1 = now()
            tid, parent, tstate = parse_tp(headers, body)
            st = {"runId": rid, "marker": req["publicMarker"], "agentName": req["agentName"], "model": self.model,
                  "status": "waiting", "phase": "diagnostics", "policy": {"approvalRequiredFor": req["policy"]["approvalRequiredFor"]},
                  "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]}, "plan": plan,
                  "actions": {}, "order": [], "actionLog": [], "receiptLog": [], "approvals": {}, "suppressed": [],
                  "trace": {"traceId": tid, "parentSpanId": parent, "tracestate": tstate, "serverSpanId": hid(8),
                            "agentSpanId": hid(8), "chatSpanId": hid(8), "joinSpanId": hid(8), "gateSpanId": hid(8),
                            "start": t_plan0 - 2_000_000, "planStart": t_plan0, "planEnd": t_plan1}}
            aids = [add_action(st, f"d{i}", "diagnostic", c) for i, c in enumerate(plan["diagnostics"])]
            disp = [make_dispatch(st, a) for a in aids]
            resp = waiting(st, disp, [])
            self.db.put_run(rid, h, st, resp)
            return 200, resp

    async def receipt(self, rid, body):
        b = validate_receipt(body)
        h = sha(b)
        async with self.lock("run:" + rid):
            row = self.db.get_run(rid)
            if not row:
                raise Err(404, "unknown run")
            prev = self.db.get_receipt(b["receiptId"])
            if prev:
                if prev[0] != rid or prev[1] != h:
                    raise Err(409, "receiptId already used with different content")
                return 200, prev[2]
            st = row[1]
            resp = apply_receipt(st, b)
            self.db.commit_receipt(rid, st, b["receiptId"], h, resp)
            return 200, resp

    def get(self, rid):
        row = self.db.get_run(rid)
        if not row:
            raise Err(404, "unknown run")
        st = row[1]
        if st["status"] != "waiting":
            return 200, finalize_view(st)
        v = waiting(st, [], [ap["req"] for ap in st["approvals"].values() if ap["status"] == "pending"])
        v["dispatches"] = [d for d in st["actionLog"] if st["actions"][d["actionId"]]["state"] == "pending"
                           and st["actions"][d["actionId"]]["attempts"][-1]["attempt"] == d["attempt"]]
        v["actionLog"], v["receiptLog"] = st["actionLog"], st["receiptLog"]
        return 200, v


def finalize_view(st):
    v = base_view(st)
    v.update({"status": st["status"], "chosenEffect": st["plan"]["effect"]["toolName"], "suppressed": st["suppressed"],
              "actionLog": st["actionLog"], "receiptLog": st["receiptLog"], "otlp": build_otlp(st),
              "dispatches": [], "approvals": []})
    return v


# ---------------- ASGI ----------------
CORS = [(b"access-control-allow-origin", b"*"), (b"access-control-allow-methods", b"GET,POST,OPTIONS"),
        (b"access-control-allow-headers", b"*"), (b"access-control-expose-headers", b"*")]


def get_app(db_path=None, planner=None, model=None):
    svc = Service(DB(db_path or os.environ.get("DB_PATH", "/tmp/incident.db")), planner, model)

    async def reply(send, code, obj):
        data = json.dumps(obj, separators=(",", ":")).encode()
        if len(data) > MAX_RESP:
            code, data = 500, b'{"error":"response too large"}'
        await send({"type": "http.response.start", "status": code,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode()),
                                (b"cache-control", b"no-store")] + CORS})
        await send({"type": "http.response.body", "body": data})

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                m = await receive()
                if m["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        method = scope["method"]
        path = re.sub(r"/+", "/", scope["path"])
        i = path.find("/v2/incidents")
        sub = path[i:].rstrip("/") if i >= 0 else path
        headers = {k.decode().lower(): v.decode("latin-1") for k, v in scope["headers"]}
        try:
            if method == "OPTIONS":
                await send({"type": "http.response.start", "status": 204, "headers": CORS})
                await send({"type": "http.response.body", "body": b""})
                return
            if sub in ("", "/healthz") or path in ("/", "/healthz"):
                return await reply(send, 200, {"ok": True})
            m = re.fullmatch(r"/v2/incidents(?:/([^/]+)(/receipts)?)?", sub)
            if not m:
                raise Err(404, "not found")
            rid, rcp = m.group(1), m.group(2)
            if method == "GET" and rid and not rcp:
                return await reply(send, *svc.get(rid))
            if method != "POST" or (rid is None and rcp):
                raise Err(405, "method not allowed")
            body = b""
            while True:
                msg = await receive()
                body += msg.get("body", b"")
                if len(body) > MAX_BODY:
                    raise Err(413, "body too large")
                if not msg.get("more_body"):
                    break
            try:
                data = json.loads(body)
            except Exception:
                raise Err(400, "invalid JSON")
            if rid is None:
                return await reply(send, *await svc.create(data, headers))
            if not rcp:
                raise Err(405, "method not allowed")
            return await reply(send, *await svc.receipt(rid, data))
        except Err as e:
            await reply(send, e.code, {"error": e.msg})
        except Exception:
            await reply(send, 500, {"error": "internal error"})

    app.service = svc
    return app
