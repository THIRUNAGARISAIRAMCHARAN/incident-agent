import asyncio, json, os, tempfile, hashlib
import inc_app

TR = "\n".join([f"[ev_{i:02d}] line {i} noise" for i in range(1, 30)])
def req(run="run_abcdef01", eff="scale_service", approval=("rollback_deployment",)):
    return {"profile": "ga5-incident-agent/v2", "runId": run, "agentName": "incident-response", "publicMarker": "mk_PUB_1",
            "sensitive": {"accessToken": "TOK_SECRET_9999", "privateNote": "NOTE_SECRET_8888"},
            "incident": {"incidentId": "i1", "title": "t", "service": "checkout", "severity": "SEV-1", "transcript": TR,
                         "allowedRootCauses": ["bad_deploy", "db_saturation"]},
            "toolCatalog": [
                {"name": "query_metrics", "description": "m", "inputSchema": {"type": "object", "required": ["service"], "properties": {"service": {"type": "string"}}}},
                {"name": "get_logs", "description": "l", "inputSchema": {"type": "object", "required": ["service"], "properties": {"service": {"type": "string"}}}},
                {"name": "scale_service", "description": "s", "inputSchema": {"type": "object"}},
                {"name": "rollback_deployment", "description": "r", "inputSchema": {"type": "object", "required": ["deploymentId"], "properties": {"deploymentId": {"type": "string"}}}}],
            "policy": {"maximumDiagnostics": 3, "effectTools": ["scale_service", "rollback_deployment"],
                       "approvalRequiredFor": list(approval), "doNotExport": ["NOTE_SECRET_8888"]}}

def planner_for(effect):
    def p(prompt, model, timeout):
        assert "TOK_SECRET_9999" not in prompt and "NOTE_SECRET_8888" not in prompt
        e = {"toolName": effect, "arguments": {"deploymentId": "dep-42"} if effect == "rollback_deployment" else {}, "evidence": ["ev_03"]}
        return {"rootCause": "bad_deploy", "evidence": ["ev_03", "ev_07"],
                "diagnostics": [{"toolName": "query_metrics", "arguments": {"service": "checkout"}, "evidence": ["ev_03"]},
                                {"toolName": "get_logs", "arguments": {"service": "checkout"}, "evidence": ["ev_07"]}], "effect": e}
    return p

async def call(app, method, path, body=None, headers=None):
    raw = json.dumps(body).encode() if body is not None else b""
    hs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    out = {}; sent = [False]
    async def recv():
        if sent[0]: return {"type": "http.disconnect"}
        sent[0] = True; return {"type": "http.request", "body": raw, "more_body": False}
    async def send(m):
        if m["type"] == "http.response.start": out["s"] = m["status"]; out["h"] = dict(m["headers"])
        elif m["type"] == "http.response.body": out["b"] = out.get("b", b"") + m["body"]
    await app({"type": "http", "method": method, "path": path, "headers": hs}, recv, send)
    return out["s"], json.loads(out["b"] or b"null"), out["h"]

def mk(effect="scale_service"):
    return inc_app.get_app(tempfile.mktemp(suffix=".db"), planner_for(effect), "test-model")

def ok(c, m):
    assert c, m; print("ok", m)

def outcome(d, status=200, **kw):
    o = {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"], "status": status, "resultClass": "diagnosis_confirmed", "nonce": "n-" + d["actionId"] + str(d["attempt"])}
    if status == 0: o["errorType"] = "timeout"
    o.update(kw); return o

def check_trace(f, run, marker):
    spans = f["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    tid = {s["traceId"] for s in spans}; ok(len(tid) == 1, "single trace id")
    ids = [s["spanId"] for s in spans]; ok(len(set(ids)) == len(ids), "unique span ids")
    by = {s["spanId"]: s for s in spans}
    for s in spans:
        at = {a["key"]: a["value"] for a in s["attributes"]}
        assert at["ga5.run.id"]["stringValue"] == run and at["ga5.public.marker"]["stringValue"] == marker
        if s.get("parentSpanId") and s["kind"] != 2: assert s["parentSpanId"] in by, s["name"]
        assert int(s["startTimeUnixNano"]) <= int(s["endTimeUnixNano"])
        if s.get("parentSpanId") in by:
            p = by[s["parentSpanId"]]
            assert int(p["startTimeUnixNano"]) <= int(s["startTimeUnixNano"]) and int(s["endTimeUnixNano"]) <= int(p["endTimeUnixNano"]), (s["name"], p["name"])
    ok(True, "span nesting/time ok")
    names = [s["name"] for s in spans]
    ok(names.count("chat incident-plan") == 1, "one chat span")
    return spans

async def main():
    # --- full flow with retry + approval ---
    app = mk("rollback_deployment")
    h = {"traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01", "tracestate": "k=v"}
    st, r1, _ = await call(app, "POST", "/v2/incidents", req(), h)
    ok(st == 200 and r1["status"] == "waiting" and len(r1["dispatches"]) == 2 and r1["approvals"] == [], "propose diagnostics")
    d0, d1 = r1["dispatches"]
    ok(d0["traceparent"].startswith("00-" + "a" * 32) and d0["tracestate"] == "k=v", "continues incoming trace")
    ok(d0["traceparent"] != d1["traceparent"], "distinct client spans")
    st, again, _ = await call(app, "POST", "/v2/incidents", req(), h); ok(again == r1, "exact replay equal")
    r = req(); r["publicMarker"] = "other"
    st, _, _ = await call(app, "POST", "/v2/incidents", r); ok(st == 409, "changed content 409")
    st, r2, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_00000001", "outcomes": [outcome(d0, 503), outcome(d1)]})
    ok(st == 200 and r2["status"] == "waiting" and len(r2["dispatches"]) == 1 and r2["dispatches"][0]["attempt"] == 2 and r2["approvals"] == [], "503 -> retry only, no approval")
    ok(r2["dispatches"][0]["actionId"] == d0["actionId"] and r2["dispatches"][0]["traceparent"] != d0["traceparent"], "same action, new span")
    st, rep, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_00000001", "outcomes": [outcome(d0, 503), outcome(d1)]}); ok(rep == r2, "receipt replay equal")
    st, _, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_00000001", "outcomes": [outcome(d0, 200)]}); ok(st == 409, "receipt changed 409")
    st, _, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_bad", "outcomes": [outcome(d1)]}); ok(st == 422, "outcome for non-pending rejected")
    st, _, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_bad2", "outcomes": [outcome(r2["dispatches"][0], attempt=1)]}); ok(st == 422, "wrong attempt rejected")
    st, r3, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_00000002", "outcomes": [outcome(r2["dispatches"][0])]})
    ok(st == 200 and r3["dispatches"] == [] and len(r3["approvals"]) == 1, "approval request, zero effects")
    ap = r3["approvals"][0]
    ok(ap["argumentsDigest"] == hashlib.sha256(b'{"deploymentId":"dep-42"}').hexdigest(), "digest")
    st, g, _ = await call(app, "GET", "/v2/incidents/run_abcdef01"); ok(g["status"] == "waiting" and g["approvals"], "GET waiting")
    st, r4, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_00000003", "approvals": [{"approvalId": ap["approvalId"], "decision": "approved", "nonce": "appr-nonce-1"}]})
    e = r4["dispatches"][0]
    ok(e["toolName"] == "rollback_deployment" and e["approvalId"] == ap["approvalId"] and e["approvalNonce"] == "appr-nonce-1" and e["actionId"] == ap["actionId"], "effect after approval")
    st, f, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_00000004", "outcomes": [outcome(e)]})
    ok(f["status"] == "completed" and "dispatches" in f and f["dispatches"] == [], "completed")
    ok(len(f["actionLog"]) == 4 and len(f["receiptLog"]) == 5, "logs complete (%d,%d)" % (len(f["actionLog"]), len(f["receiptLog"])))
    spans = check_trace(f, "run_abcdef01", "mk_PUB_1")
    names = [s["name"] for s in spans]
    ok(names.count("execute_tool query_metrics") == 1 and names.count("POST tool/query_metrics") == 2, "attempt spans")
    ok(names.count("incident.join") == 1 and names.count("approval_gate") == 1, "join+gate")
    c503 = [s for s in spans if s["name"] == "POST tool/query_metrics" and s["status"]["code"] == 2]
    at = {a["key"]: a["value"] for a in c503[0]["attributes"]}
    ok(at["error.type"]["stringValue"] == "503" and at["http.request.resend_count"]["intValue"] == 0, "503 span")
    ok(next(s for s in spans if s["name"] == "invoke_agent incident-response")["parentSpanId"] == next(s for s in spans if s["kind"] == 2)["spanId"], "agent under server")
    ok(next(s for s in spans if s["kind"] == 2)["parentSpanId"] == "b" * 16, "server span parent = incoming")
    blob = json.dumps(f)
    ok("TOK_SECRET_9999" not in blob and "NOTE_SECRET_8888" not in blob, "no sensitive leak")
    ok("gen_ai.tool.call.arguments" not in blob, "no tool args in trace")
    st, g, _ = await call(app, "GET", "/v2/incidents/run_abcdef01"); ok(g == f, "GET final == final")
    st, rep, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_00000004", "outcomes": [outcome(e)]}); ok(rep == f, "final receipt replay")
    st, _, _ = await call(app, "POST", "/v2/incidents/run_abcdef01/receipts", {"receiptId": "rc_new", "outcomes": [outcome(e)]}); ok(st == 422, "receipt after finish 422")

    # --- timeout suppresses effect ---
    app = mk("scale_service")
    st, r1, _ = await call(app, "POST", "/v2/incidents", req("run_timeout01"))
    ok(r1["approvals"] == [], "no tp: fresh trace")
    d0, d1 = r1["dispatches"]
    st, f, _ = await call(app, "POST", "/v2/incidents/run_timeout01/receipts", {"receiptId": "rc_t0000001", "outcomes": [outcome(d0, 0), outcome(d1)]})
    ok(f["status"] == "failed" and f["suppressed"] == ["scale_service"] and all(a["phase"] == "diagnostic" for a in f["actionLog"]), "timeout -> failed, no effect")
    spans = check_trace(f, "run_timeout01", "mk_PUB_1")
    to = [s for s in spans if s["name"] == "POST tool/" + d0["toolName"]][0]
    ok({a["key"]: a["value"] for a in to["attributes"]}["error.type"]["stringValue"] == "timeout" and to["status"]["code"] == 2, "timeout span")

    # --- direct effect (no approval) ---
    st, r1, _ = await call(app, "POST", "/v2/incidents", req("run_direct01"))
    d0, d1 = r1["dispatches"]
    st, r2, _ = await call(app, "POST", "/v2/incidents/run_direct01/receipts", {"receiptId": "rc_d0000001", "outcomes": [outcome(d0), outcome(d1)]})
    ok(r2["status"] == "waiting" and r2["dispatches"][0]["phase"] == "effect" and r2["approvals"] == [], "effect dispatched directly")
    st, f, _ = await call(app, "POST", "/v2/incidents/run_direct01/receipts", {"receiptId": "rc_d0000002", "outcomes": [outcome(r2["dispatches"][0])]})
    ok(f["status"] == "completed", "completed"); check_trace(f, "run_direct01", "mk_PUB_1")

    # --- validation ---
    for bad, code, m in [({**req("run_bad0001"), "profile": "x"}, 400, "bad profile"), ({**req("run_bad0002"), "toolCatalog": []}, 422, "empty catalog")]:
        st, _, _ = await call(app, "POST", "/v2/incidents", bad); ok(st == code, m)
    st, _, _ = await call(app, "POST", "/v2/incidents/nope/receipts", {"receiptId": "x1", "outcomes": [{}]}); ok(st == 422, "malformed receipt")
    st, _, _ = await call(app, "POST", "/v2/incidents/nope/receipts", {"receiptId": "x1", "outcomes": [outcome(d0)]}); ok(st == 404, "unknown run 404")
    st, _, _ = await call(app, "GET", "/v2/incidents/nope"); ok(st == 404, "GET unknown 404")
    # planner returns a protected value -> retried, then 502 and nothing stored
    def leaky(prompt, model, timeout):
        return {"rootCause": "bad_deploy", "evidence": ["ev_03", "ev_07"], "diagnostics": [{"toolName": "get_logs", "arguments": {"service": "TOK_SECRET_9999"}, "evidence": ["ev_03"]}],
                "effect": {"toolName": "scale_service", "arguments": {}, "evidence": ["ev_03"]}}
    app2 = inc_app.get_app(tempfile.mktemp(suffix=".db"), leaky, "m")
    st, b, _ = await call(app2, "POST", "/v2/incidents", req("run_leak0001")); ok(st == 502 and "SECRET" not in json.dumps(b), "leaky plan refused")
    st, _, _ = await call(app2, "GET", "/v2/incidents/run_leak0001"); ok(st == 404, "nothing created")
    # concurrent same runId -> one model call
    calls = []
    def counting(prompt, model, timeout):
        calls.append(1); return planner_for("scale_service")(prompt, model, timeout)
    app3 = inc_app.get_app(tempfile.mktemp(suffix=".db"), counting, "m")
    rs = await asyncio.gather(*[call(app3, "POST", "/v2/incidents", req("run_conc0001")) for _ in range(5)])
    ok(len(calls) == 1 and all(x[1] == rs[0][1] for x in rs), "concurrent dedupe: one model call")
    st, _, hh = await call(app3, "GET", "/v2/incidents/run_conc0001"); ok(hh[b"content-type"] == b"application/json", "json content-type")
    print("all passed")
asyncio.run(main())
