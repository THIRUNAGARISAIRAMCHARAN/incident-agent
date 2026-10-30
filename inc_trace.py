"""Build the OTLP trace purely from stored state (no model, no randomness except stored ids)."""


def _a(k, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": v}}
    return {"key": k, "value": {"stringValue": str(v)}}


def build_otlp(st):
    t = st["trace"]
    tid = t["traceId"]
    run, mk = st["runId"], st["marker"]
    base = [_a("ga5.run.id", run), _a("ga5.public.marker", mk)]
    spans = []

    def span(name, kind, sid, parent, start, end, attrs, code=0, links=None, extra=None):
        s = {"traceId": tid, "spanId": sid, "name": name, "kind": kind,
             "startTimeUnixNano": str(start), "endTimeUnixNano": str(max(end, start)),
             "attributes": base + attrs, "status": {"code": code}}
        if parent:
            s["parentSpanId"] = parent
        if links:
            s["links"] = [{"traceId": tid, "spanId": x} for x in links]
        if extra:
            s.update(extra)
        spans.append(s)

    end_all = st.get("endTs") or t["planEnd"]
    server = {"extra": {"traceState": t["tracestate"]}} if t.get("tracestate") else {}
    span("POST /v2/incidents", 2, t["serverSpanId"], t.get("parentSpanId"), t["start"], end_all,
         [_a("http.request.method", "POST"), _a("http.route", "/v2/incidents"), _a("http.response.status_code", 200)],
         extra=server.get("extra"))
    span("invoke_agent " + st["agentName"], 1, t["agentSpanId"], t["serverSpanId"], t["start"], end_all,
         [_a("gen_ai.operation.name", "invoke_agent"), _a("gen_ai.agent.name", st["agentName"])])
    span("chat incident-plan", 3, t["chatSpanId"], t["agentSpanId"], t["planStart"], t["planEnd"],
         [_a("gen_ai.operation.name", "chat"), _a("gen_ai.request.model", st["model"])])

    diag_exec = []
    for aid in st["order"]:
        a = st["actions"][aid]
        atts = a["attempts"]
        start = atts[0]["dispatchTs"]
        end = max((x.get("receipt", {}).get("ts", x["dispatchTs"]) for x in atts), default=start)
        final_ok = a["state"] == "ok"
        pending = a["state"] == "pending"
        xs = a["execSpanId"]
        span("execute_tool " + a["toolName"], 1, xs, t["agentSpanId"], start, end,
             [_a("ga5.action.id", aid), _a("gen_ai.tool.name", a["toolName"]), _a("gen_ai.tool.call.id", a["callId"]),
              _a("gen_ai.operation.name", "execute_tool")],
             code=1 if final_ok else (0 if pending else 2))
        if a["phase"] == "diagnostic":
            diag_exec.append((xs, end))
        for x in atts:
            r = x.get("receipt")
            at = [_a("ga5.action.id", aid), _a("ga5.attempt", x["attempt"]),
                  _a("http.request.method", "POST"), _a("http.request.resend_count", x["attempt"] - 1)]
            code = 0
            if r:
                at += [_a("ga5.receipt.id", r["receiptId"]), _a("ga5.receipt.nonce", r["nonce"]),
                       _a("http.response.status_code", r["status"])]
                if r["status"] == 0 or r["status"] >= 400 or r.get("errorType"):
                    et = "timeout" if r["status"] == 0 else (r.get("errorType") or str(r["status"]))
                    at.append(_a("error.type", et))
                    code = 2
            span("POST tool/" + a["toolName"], 3, x["spanId"], xs, x["dispatchTs"],
                 r["ts"] if r else x["dispatchTs"], at, code=code)
    if len(diag_exec) > 1:
        jstart = max(e for _, e in diag_exec)
        span("incident.join", 1, t["joinSpanId"], t["agentSpanId"], jstart, jstart + 1000,
             [_a("ga5.join.count", len(diag_exec))], links=[x for x, _ in diag_exec])
    for apid, ap in st["approvals"].items():
        if ap["status"] == "pending":
            continue
        span("approval_gate", 1, t["gateSpanId"], t["agentSpanId"], ap["ts0"], ap["ts"],
             [_a("ga5.approval.id", apid), _a("ga5.approval.nonce", ap["nonce"]), _a("ga5.receipt.id", ap["receiptId"]),
              _a("ga5.receipt.nonce", ap["nonce"]), _a("ga5.action.id", ap["actionId"]),
              _a("ga5.approval.decision", ap["status"])])
    return {"resourceSpans": [{"resource": {"attributes": [_a("service.name", st["agentName"])]},
                               "scopeSpans": [{"scope": {"name": "ga5-incident-agent"}, "spans": spans}]}]}
