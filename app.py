import os
import streamlit as st
from dotenv import load_dotenv

from cybershield.alerts import SAMPLE_ALERTS, AlertValidationError, normalize_alert
from cybershield.explainer import explain_with_bedrock, template_explanation
from cybershield.policy_decision import DeciderServerClient, MockDecider
from cybershield.workflow import triage

load_dotenv()
st.set_page_config(page_title="CyberShield AI", page_icon="🛡️")
st.title("🛡️ CyberShield AI: SOC Alert Triage")
st.caption("#strands-decider-2b #policy")

mode = st.sidebar.radio("Mode", ["REAL: Decider 2B server + Bedrock", "DEMO/MOCK (not Decider)"])
real = mode.startswith("REAL")
if real:
    url = os.getenv("STRANDS_DECIDER_URL", "http://127.0.0.1:8099")
    st.sidebar.info(f"Decider server: {url}")
    if st.sidebar.button("Check Decider server"):
        try:
            st.sidebar.success(DeciderServerClient(url).health())
        except Exception as e:
            st.sidebar.error(f"Server not reachable: {e}")
else:
    st.error("DEMO/MOCK MODE: results come from simple keyword rules, NOT from Strands Decider 2B or Bedrock.")

sample = st.selectbox("Load a sample alert", ["(custom)"] + list(SAMPLE_ALERTS))
s = SAMPLE_ALERTS.get(sample, {})
title = st.text_input("Title", s.get("title", ""))
desc = st.text_area("Description", s.get("description", ""), height=120)
c1, c2 = st.columns(2)
ip = c1.text_input("Source IP (optional)", s.get("source_ip", ""))
host = c2.text_input("Host (optional)", s.get("host", ""))

if st.button("Triage alert", type="primary"):
    try:
        alert = normalize_alert(title, desc, ip, host)
    except AlertValidationError as e:
        st.warning(str(e))
        st.stop()
    try:
        if real:
            res = triage(alert, DeciderServerClient(url), explain_with_bedrock)
        else:
            res = triage(alert, MockDecider(), lambda a, d: template_explanation(d))
    except Exception as e:
        st.error(f"Triage failed: {type(e).__name__}: {e}")
        st.stop()

    d = res.decision
    st.subheader("1. Policy decision")
    label = "Strands Decider 2B (real)" if d.is_real else "DEMO/MOCK keyword rules (NOT Decider)"
    st.markdown(f"**Source:** {label}")
    st.metric("Severity", d.option)
    if d.confidence == d.confidence:
        st.write(f"Confidence: **{d.confidence:.3f}** ({d.confidence_source})")
    st.write("Option probabilities:", d.probabilities)
    if d.latency_ms:
        st.caption(f"Measured round-trip for this call: {d.latency_ms:.0f} ms (includes HTTP; first call is slower)")

    st.subheader("2. Fixed policy action (written by developers)")
    (st.error if d.option == "HIGH" else st.info)(res.policy_action)

    st.subheader("3. Generated explanation")
    st.caption(f"Status: {res.explanation.status}. This is model-generated text or a template, NOT Decider's reasoning, and is not verified fact.")
    st.write(res.explanation.text)
    if res.explanation.error:
        st.warning(res.explanation.error)
    st.caption(f"Policy gate: tool calls allowed={res.explanation.gate_allowed}, denied={res.explanation.gate_denied}")
    st.success("Audit record appended to audit/audit_log.jsonl")