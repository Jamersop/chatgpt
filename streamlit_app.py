"""Streamlit UI for interactive log summarization."""

from __future__ import annotations

import json

import streamlit as st

from log_extract import summarize_lines

st.set_page_config(page_title="Log Event Summarizer", page_icon="🧾", layout="wide")
st.title("🧾 Log Event Summarizer")
st.caption("Upload a log file to extract key metrics and highlight critical and major events.")

sample_limit = st.sidebar.slider("Sample lines per category", min_value=1, max_value=20, value=5)
uploaded = st.file_uploader("Upload a log file", type=["log", "txt", "out"])

if uploaded is None:
    st.info("Upload a log file to begin.")
    st.stop()

raw_text = uploaded.getvalue().decode("utf-8", errors="replace")
summary = summarize_lines(raw_text.splitlines(), source_name=uploaded.name, sample_limit=sample_limit)

col1, col2, col3 = st.columns(3)
col1.metric("Total lines", summary["total_lines"])
col2.metric("Error/Exception lines", summary["lines_with_error_or_exception"])
col3.metric("Critical events", summary["highlighted_events"]["critical_count"])

st.subheader("Highlighted events")
left, right = st.columns(2)
with left:
    st.markdown("#### 🔴 Critical")
    critical_events = summary["highlighted_events"]["critical"]
    if critical_events:
        for event in critical_events:
            st.code(event)
    else:
        st.write("No critical events detected.")

with right:
    st.markdown("#### 🟠 Major")
    major_events = summary["highlighted_events"]["major"]
    if major_events:
        for event in major_events:
            st.code(event)
    else:
        st.write("No major events detected.")

st.subheader("Top distributions")
tab1, tab2, tab3, tab4 = st.tabs(["Levels", "Users", "IPs", "Error codes"])

with tab1:
    st.json(summary["top_log_levels"])
with tab2:
    st.json(summary["top_users"])
with tab3:
    st.json(summary["top_ips"])
with tab4:
    st.json(summary["error_codes"])

st.subheader("JSON summary")
st.download_button(
    "Download summary JSON",
    data=json.dumps(summary, indent=2),
    file_name=f"{uploaded.name}.summary.json",
    mime="application/json",
)
st.json(summary)
