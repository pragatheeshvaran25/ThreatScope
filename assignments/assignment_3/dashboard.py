"""
dashboard.py
Simple Vulnerability Scanner Dashboard
Run: python -m streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import os
from dotenv import load_dotenv
from datetime import datetime

from scanner import scan_website
from alerts import send_alert

# ── Load email credentials from .env ─────────────────────────────────────────
load_dotenv()
SENDER    = os.getenv("GMAIL_SENDER", "")
PASSWORD  = os.getenv("GMAIL_PASSWORD", "")
RECIPIENT = os.getenv("GMAIL_RECIPIENT", "")

# ── Page setup ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VulnScan",
    page_icon="🛡️",
    layout="wide"
)

# ── Colors for each severity ──────────────────────────────────────────────────
SEV_COLORS = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#d97706",
    "Low":      "#16a34a",
}

# ── Session state — remembers results between clicks ─────────────────────────
if "findings" not in st.session_state:
    st.session_state["findings"] = None
if "url" not in st.session_state:
    st.session_state["url"] = None
if "email_sent" not in st.session_state:
    st.session_state["email_sent"] = None

# ════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ════════════════════════════════════════════════════════════════════════════
st.sidebar.title("🛡️ VulnScan")
st.sidebar.markdown("Web Vulnerability Scanner")
st.sidebar.divider()

# Target URL input
st.sidebar.subheader("🎯 Target")
SAFE_TARGETS = [
    "Type your own URL...",
    "http://testphp.vulnweb.com/artists.php",
    "http://zero.webappsecurity.com",
    "http://testphp.vulnweb.com",
]

selected = st.sidebar.selectbox("Choose target", SAFE_TARGETS)

if selected == "Type your own URL...":
    url = st.sidebar.text_input("Enter URL", placeholder="http://example.com")
else:
    url = selected
    st.sidebar.info(f"Selected: {url}")

st.sidebar.divider()

# Email status
st.sidebar.subheader("📧 Email Status")
if SENDER and PASSWORD and RECIPIENT:
    st.sidebar.success("Email ready ✅")
else:
    st.sidebar.warning("Email not set in .env")

st.sidebar.divider()

# Scan button
scan_btn = st.sidebar.button(
    "🚀 Start Scan",
    type="primary",
    use_container_width=True
)

# ════════════════════════════════════════════════════════════════════════════
#  HEADER
# ════════════════════════════════════════════════════════════════════════════
st.title("🛡️ VulnScan")
st.caption("Web Application Vulnerability Scanner")
st.divider()

# ════════════════════════════════════════════════════════════════════════════
#  RUN SCAN WHEN BUTTON CLICKED
# ════════════════════════════════════════════════════════════════════════════
if scan_btn:
    if not url:
        st.error("❌ Please enter a URL first!")
    else:
        # Show progress
        progress = st.progress(0)
        status   = st.empty()

        status.info(f"🔍 Scanning {url}...")
        progress.progress(20)

        # Run the scan
        scanned_url, findings = scan_website(url)
        progress.progress(80)

        # Save results to session state
        st.session_state["findings"] = findings
        st.session_state["url"]      = scanned_url

        # AUTO SEND EMAIL if Critical/High found
        status.info("📧 Checking if email alert needed...")
        progress.progress(90)

        if SENDER and PASSWORD and RECIPIENT:
            sent = send_alert(scanned_url, findings, SENDER, PASSWORD, RECIPIENT)
            st.session_state["email_sent"] = sent
        else:
            st.session_state["email_sent"] = False

        progress.progress(100)
        progress.empty()
        status.empty()

        st.rerun()

# ════════════════════════════════════════════════════════════════════════════
#  SHOW RESULTS
# ════════════════════════════════════════════════════════════════════════════
findings = st.session_state["findings"]
url      = st.session_state["url"]

# If no scan done yet — show welcome message
if findings is None:
    st.info("👈 Enter a URL in the sidebar and click Start Scan!")
    st.markdown("### 🧪 Safe test websites:")
    st.success("✅ http://testphp.vulnweb.com")
    st.success("✅ http://zero.webappsecurity.com")

else:
    # ── Email alert status ────────────────────────────────────────────────────
    if st.session_state["email_sent"] is True:
        st.success("📧 Alert email automatically sent!")
    elif st.session_state["email_sent"] is False:
        serious = [f for f in findings if f["severity"] in ["Critical", "High"]]
        if serious and not (SENDER and PASSWORD and RECIPIENT):
            st.warning("📧 Email not configured — add Gmail details to .env")
        elif not serious:
            st.info("📧 No Critical/High issues — email not needed")

    # ── KPI Cards ─────────────────────────────────────────────────────────────
    st.subheader(f"📊 Scan Results for: `{url}`")

    critical = len([f for f in findings if f["severity"] == "Critical"])
    high     = len([f for f in findings if f["severity"] == "High"])
    medium   = len([f for f in findings if f["severity"] == "Medium"])
    low      = len([f for f in findings if f["severity"] == "Low"])
    total    = sum(f["score"] for f in findings)

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("🔴 Critical", critical)
    k2.metric("🟠 High",     high)
    k3.metric("🟡 Medium",   medium)
    k4.metric("🟢 Low",      low)
    k5.metric("📊 Total Score", total)

    st.divider()

    if not findings:
        st.success("✅ No vulnerabilities found! Website looks secure.")
    else:
        # ── Tabs ──────────────────────────────────────────────────────────────
        tab1, tab2, tab3 = st.tabs([
            "📋 All Findings",
            "📈 Charts",
            "🚨 Critical & High"
        ])

        # ── TAB 1 — All Findings ──────────────────────────────────────────────
        with tab1:
            st.subheader("📋 All Vulnerabilities Found")

            for finding in findings:
                color = SEV_COLORS.get(finding["severity"], "#6b7280")

                with st.expander(
                    f"{finding['severity']} — {finding['name']} (Score: {finding['score']}/10)",
                    expanded=finding["severity"] == "Critical"
                ):
                    st.markdown(f"**Severity:** {finding['severity']}")
                    st.markdown(f"**Score:** {finding['score']}/10")
                    st.markdown(f"**What was found:** {finding['description']}")
                    st.markdown(f"**How to fix:** {finding['fix']}")

        # ── TAB 2 — Charts ────────────────────────────────────────────────────
        with tab2:
            st.subheader("📈 Vulnerability Charts")

            df = pd.DataFrame(findings)

            c1, c2 = st.columns(2)

            with c1:
                # Severity pie chart
                sev_counts = df["severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                fig1 = px.pie(
                    sev_counts,
                    names="Severity",
                    values="Count",
                    title="Issues by Severity",
                    color="Severity",
                    color_discrete_map=SEV_COLORS,
                    hole=0.4
                )
                st.plotly_chart(fig1, use_container_width=True)

            with c2:
                # Risk score bar chart
                fig2 = px.bar(
                    df.sort_values("score", ascending=True),
                    x="score",
                    y="name",
                    orientation="h",
                    title="Risk Score per Vulnerability",
                    color="severity",
                    color_discrete_map=SEV_COLORS,
                    text="score"
                )
                fig2.update_traces(textposition="outside")
                st.plotly_chart(fig2, use_container_width=True)

        # ── TAB 3 — Critical & High ───────────────────────────────────────────
        with tab3:
            st.subheader("🚨 Critical & High Issues")

            serious = [f for f in findings if f["severity"] in ["Critical", "High"]]

            if not serious:
                st.success("✅ No Critical or High vulnerabilities!")
            else:
                st.error(f"⚠️ {len(serious)} serious issues need immediate attention!")

                for finding in serious:
                    color = SEV_COLORS.get(finding["severity"], "#6b7280")
                    st.markdown(f"""
                    <div style="background:#1a1a1a;border-left:4px solid {color};
                                padding:15px;border-radius:4px;margin-bottom:10px">
                        <strong style="color:{color}">{finding['severity']}: {finding['name']}</strong><br>
                        <span style="color:#9ca3af">{finding['description']}</span><br>
                        <span style="color:#60a5fa">💡 Fix: {finding['fix']}</span>
                    </div>
                    """, unsafe_allow_html=True)

                # Export button
                st.divider()
                serious_df = pd.DataFrame(serious)
                st.download_button(
                    "⬇️ Download Critical/High Report",
                    data=serious_df.to_csv(index=False).encode(),
                    file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

st.divider()
st.caption("🛡️ VulnScan — Infosys Springboard 6.0 | Only scan authorized websites!")