# dashboard/app.py — Main Streamlit page
# Run: py -m streamlit run dashboard/app.py

import streamlit as st
import pandas as pd
import plotly.express as px
import time, os, sys
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

# Tell Python where to find the modules folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.scanner  import run_nmap_scan, parse_nmap_xml, check_virustotal
from modules.analyser import enrich_dataframe, get_summary
from modules.database import save_scan
from modules.emailer  import send_alert_email

# ── Page setup ────────────────────────────────────────────────────────────────
st.set_page_config(page_title='ThreatScope', page_icon='🛡️', layout='wide')

# ── Load credentials from .env ────────────────────────────────────────────────
VT_KEY       = os.environ.get('VT_API_KEY', '')
GMAIL_SENDER = os.environ.get('GMAIL_SENDER', '')
GMAIL_PASS   = os.environ.get('GMAIL_PASSWORD', '')
ALERT_TO     = os.environ.get('ALERT_EMAIL', '')

# ── Session state ─────────────────────────────────────────────────────────────
if 'df'        not in st.session_state: st.session_state.df        = None
if 'scan_time' not in st.session_state: st.session_state.scan_time = None
if 'last_scan' not in st.session_state: st.session_state.last_scan = None
if 'targets'   not in st.session_state: st.session_state.targets   = []

# ── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.title('🛡️ ThreatScope')
st.sidebar.divider()

# Target input
st.sidebar.subheader('🎯 Scan Target')
target_input = st.sidebar.text_input(
    'Enter target (IP or domain):',
    placeholder='e.g. scanme.nmap.org'
)
if st.sidebar.button('➕ Add Target') and target_input:
    if target_input not in st.session_state.targets:
        st.session_state.targets.append(target_input)

# Show added targets
if st.session_state.targets:
    st.sidebar.caption('Targets:')
    for t in st.session_state.targets:
        c1, c2 = st.sidebar.columns([4, 1])
        c1.caption(f'• {t}')
        if c2.button('❌', key=f'del_{t}'):
            st.session_state.targets.remove(t)
            st.rerun()

st.sidebar.divider()

# Status
if VT_KEY:
    st.sidebar.success('✅ VirusTotal API ready')
else:
    st.sidebar.error('❌ VT_API_KEY missing in .env')

st.sidebar.divider()
scan_btn = st.sidebar.button('🚀 Run Scan', use_container_width=True, type='primary')

# ── Header ────────────────────────────────────────────────────────────────────
st.title('🛡️ ThreatScope')
st.caption('Cyber Risk Assessment & Threat Intelligence Platform')

if st.session_state.last_scan:
    st.info(f'🕐 Last scan: {st.session_state.last_scan}')
else:
    st.info('👈 Add a target and click Run Scan to get started.')

st.divider()

# ── Run scan ──────────────────────────────────────────────────────────────────
if scan_btn:
    if not VT_KEY:
        st.error('❌ Add VT_API_KEY to your .env file first!')
    elif not st.session_state.targets:
        st.error('❌ Add at least one target in the sidebar!')
    else:
        TARGETS  = st.session_state.targets
        bar      = st.progress(0)
        status   = st.empty()
        all_rows = []
        total    = len(TARGETS) * 2

        # Step 1: Nmap scan
        for i, target in enumerate(TARGETS):
            status.info(f'🔍 Scanning {target}...')
            xml  = run_nmap_scan(target)
            rows = parse_nmap_xml(xml)
            all_rows.extend(rows)
            bar.progress((i + 1) / total)

        if not all_rows:
            status.warning('⚠️ No open ports found!')
            st.stop()

        df_raw = pd.DataFrame(all_rows)

        # Step 2: VirusTotal
        vt         = {}
        unique_ips = df_raw['ip'].unique()
        for j, ip in enumerate(unique_ips):
            status.info(f'🦠 Checking VirusTotal: {ip}...')
            vt[ip] = check_virustotal(ip, VT_KEY)
            bar.progress((len(TARGETS) + j + 1) / total)
            if j < len(unique_ips) - 1:
                time.sleep(15)

        # Step 3: Score everything
        status.info('📊 Calculating risk scores...')
        df = enrich_dataframe(df_raw, vt)

        # Step 4: Save to session + database
        st.session_state.df        = df
        st.session_state.scan_time = time.strftime('%Y-%m-%d %H:%M:%S')
        st.session_state.last_scan = datetime.now().strftime('%d %b %Y  %H:%M:%S')
        save_scan(df, TARGETS)

        # Step 5: Send email alert if needed
        if GMAIL_SENDER and GMAIL_PASS and ALERT_TO:
            high = len(df[df['severity'].isin(['High', 'Critical'])])
            if high > 0:
                send_alert_email(GMAIL_SENDER, GMAIL_PASS, ALERT_TO,
                                 df, st.session_state.scan_time)
                status.success(f'✅ Done! Alert email sent for {high} findings.')
            else:
                status.success('✅ Scan complete! No high-risk findings.')
        else:
            status.success('✅ Scan complete!')

        bar.empty()
        st.rerun()

# ── Dashboard ─────────────────────────────────────────────────────────────────
df = st.session_state.df
if df is None:
    st.info('No scan data yet. Add a target and click Run Scan!')
else:
    summary = get_summary(df)

    # Posture banner
    st.markdown(
        f'<div style="background:{summary["colour"]};padding:20px;'
        f'border-radius:10px;text-align:center;">'
        f'<h2 style="color:white;margin:0;">🛡️ {summary["posture"]}</h2></div>',
        unsafe_allow_html=True
    )
    st.divider()

    # KPI cards
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric('🖥️ Hosts',    summary['total_hosts'])
    c2.metric('🔓 Ports',    summary['total_ports'])
    c3.metric('🚨 Critical', summary['critical'])
    c4.metric('⚠️ High',     summary['high'])
    c5.metric('🦠 VT Hits',  summary['vt_flagged'])
    st.divider()

    # Charts
    col1, col2 = st.columns(2)

    with col1:
        st.subheader('📊 Risk by Severity')
        sev_counts = df['severity'].value_counts().reset_index()
        sev_counts.columns = ['Severity', 'Count']
        colors = {'Critical': '#dc2626', 'High': '#ea580c',
                  'Medium': '#d97706',   'Low':  '#16a34a'}
        fig = px.bar(sev_counts, x='Severity', y='Count',
                     color='Severity', color_discrete_map=colors)
        fig.update_layout(showlegend=False, height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader('🌍 Top Services Found')
        svc_counts = df['service'].value_counts().head(8).reset_index()
        svc_counts.columns = ['Service', 'Count']
        fig2 = px.pie(svc_counts, names='Service', values='Count', hole=0.4)
        fig2.update_layout(height=300)
        st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # Top 10 riskiest
    st.subheader('🚨 Top 10 Riskiest Findings')
    top10 = df.nlargest(10, 'risk_score')[
        ['ip', 'port', 'service', 'risk_score', 'severity', 'country', 'malicious_reports']
    ]
    st.dataframe(top10, use_container_width=True)

    st.divider()
    st.info('👈 Use sidebar for Analysis, Raw Data, and History pages.')