# dashboard/pages/2_Analysis.py
import streamlit as st
import plotly.express as px
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.analyser import get_summary, HIGH_RISK_COUNTRIES

st.title('🔍 Security Analysis')
st.caption('Detailed findings and recommendations')

df = st.session_state.get('df')
if df is None:
    st.info('No scan data. Run a scan from the main page first.')
    st.stop()

summary = get_summary(df)

# Posture banner
st.markdown(
    f'<div style="background:{summary["colour"]};padding:20px;'
    f'border-radius:10px;text-align:center;">'
    f'<h2 style="color:white;margin:0;">Security Posture: {summary["posture"]}</h2></div>',
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

# Key findings
st.subheader('📋 Key Findings')
findings = []
if len(df[df['service'].isin(['telnet', 'ftp'])]):
    findings.append('🔴 Plaintext protocols detected (telnet/ftp) — credentials sent unencrypted!')
if df['malicious_reports'].gt(0).any():
    n = df[df['malicious_reports'] > 0]['ip'].nunique()
    findings.append(f'🔴 {n} IP(s) flagged as malicious by VirusTotal!')
if len(df[df['service'].isin(['mysql', 'mssql', 'mongodb', 'redis', 'postgresql'])]):
    findings.append('🟠 Database ports exposed — should not be internet-facing!')
if 'country' in df.columns:
    risky = df[df['country'].isin(HIGH_RISK_COUNTRIES)]['ip'].nunique()
    if risky:
        findings.append(f'🟠 {risky} IP(s) from high-risk countries!')
if not findings:
    findings.append('✅ No critical findings detected in this scan.')

for f in findings:
    st.markdown(f'- {f}')
st.divider()

# Recommendations
st.subheader('🚀 What To Do — Priority Actions')
action_df = (
    df.sort_values('risk_score', ascending=False)
      .drop_duplicates(subset=['ip', 'service'])
      [['ip', 'port', 'service', 'risk_score', 'severity', 'recommendation']]
      .head(10)
)
for _, row in action_df.iterrows():
    color = {'Critical': '#dc2626', 'High': '#ea580c',
             'Medium': '#ca8a04',   'Low':  '#16a34a'}.get(row['severity'], '#6b7280')
    with st.expander(
        f"[{row['severity']}] {row['ip']}:{row['port']} ({row['service']}) — Score {row['risk_score']}",
        expanded=row['severity'] in ['Critical', 'High']
    ):
        st.markdown(
            f'<b style="color:{color};">Action:</b> {row["recommendation"]}',
            unsafe_allow_html=True
        )
st.divider()

# Risk Heatmap
st.subheader('🗺️ Risk Heatmap')
if 'exposure_score' in df.columns:
    heat = df.groupby('ip').agg(
        exposure=('exposure_score', 'max'),
        threat  =('threat_score',   'max'),
        risk    =('risk_score',     'max'),
        services=('service', lambda x: ', '.join(sorted(set(x))))
    ).reset_index()
    fig = px.scatter(
        heat, x='exposure', y='threat',
        size='risk', color='risk',
        text='ip', hover_data=['services'],
        color_continuous_scale='RdYlGn_r',
        title='Exposure vs Threat (bigger bubble = higher risk)',
        labels={'exposure': 'Exposure Score', 'threat': 'Threat Score'}
    )
    fig.update_traces(textposition='top center')
    fig.update_layout(height=450)
    st.plotly_chart(fig, use_container_width=True)