# dashboard/pages/3_Scan_Data.py
import streamlit as st

st.title('📊 Raw Scan Data')
st.caption('Full scan results with filters and download')

df = st.session_state.get('df')
if df is None:
    st.info('No scan data. Run a scan from the main page first.')
    st.stop()

# Filters
c1, c2, c3 = st.columns(3)
sev_filter = c1.selectbox('Severity', ['All', 'Critical', 'High', 'Medium', 'Low'])
svc_filter = c2.selectbox('Service',  ['All'] + sorted(df['service'].unique().tolist()))
ip_filter  = c3.selectbox('IP',       ['All'] + sorted(df['ip'].unique().tolist()))

filtered = df.copy()
if sev_filter != 'All': filtered = filtered[filtered['severity'] == sev_filter]
if svc_filter != 'All': filtered = filtered[filtered['service']  == svc_filter]
if ip_filter  != 'All': filtered = filtered[filtered['ip']       == ip_filter]

st.caption(f'Showing {len(filtered)} of {len(df)} records')
st.divider()

cols = ['ip', 'port', 'service', 'product', 'version',
        'risk_score', 'severity', 'country', 'malicious_reports']
show = [c for c in cols if c in filtered.columns]
st.dataframe(filtered[show].sort_values('risk_score', ascending=False),
             use_container_width=True, height=500)

st.divider()
st.download_button('📥 Download CSV', filtered.to_csv(index=False),
                   'cyberscan_results.csv', 'text/csv')