# dashboard/pages/4_History.py
import streamlit as st
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.database import load_history, load_scan_by_id

st.title('📜 Scan History')
st.caption('View all past scans saved in the database')

history = load_history()
if history.empty:
    st.info('No scan history yet. Run your first scan!')
    st.stop()

st.dataframe(history, use_container_width=True)
st.divider()

st.subheader('🔄 Reload a Past Scan')
scan_id = st.selectbox('Select scan to reload:', history['id'].tolist())

if st.button('Load This Scan'):
    old = load_scan_by_id(scan_id)
    if not old.empty:
        st.session_state.df = old
        st.success(f'✅ Scan #{scan_id} loaded! Go to Analysis page.')
    else:
        st.error('Could not load that scan.')