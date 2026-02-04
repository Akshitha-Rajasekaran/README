import streamlit as st
import requests
import pandas as pd

st.set_page_config(page_title="PromptShield Dashboard", layout="wide")

st.title("🛡️ PromptShield – Prompt Injection Defense Dashboard")

prompt = st.text_area("Enter a user prompt:")

if st.button("Submit Prompt"):
    response = requests.post(
        "http://localhost:8000/prompt",
        params={"prompt": prompt}
    ).json()

    st.subheader("System Decision")
    st.json(response)

st.divider()

if st.button("View Attack Logs"):
    logs = requests.get("http://localhost:8000/logs").json()
    if logs:
        df = pd.DataFrame(logs)
        st.subheader("Monitoring Logs")
        st.dataframe(df)
    else:
        st.info("No logs yet.")
