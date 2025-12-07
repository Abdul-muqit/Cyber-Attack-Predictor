import streamlit as st
import pandas as pd
import numpy as np
import joblib

# ===============================
# LOAD MODEL & SCALER
# ===============================
model = joblib.load("rf_model_new1.pkl")
scaler = joblib.load("scaler_new.pkl")
all_features = joblib.load("scaler_columns.pkl")  # all columns used during training

# ===============================
# TOP 10 FEATURES & SLIDER INFO
# ===============================
top_features_info = {
    "fwd_last_window_size": {
        "label": "Forward Last Window Size",
        "min": 0, "max": 65535, "default": 1024,
        "help": "Size of the last chunk of data sent. Large/unusual sizes may indicate malicious traffic."
    },
    "fwd_PSH_flag_count": {
        "label": "Forward PSH Flag Count",
        "min": 0, "max": 1000, "default": 0,
        "help": "Counts packets marked urgent (PSH flag). High counts could suggest rapid or aggressive traffic."
    },
    "fwd_header_size_min": {
        "label": "Forward Header Size (Min)",
        "min": 0, "max": 1500, "default": 60,
        "help": "Smallest size of packet headers sent. Abnormal sizes could be suspicious."
    },
    "fwd_URG_flag_count": {
        "label": "Forward URG Flag Count",
        "min": 0, "max": 100, "default": 0,
        "help": "Counts packets marked urgent (URG flag). Too many urgent packets may indicate attacks."
    },
    "flow_pkts_payload.max": {
        "label": "Flow Packets Payload (Max)",
        "min": 0, "max": 65535, "default": 0,
        "help": "Largest amount of data in a single packet. Very large packets may indicate system flooding."
    },
    "flow_FIN_flag_count": {
        "label": "Flow FIN Flag Count",
        "min": 0, "max": 100, "default": 0,
        "help": "Counts packets signaling connection end. Unusual patterns can indicate probing or attacks."
    },
    "fwd_init_window_size": {
        "label": "Forward Initial Window Size",
        "min": 0, "max": 65535, "default": 1024,
        "help": "Size of the first data window sent when connection starts. Abnormal sizes can be suspicious."
    },
    "fwd_pkts_payload.avg": {
        "label": "Forward Packets Payload (Avg)",
        "min": 0, "max": 65535, "default": 0,
        "help": "Average packet size sent. Too high or low may indicate abnormal traffic."
    },
    "flow_iat.min": {
        "label": "Flow IAT (Min)",
        "min": 0, "max": 10000, "default": 0,
        "help": "Minimum time gap between packets. Very short gaps may indicate automated attacks."
    },
    "fwd_pkts_payload.min": {
        "label": "Forward Packets Payload (Min)",
        "min": 0, "max": 65535, "default": 0,
        "help": "Smallest packet size. Tiny packets can be used to probe systems or bypass checks."
    }
}

# ===============================
# APP HEADER
# ===============================
st.title("Cyber Attack Prediction System")
st.write("""
This application predicts whether a network connection is **Normal** or an **Attack**
based on key traffic features extracted from the RT-IoT2022 dataset.
""")

# ===============================
# FEATURE INPUTS (SIDEBAR)
# ===============================
st.sidebar.header("Input Traffic Features")

user_data = {}
for key, info in top_features_info.items():
    value = st.sidebar.slider(
        info["label"],
        min_value=info["min"],
        max_value=info["max"],
        value=info["default"],
        help=info["help"]  # Tooltip shown when hovering
    )
    user_data[key] = value

# Convert to DataFrame and fill missing features
input_df = pd.DataFrame([user_data])
input_df = input_df.reindex(columns=all_features, fill_value=0)

# ===============================
# PREDICT BUTTON
# ===============================
if st.button("Predict"):
    # Scale input
    scaled_input = scaler.transform(input_df)
    # Make prediction
    prediction = model.predict(scaled_input)[0]

    # Display result
    st.subheader("Prediction Result")
    st.write("###  The system predicts this connection as:")

    if prediction == 1:
        st.error(" **CYBER ATTACK DETECTED!**")
    else:
        st.success(" **Normal Traffic**")

    # Show user input (only top features)
    st.subheader("Your Input Data")
    st.dataframe(input_df[[key for key in top_features_info.keys()]])