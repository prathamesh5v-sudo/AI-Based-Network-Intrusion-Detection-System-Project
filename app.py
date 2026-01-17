import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
from groq import Groq

# --- PAGE SETUP ---
st.set_page_config(page_title="AI-NIDS Student Project", layout="wide")

st.title("AI-Based Network Intrusion Detection System")
st.markdown("""
**Student Project**: This system uses **Random Forest** to detect Network attacks and **Groq AI** to explain the packets.
""")

# --- SIDEBAR: SETTINGS ---
st.sidebar.header("1. Settings")
groq_api_key = st.sidebar.text_input("Groq API Key (starts with gsk_)", type="password")
st.sidebar.caption("[Get a free key here](https://console.groq.com/keys)")

# --- DATASET HANDLING ---
st.sidebar.header("2. Dataset Selection")

dataset_option = st.sidebar.selectbox(
    "Choose a dataset",
    [
        "Upload your own",
        "CICIDS2017 - Friday DDoS",
        "CICIDS2017 - Friday PortScan",
        "CICIDS2017 - Friday Botnet",
        "CICIDS2017 - Friday DDoS (with IP info)"
    ]
)

df = None

if dataset_option == "Upload your own":
    uploaded_file = st.sidebar.file_uploader("Upload Dataset (CSV or Excel)", type=["csv", "xls", "xlsx"])
    if uploaded_file is not None:
        if uploaded_file.name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
else:
    if dataset_option == "CICIDS2017 - Friday DDoS":
        df = pd.read_csv("datasets/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    elif dataset_option == "CICIDS2017 - Friday PortScan":
        df = pd.read_csv("datasets/CICIDS2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    elif dataset_option == "CICIDS2017 - Friday Botnet":
        df = pd.read_csv("datasets/CICIDS2017/Friday-WorkingHours-Morning.pcap_ISCX.csv")
    elif dataset_option == "CICIDS2017 - Friday DDoS (with IP info)":
        df = pd.read_csv("datasets/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX(withIPinfo).csv")

# --- Clean dataset ---
if df is not None:
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    # Drop non-useful columns if present
    drop_cols = [c for c in ["Flow ID", "Source IP", "Destination IP"] if c in df.columns]
    df = df.drop(columns=drop_cols, errors="ignore")
    st.sidebar.success(f"Dataset Loaded: {len(df)} rows")
else:
    st.warning("Please upload or select a dataset to continue.")
    st.stop()

# --- SIDEBAR: MODEL TRAINING ---
st.sidebar.header("3. Model Training")

def train_model(df):
    features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
                'Total Length of Fwd Packets', 'Fwd Packet Length Max', 
                'Flow IAT Mean', 'Flow IAT Std', 'Flow Packets/s']
    target = 'Label'
    
    missing_cols = [c for c in features if c not in df.columns]
    if missing_cols:
        st.error(f"Missing columns in CSV: {missing_cols}")
        return None, 0, [], None, None

    X = df[features]
    y = df[target]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
    clf.fit(X_train, y_train)
    
    score = accuracy_score(y_test, clf.predict(X_test))
    return clf, score, features, X_test, y_test

if st.sidebar.button("Train Model Now"):
    with st.spinner("Training model..."):
        clf, accuracy, feature_names, X_test, y_test = train_model(df)
        if clf:
            st.session_state['model'] = clf
            st.session_state['features'] = feature_names
            st.session_state['X_test'] = X_test 
            st.session_state['y_test'] = y_test
            st.sidebar.success(f"Training Complete! Accuracy: {accuracy:.2%}")

# --- THREAT DASHBOARD ---
st.header("4. Threat Analysis Dashboard")

if 'model' in st.session_state:
    st.subheader("📊 Model Performance Dashboard")

    y_pred = st.session_state['model'].predict(st.session_state['X_test'])
    cm = confusion_matrix(st.session_state['y_test'], y_pred)

    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    st.pyplot(fig)

    report = classification_report(st.session_state['y_test'], y_pred, output_dict=True)
    report_df = pd.DataFrame(report).transpose()
    st.dataframe(report_df, use_container_width=True)

    attack_counts = df['Label'].value_counts()
    fig2, ax2 = plt.subplots()
    attack_counts.plot(kind='bar', ax=ax2, color="orange")
    ax2.set_title("Attack Distribution in Dataset")
    st.pyplot(fig2)

    # --- Packet Simulation ---
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Simulation")
        st.info("Pick a random packet from the test data to simulate live traffic.")
        
        if st.button("🎲 Capture Random Packet"):
            random_idx = np.random.randint(0, len(st.session_state['X_test']))
            packet_data = st.session_state['X_test'].iloc[random_idx]
            actual_label = st.session_state['y_test'].iloc[random_idx]
            
            st.session_state['current_packet'] = packet_data
            st.session_state['actual_label'] = actual_label
            
    if 'current_packet' in st.session_state:
        packet = st.session_state['current_packet']
        
        with col1:
            st.write("**Packet Feature Info:**")
            st.dataframe(packet, use_container_width=True)

        with col2:
            st.subheader("AI Detection Result")
            prediction = st.session_state['model'].predict([packet])[0]
            
            if prediction == "BENIGN":
                st.success("✅ STATUS: SAFE (BENIGN)")
            else:
                st.error(f"🚨 STATUS: UNSAFE - ATTACK DETECTED ({prediction})")
            
            st.caption(f"Ground Truth Label: {st.session_state['actual_label']}")

            st.markdown("---")
            st.subheader(" Ask AI Analyst (Groq)")
            
            if st.button("Generate Explanation"):
                if not groq_api_key:
                    st.warning(" Please enter your Groq API Key in the sidebar first.")
                else:
                    try:
                        client = Groq(api_key=groq_api_key)
                        
                        prompt = f"""
                        You are a cybersecurity analyst. 
                        A network packet was detected as: {prediction}.
                        
                        Packet Technical Details:
                        {packet.to_string()}
                        
                        Please explain:
                        1. Why these specific values (like Flow Duration or Packet Length) might indicate {prediction}.
                        2. If it is BENIGN, explain why it looks normal.
                        3. Keep the answer short and simple for a student.
                        """

                        with st.spinner("Groq is analyzing the packet..."):
                            completion = client.chat.completions.create(
                                model="llama-3.3-70b-versatile",
                                messages=[{"role": "user", "content": prompt}],
                                temperature=0.6,
                            )
                            st.info(completion.choices[0].message.content)
                            
                    except Exception as e:
                        st.error(f"API Error: {e}")

else:
    st.info(" Waiting for model training. Click **'Train Model Now'** in the sidebar.")