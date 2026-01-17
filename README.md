---
title: AI NIDS Student Project
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: streamlit
sdk_version: 1.39.0
app_file: app.py
pinned: false
---

# 🛡️ AI-Based Network Intrusion Detection System (Student Project)

This project demonstrates how to use **Machine Learning (Random Forest)** and **Generative AI (Groq)** to detect and explain network attacks using the **CICIDS2017 dataset**.  
It provides an interactive dashboard to train models, analyze threats, and simulate packet detection.

---

## 🚀 How to Use
1. **Enter API Key (Optional):** Paste your Groq API key in the sidebar if you want AI explanations.  
2. **Upload Dataset or Use Included Ones:**  
   - You can upload your own CSV/Excel dataset.  
   - Or use the included CICIDS2017 subset files already in this Space.  
3. **Train Model:** Click **"Train Model Now"** to train a Random Forest classifier.  
4. **Threat Dashboard:** View confusion matrix, classification report, and attack distribution charts.  
5. **Simulate:** Click **"Capture Random Packet"** to test live detection on a random packet.  
6. **Analyze:** The system will flag packets as:  
   - ✅ **SAFE (BENIGN)**  
   - 🚨 **UNSAFE – ATTACK DETECTED (e.g., DDoS, PortScan, Botnet)**  
7. **Ask Groq Analyst:** Generate a short explanation of why the packet was classified that way.

---

## 📊 Datasets Included
This Space includes CICIDS2017 subsets with both BENIGN and ATTACK traffic:

- **Friday Afternoon – DDoS** → Distributed Denial of Service traffic  
- **Friday Afternoon – PortScan** → Reconnaissance scanning activity  
- **Friday Morning – Botnet** → Botnet-controlled malicious traffic  
- **Friday Afternoon – DDoS (with IP info)** → Same as DDoS but includes raw `Source IP` and `Destination IP` columns for context  

> Note: Some subsets include IP information, while others only provide flow-based statistical features. Both are valid for ML-based intrusion detection.

---

## 📂 Files
- `app.py` → The main Streamlit application code  
- `requirements.txt` → List of libraries used  
- `README.md` → Project documentation  
- `datasets/` → Contains CICIDS2017 subset files used in the demo  
- `.gitattributes` → Ensures large datasets are tracked with Git LFS  

---

## 🎓 About
Created for a university cybersecurity project to demonstrate the integration of:
- **Traditional ML** → Random Forest for intrusion detection  
- **Generative AI** → Groq for packet explanations  
- **Interactive Dashboards** → Streamlit for visualization  

This project helps students understand how AI can be applied to **network security operations**, combining **attack detection** with **human-readable explanations**.

---
