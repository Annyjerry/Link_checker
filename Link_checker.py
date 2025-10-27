# -*- coding: utf-8 -*-
"""
Created on Wed Oct 22 09:39:15 2025

@author: Annyjerry
"""

import streamlit as st
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
from joblib import load
from scipy.sparse import hstack, csr_matrix


# Load model artifacts
@st.cache_resource(show_spinner=False)
def load_artifacts():
    try:
        rf = load("random_forest.joblib")
        tfidf = load("vectorizer.joblib")
        numeric_cols = load("numeric_feature_names.joblib")
        scaler = load("numeric_scaler.joblib")
        le = load("label_encoder.joblib")
        return rf, tfidf, numeric_cols, scaler, le
    except Exception as e:
        st.error(f"⚠️ Unable to load model artifacts: {e}")
        return None, None, None, None, None

rf, tfidf, numeric_cols, scaler, le = load_artifacts()


# Feature extraction

def extract_url_features(url):
    url = str(url)
    f = {}
    if not re.match(r'^[a-zA-Z]+://', url):
        parsed = urlparse('http://' + url)
    else:
        parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = parsed.scheme or ''
    host = domain.lower()
    full = (domain + path + ('?' + query if query else '')).lower()

    f['url_length'] = len(url)
    f['domain_length'] = len(domain)
    f['path_length'] = len(path)
    f['query_length'] = len(query)
    f['count_dot'] = url.count('.')
    f['count_dash'] = url.count('-')
    f['count_underscore'] = url.count('_')
    f['count_slash'] = url.count('/')
    f['count_question'] = url.count('?')
    f['count_equal'] = url.count('=')
    f['count_at'] = url.count('@')
    f['count_amp'] = url.count('&')
    f['count_hash'] = url.count('#')
    f['count_digits'] = sum(c.isdigit() for c in url)
    f['count_letters'] = sum(c.isalpha() for c in url)
    f['digits_ratio'] = f['count_digits'] / max(1, f['url_length'])
    f['letters_ratio'] = f['count_letters'] / max(1, f['url_length'])
    f['has_ip'] = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain) else 0
    f['has_https'] = 1 if scheme == 'https' else 0
    f['has_at_symbol'] = 1 if f['count_at'] > 0 else 0
    tokens = re.split(r'[/:?&.=#\-_]', url)
    token_lengths = [len(t) for t in tokens if t]
    f['num_tokens'] = len(token_lengths)
    f['avg_token_length'] = np.mean(token_lengths) if token_lengths else 0
    f['max_token_length'] = np.max(token_lengths) if token_lengths else 0
    f['has_long_token'] = 1 if token_lengths and max(token_lengths) > 25 else 0
    suspicious = ['login','signin','secure','account','update','verify','bank','confirm',
                  'webscr','paypal','wp-content','auth','session','admin','ebayisapi','reset']
    for w in suspicious:
        f[f'kw_{w}'] = 1 if w in full else 0
    non_alnum = sum(1 for c in url if not c.isalnum())
    f['non_alnum_ratio'] = non_alnum / max(1, f['url_length'])
    return f

def prepare_single_url(url, tfidf, numeric_cols, scaler):
    nf = extract_url_features(url)
    if numeric_cols is None:
        return None
    numeric_values = np.array([nf.get(c, 0) for c in numeric_cols], dtype=float).reshape(1, -1)
    numeric_scaled = scaler.transform(numeric_values)
    tfidf_vec = tfidf.transform([url])
    return hstack([csr_matrix(numeric_scaled), tfidf_vec], format='csr')


# Page config and global styles

st.set_page_config(
    page_title="Malicious URL Detection System",
    page_icon="🌐",
    layout="wide"
)

st.markdown("""
    <style>
    body {
        background: linear-gradient(to right, #f4f7f9, #e8eef3);
        font-family: 'Segoe UI', sans-serif;
    }
    .sidebar .sidebar-content {
        background: sky-blue;
        color: white;
    }
    .sidebar .sidebar-content h2, .sidebar .sidebar-content p {
        color: white !important;
    }
    h1, h2, h3 {
        color: #1877f2;
        font-family: 'Poppins', sans-serif;
    }
    .chat-container {
        background-color: white;
        border-radius: 12px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        padding: 1.5rem;
        margin-top: 2rem;
        width: 100%;
        max-width: 700px;
        margin-left: auto;
        margin-right: auto;
    }
    .chat-bubble-user {
        background-color: #0084ff;
        color: white;
        padding: 10px 15px;
        border-radius: 18px;
        border-bottom-right-radius: 4px;
        display: inline-block;
        margin: 8px 0;
        align-self: flex-end;
        max-width: 80%;
        word-wrap: break-word;
        font-weight: bold;
    }
    .chat-bubble-bot {
        background-color: #e4e6eb;
        color: black;
        padding: 10px 15px;
        border-radius: 18px;
        border-bottom-left-radius: 4px;
        display: inline-block;
        margin: 8px 0;
        align-self: flex-start;
        max-width: 80%;
        word-wrap: break-word;
        font-weight: bold;
    }
    .confidence {
        font-size: 0.9em;
        color: gray;
        margin-top: -6px;
        font-weight: 600;
    }
    .footer-note {
        color: #777;
        font-size: 0.9em;
        text-align: center;
        margin-top: 2rem;
    }
    </style>
""", unsafe_allow_html=True)


# Sidebar Navigation

st.sidebar.title("🔎 Navigation")
menu = st.sidebar.radio("Go to:", ["Overview", "Model Demo", "Dataset", "About"])


# Overview Section

if menu == "Overview":
    st.title("🌐 Malicious URL Detection Using Random Forest")
    st.subheader("Project Overview")

    st.write("""
    Every day, millions of people visit websites without realizing that some of them are created for **malicious purposes** — 
    such as stealing personal information, spreading viruses, or tricking users into revealing sensitive details.  
    These are called **malicious URLs** (Uniform Resource Locators). A malicious URL might look safe at first glance, 
    but it can lead to harmful pages that compromise your privacy or system security.
    """)

    st.write("""
    Traditional approaches to spotting bad URLs rely on **blacklists** — stored lists of known dangerous websites.  
    However, cybercriminals are constantly creating new and unique links, which means blacklists often fail to catch new threats.  
    This is where **machine learning** becomes a smarter and faster solution.
    """)

    st.markdown("### 💡 How the Model Works")
    st.write("""
    Our system uses a **Random Forest Classifier**, a popular machine learning algorithm that makes predictions 
    by combining decisions from many smaller models called "trees". Each tree looks at a different part of the data — 
    such as how long the URL is, whether it uses HTTPS, how many special symbols it has, and even if it contains 
    suspicious words like *login*, *bank*, *verify*, or *update*.  

    By analyzing these patterns, the model can automatically learn the difference between a **safe URL** 
    and a **malicious one** — even if it has never seen the exact link before.
    """)

    st.markdown("### 🔍 Why This Project Matters")
    st.write("""
    Online safety is a big challenge today. Attackers send fake links through emails, social media, and messages every day, 
    and people can easily click them by mistake. This model helps reduce that risk by acting like a **smart security assistant** 
    — you simply paste a link, and it instantly checks if it’s likely to be harmful or safe.  
    The model also gives a **confidence score** (called an honesty score) to show how sure it is about its prediction.
    """)

    st.markdown("### 🔑 Key Insights")
    st.write("""
    - Malicious URLs often try to look like real ones but include **extra characters**, **numbers**, or **tricky keywords**.  
    - Shortened or encoded links can hide the true destination, which makes analysis important.  
    - Features such as **URL length**, **number of dots**, **presence of an IP address**, or **use of HTTPS** 
      give strong clues to detect suspicious activity.  
    - The combination of **TF-IDF (text analysis)** and **numerical URL features** makes the Random Forest model 
      both powerful and adaptable to new data.
    """)

    st.markdown("### 🧩 Project Summary")
    st.write("""
    This project shows how artificial intelligence can be used to **protect users online**.  
    Instead of relying only on pre-registered threat lists, the system learns to recognize patterns 
    that signal danger. This means it can detect **brand-new malicious links** that traditional tools 
    might miss.  

    The goal is simple: to make browsing the internet safer and to help people think twice before 
    clicking on suspicious-looking links.
    """)

    st.markdown("### 🛠️ Tools and Technologies Used")
    st.markdown("""
    - **Python 3.10+**
    - **Streamlit** – for building the interactive web interface  
    - **scikit-learn** – for machine learning and Random Forest implementation  
    - **NumPy & Pandas** – for feature extraction and data handling  
    - **Matplotlib / Seaborn** – for visualization and analysis  
    - **Joblib** – for saving and loading trained models  
    """)

    


# Model Demo Section (Improved Visual Design & Readability)

elif menu == "Model Demo":
    st.markdown("""
        <style>
        /* Modern Chat UI Styling */
        .stApp {
            background-color: #f0f2f5;
        }
        .chat-header {
            text-align: center;
            font-size: 30px;
            font-weight: 800;
            color: black;
            background-color: #ffffff;
            padding: 1rem 0;
            margin: 1.5rem auto;
            border-radius: 12px;
            max-width: 780px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        
        .user-msg {
            text-align: right;
            background-color: #1877F2;
            color: Blue;
            padding: 10px 16px;
            border-radius: 20px 20px 0 20px;
            display: inline-block;
            max-width: 80%;
            font-size: 16px;
            font-weight: 600;
            word-wrap: break-word;
            align-self: flex-end;
            animation: fadeIn 0.3s ease-in;
        }
        .bot-msg {
            text-align: left;
            background-color: #e9ebee;
            color: #1c1e21;
            padding: 10px 16px;
            border-radius: 20px 20px 20px 0;
            display: inline-block;
            max-width: 80%;
            font-size: 16px;
            font-weight: 600;
            word-wrap: break-word;
            align-self: flex-start;
            animation: fadeIn 0.3s ease-in;
        }
        .typing {
            font-size: 14px;
            color: #555;
            font-style: italic;
            animation: blink 1.4s infinite;
        }
        @keyframes blink {
            0% { opacity: 0.2; }
            50% { opacity: 1; }
            100% { opacity: 0.2; }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .stTextInput > div > div > input {
            border-radius: 25px;
            padding: 0.8rem;
            font-size: 16px;
            border: 1px solid #ccc;
            color: white !important;
        }
        .stTextInput > div > div > input::placeholder {
            color: #navy-blue !important;
            opacity: 0.8;
        }
        div.stButton > button {
            background-color: #1877F2;
            color: blue;
            border: none;
            border-radius: 50%;
            padding: 0.6rem 0.8rem;
            font-size: 18px;
            transition: all 0.3s ease;
        }
        div.stButton > button:hover {
            background-color: #145db6;
            transform: scale(1.05);
        }
        .block-container {
            padding-top: 1rem !important;
        }
        </style>
    """, unsafe_allow_html=True)

    # Clean Title with Padding and No Line
    st.markdown("<div class='chat-header'>🌐 Malicious URL Detection Chat</div>", unsafe_allow_html=True)

    st.markdown("<div class='chat-card'>", unsafe_allow_html=True)

    # Input and Send Button Layout
    st.markdown(
    "<h4 style='color:black; font-weight:700; margin-bottom:8px;'>Enter a URL to check:</h4>",
    unsafe_allow_html=True
    )
    user_input = st.text_input("", placeholder="Type or paste a link (e.g. http://example.com)...")

    col1, col2 = st.columns([6, 1])
    with col2:
        send = st.button("📨")

    # Simulated Typing Animation
    import time
    def typing_animation(text, delay=0.05):
        placeholder = st.empty()
        displayed_text = ""
        for char in text:
            displayed_text += char
            placeholder.markdown(f"<div class='bot-msg'>{displayed_text}▌</div>", unsafe_allow_html=True)
            time.sleep(delay)
        placeholder.markdown(f"<div class='bot-msg'>{displayed_text}</div>", unsafe_allow_html=True)

    # Prediction Logic
    if send and user_input.strip() != "":
        st.markdown(f"<div class='user-msg'>{user_input}</div>", unsafe_allow_html=True)

        try:
            if not all([rf, tfidf, numeric_cols, scaler, le]):
                typing_animation("⚠️ Sorry, model files are missing. Please re-upload and retry.", delay=0.03)
            else:
                X = prepare_single_url(user_input, tfidf, numeric_cols, scaler)
                if X.shape[1] != rf.n_features_in_:
                    typing_animation("⚠️ Model mismatch detected. Please retrain model and vectorizer together.", delay=0.03)
                else:
                    pred = rf.predict(X)[0]
                    proba = rf.predict_proba(X)[0]
                    label = le.inverse_transform([pred])[0]
                    confidence = np.max(proba) * 100

                    time.sleep(0.6)
                    typing_animation("Analyzing the link...", delay=0.04)
                    time.sleep(0.6)

                    if label.lower() == "malicious":
                        typing_animation(f"⚠️ This link appears malicious. Confidence: {confidence:.2f}%", delay=0.03)
                    else:
                        typing_animation(f"✅ This link seems safe. Confidence: {confidence:.2f}%", delay=0.03)

        except Exception as e:
            typing_animation(f"❌ Error: {str(e)}", delay=0.03)

    st.markdown("</div>", unsafe_allow_html=True)



# Dataset Section

elif menu == "Dataset":
    st.title("📊 Dataset Overview")
    st.write("Below is a random sample preview of the dataset used for training the model:")

    try:
        df = pd.read_csv("balanced_urls.csv")

        # Shuffle the dataset for randomness
        df_shuffled = df.sample(frac=1, random_state=42).reset_index(drop=True)

        st.dataframe(df_shuffled.head(100))
        st.info(f"Dataset contains {df_shuffled.shape[0]} rows and {df_shuffled.shape[1]} columns (shuffled view).")

        st.caption("🔄 Note: The rows are shuffled each time the page reloads to show a mixed preview.")
    except Exception:
        st.warning("⚠️ Could not load dataset.csv. Please ensure it is placed in the same folder.")

# About Section

elif menu == "About":
    st.markdown("""
        <style>
        .about-section {
            background-color: white;
            color: black;
            padding: 2rem;
            border-radius: 12px;
            font-family: 'Segoe UI', sans-serif;
            line-height: 1.7;
            font-size: 1rem;
            max-width: 800px;
            margin: auto;
            box-shadow: 0 4px 15px rgba(0,0,0,0.5);
        }
        .about-section h1, .about-section h2 {
            color: #00bcd4;
            text-align: center;
            margin-bottom: 1.5rem;
        }
        .about-section p {
            text-align: justify;
            margin-bottom: 1rem;
        }
        .developer-info {
            margin-top: 2rem;
            font-size: 0.9rem;
            color: #cccccc;
            text-align: center;
        }
        </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="about-section">
            <h1>About This Project</h1>
            <p>
            This project was created to help internet users easily identify unsafe or fake website links, often called <b>malicious URLs</b>.
            These links are commonly used by cybercriminals to trick people into sharing personal information such as passwords, bank details,
            or other sensitive data. Sometimes, clicking these links can even install harmful software on your device without your consent.
            </p>
            <p>
            The system uses a <b>Random Forest machine learning model</b> to analyze the structure and content of website links.
            It evaluates multiple characteristics — including URL length, the number of symbols or digits, and suspicious keywords
            like <i>login</i>, <i>verify</i>, <i>update</i>, or <i>account</i>. These features are combined and processed to determine
            if a link is likely safe or malicious.
            </p>
            <p>
            Unlike traditional security systems that rely only on blacklists of known harmful sites, this model uses <b>AI intelligence</b>
            to identify <b>new and evolving threats</b>. By learning from real-world malicious links, it can detect suspicious patterns even if
            hackers slightly modify their URLs to bypass detection.
            </p>
            <p>
            The main goal of this project is to make the web safer and more trustworthy. Users can simply paste a link and instantly check if
            it poses a potential risk. This tool helps prevent phishing, online scams, and identity theft by warning users before they click
            on dangerous links.
            </p>
            <p>
            <b>Future Improvements:</b> In the future, this system can be enhanced into a browser extension for real-time detection,
            integrated with deep learning models, and trained on larger and more diverse datasets. This will improve accuracy and help
            protect users from modern, AI-powered cyber threats across languages and platforms.
            </p>
            <p>
            <b> <b> <i>This model is open for interaction, contribution, and collaboration<i/><b/>
            </p>
            <div class="developer-info">
                👨‍💻 Developed by <b>Annyjerry</b> | Project: <b>Malicious URL Detection</b> | Technology: <b>Random Forest & AI Security</b>
            </div>
        </div>
    """, unsafe_allow_html=True)
