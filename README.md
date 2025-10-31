🌐 Malicious URL Detection Using Machine Learning

A **Streamlit-powered web app** that intelligently detects **malicious URLs** using a **Random Forest Classifier** trained on both textual and numerical features extracted from website links.


Overview

Every day, users are exposed to fake, phishing, and malicious websites designed to steal data, spread malware, or trick users into revealing sensitive information.  
This project leverages **machine learning** to automatically identify whether a URL is **safe or malicious**, based on structural and linguistic features.

Traditional blacklist-based detection systems fail against newly generated URLs.  
Our model instead **learns from patterns** such as:

- URL length, domain and path complexity  
- Count of special characters (e.g., `.`, `@`, `-`, `_`)  
- Suspicious keywords like `login`, `verify`, `update`, or `bank`  
- Presence of HTTPS or IP addresses in domain  

The result is a robust, explainable system that generalizes well to unseen, real-world threats.


⚙️ Tech Stack

- **Python 3.10+**
- **Streamlit** – Interactive frontend UI
- **Scikit-learn** – Machine learning pipeline
- **Pandas & NumPy** – Data processing
- **Joblib** – Model serialization
- **Matplotlib / Seaborn** – Data visualization
- **Regular Expressions (re)** – URL pattern extraction



🧩 Features

✅ Real-time malicious URL classification  
✅ Confidence score for each prediction  
✅ Intuitive chat-style user interface  
✅ Integrated dataset preview  
✅ Modular code design (easily extendable to deep learning)  
✅ Light & professional theme with modern CSS styling  



🧑‍💻 How to Run Locally

1️⃣ Clone the repository

git clone https://github.com/Annyjerry/Link_checker.git
cd Link_checker


2️⃣ Install dependencies

Make sure you have Python 3.10+ installed. Then install all required packages:

pip install -r requirements.txt

3️⃣ Add model files

Place your trained model artifacts in the project root directory:

random_forest.joblib
vectorizer.joblib
numeric_feature_names.joblib
numeric_scaler.joblib
label_encoder.joblib
balanced_urls.csv


4️⃣ Run the app

streamlit run app.py


The app will open automatically in your default browser.


📊 Dataset Information

The dataset (`balanced_urls.csv`) contains labeled examples of **malicious** and **benign** URLs.
Each record includes:

* Raw URL
* Extracted numeric features (lengths, symbol counts, etc.)
* TF-IDF vectorized text features
* Label: `malicious` or `benign`

> ⚠️ Disclaimer: The dataset included in this repository was obtained from publicly available open-source phishing datasets intended for educational and research purposes only.
Users are encouraged to cite or reference original data sources where applicable.



🤖 Model Details

* **Algorithm:** Random Forest Classifier
* **Text Vectorization:** TF-IDF
* **Feature Combination:** Numeric + Textual (using `scipy.hstack`)
* **Evaluation Metrics:** Accuracy, Precision, Recall, F1-Score

The hybrid design allows the model to understand both the **structure** and **semantics** of URLs, achieving strong generalization across unseen links.


🗂️ Project Structure


malicious-url-detection/
│
├── app.py                      # Streamlit app entry point
├── balanced_urls.csv           # Training dataset (optional)
├── random_forest.joblib        # Trained Random Forest model
├── vectorizer.joblib           # TF-IDF vectorizer
├── numeric_feature_names.joblib# Feature name mapping
├── numeric_scaler.joblib       # StandardScaler object
├── label_encoder.joblib        # Encoded labels
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```


🧭 Future Improvements

* Integrate **deep learning** (CNN/LSTM) for more subtle URL patterns
* Build a **browser extension** for real-time protection
* Include **auto-retraining** from live threat feeds
* Add **explainable AI (XAI)** visualization for decision interpretation


👨‍💻 Author

**Developed by:** [Aniebiet Jeremiah](https://github.com/Annyjerry)
**Project:** Malicious URL Detection
**Technology:** Random Forest & AI-driven Security
**Version:** 1.0 (First Phase Release)

> 💡 The project is in its **first-phase release**, currently optimized for standard malicious patterns.
> Future versions will focus on **scalability and detection of subtle, AI-evasive patterns** in URLs.



🧑‍🤝‍🧑 Contributing

Contributions are welcome!
If you'd like to improve the UI, retrain the model, or extend the dataset, follow these steps:

1. Fork the repository
2. Create a new branch (`feature/new-feature`)
3. Commit your changes
4. Push to your fork
5. Create a Pull Request


📜 License

This project is open-source under the MIT License – you are free to use, modify, and distribute it with proper attribution.


🌟 Acknowledgments

Special thanks to:

The open-source community for datasets and libraries

Streamlit and scikit-learn contributors

Researchers in cybersecurity and AI for ongoing innovation