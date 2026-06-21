# Real-Time Phishing Detection System with Explainable AI

Final Year Project (FYP2) — Bachelor of Information Technology (Hons.) in Computer Security
Universiti Kuala Lumpur (UniKL MIIT)
June 2026

**Student:** MIOR MUHAMMAD IDHAM BIN MIOR DARUL RIDZUAN
**Student ID:** 52215124313

---

## Overview

The **Real-Time Phishing Detection System with Explainable AI** is a web-based and browser-extension phishing detection system designed to detect suspicious and phishing URLs in real time. The system uses a hybrid machine learning approach that combines **Random Forest** and **Character-Level Convolutional Neural Network (CNN)** models to classify URLs as Safe, Warn, or Block.

The project also integrates **SHAP Explainable AI (XAI)** to provide understandable explanations for phishing predictions, helping users and analysts understand why a URL is considered suspicious or malicious.

This repository is uploaded for academic, portfolio, and project demonstration purposes.

---

## Key Features

* **Real-Time URL Detection** — Detects URLs during browsing through a Chrome Extension.
* **Hybrid Machine Learning Model** — Combines Random Forest and Character-Level CNN for phishing detection.
* **3-Level Risk Decision** — Classifies URLs into Safe, Warn, and Block categories.
* **Explainable AI (XAI)** — Uses SHAP to explain important URL features that influence phishing prediction.
* **Chrome Extension Integration** — Provides user-side phishing protection while browsing.
* **FastAPI Backend** — Handles prediction requests, model processing, and API responses.
* **Firebase Authentication** — Supports user login and authentication.
* **Firestore Database** — Stores detection history, user records, prediction logs, and alert data.
* **Web-Based Dashboard** — Displays phishing alerts, detection history, prediction scores, and XAI explanations.
* **Safe List and Phishing List Support** — Allows trusted and blocked URL list management.
* **Audit and History Logging** — Records detection events for review and analysis.

---

## Tech Stack

| Layer             | Technology                                     |
| ----------------- | ---------------------------------------------- |
| Backend           | Python 3.10, FastAPI                           |
| Machine Learning  | scikit-learn, TensorFlow/Keras                 |
| ML Models         | Random Forest, Character-Level CNN             |
| Explainable AI    | SHAP TreeExplainer                             |
| Database          | Firebase Firestore                             |
| Authentication    | Firebase Authentication                        |
| Frontend          | HTML, CSS, JavaScript                          |
| Browser Extension | Google Chrome Extension, Manifest V3           |
| Development Tools | Visual Studio Code, Git, GitHub                |
| Testing Tools     | Browser testing, API testing, security testing |

---

## Project Structure

```text
Real-Time-Phishing-Detection-System/
├── backend/                    # FastAPI backend application
│   ├── __init__.py
│   ├── auth.py                 # Authentication and token validation
│   ├── firebase.py             # Firebase Admin integration
│   └── main.py                 # Main API routes and prediction endpoints
│
├── dashboard/                  # Web dashboard interface
│   ├── index.html              # Dashboard page
│   ├── style.css               # Dashboard styling
│   └── app.js                  # Dashboard logic and API calls
│
├── extension/                  # Chrome Extension files
│   ├── manifest.json           # Chrome Extension manifest
│   ├── background.js           # Background URL detection logic
│   ├── content.js              # Content script
│   ├── popup.html              # Extension popup interface
│   ├── popup.js                # Login and extension interaction
│   ├── blocked.html            # Block page for phishing URLs
│   ├── blocked.js              # Block page logic
│   ├── qrcode.min.js           # QR code library
│   └── icons/                  # Extension icons
│
├── ml/                         # Machine learning pipeline
│   ├── __init__.py
│   ├── dataset_loader.py       # Dataset loading and preprocessing
│   ├── feature_extraction.py   # URL feature extraction
│   ├── train_rf.py             # Random Forest training script
│   ├── train_cnn.py            # Character-Level CNN training script
│   └── shap_explainer.py       # SHAP explanation generation
│
├── model/                      # Model artifacts and result files
│   ├── cnn_model.h5            # Character-Level CNN model
│   ├── cnn_tokenizer.json      # CNN tokenizer
│   ├── cnn_maxlen.txt          # CNN maximum sequence length
│   ├── cnn_threshold.txt       # CNN threshold value
│   ├── feature_columns.json    # Random Forest feature schema
│   ├── rf_threshold.txt        # Random Forest threshold value
│   ├── cnn_confusion_matrix.png
│   └── rf_confusion_matrix.png
│
├── requirements.txt            # Python dependencies
├── requirements_backup.txt     # Backup dependency list
├── test_predict.py             # Prediction testing script
├── .gitignore
└── README.md
```

---

## Detection Decision Policy

The system applies a risk-based decision policy after combining the Random Forest and CNN prediction scores.

| Final Score   | Decision | System Action               |
| ------------- | -------- | --------------------------- |
| Below 70%     | Safe     | Website is allowed          |
| 70% – 89%     | Warn     | Warning banner is displayed |
| 90% and above | Block    | Website is blocked          |

The **Warn** category is used for medium-risk or uncertain URLs. This helps reduce unnecessary blocking of legitimate websites while still alerting users about possible phishing risks.

---

## Machine Learning Models

### Random Forest

The Random Forest model analyzes handcrafted URL features such as:

* URL length
* Number of special characters
* HTTPS usage
* Subdomain count
* URL entropy
* Suspicious keywords
* Brand-related keywords
* Suspicious path tokens
* IP address usage in URL
* URL shortener indicators

### Character-Level CNN

The Character-Level CNN model analyzes the URL as a sequence of characters. It is designed to detect hidden phishing patterns from the structure and character arrangement of URLs.

### Fusion Approach

The system combines the prediction outputs from Random Forest and Character-Level CNN into a final phishing risk score. This hybrid method allows the system to analyze both handcrafted URL features and character-level patterns.

---

## Explainable AI

SHAP Explainable AI is used to explain the Random Forest model prediction. It shows which URL features contributed most to the phishing risk score.

Examples of explainable features include:

| Feature            | Explanation                                                                |
| ------------------ | -------------------------------------------------------------------------- |
| Long URL length    | May indicate suspicious or obfuscated URL structure                        |
| Suspicious keyword | Words such as login, verify, account, or update may increase phishing risk |
| HTTPS usage        | Can reduce risk, but does not guarantee safety                             |
| Special characters | Excessive symbols may indicate suspicious URL formatting                   |
| Subdomain count    | Too many subdomains may indicate phishing attempts                         |

SHAP is applied to the Random Forest component because it uses human-readable URL features, making the explanation easier for users and analysts to understand.

---

## Model Performance

| Model               | Result                                                                      |
| ------------------- | --------------------------------------------------------------------------- |
| Random Forest       | Achieved strong phishing detection performance using extracted URL features |
| Character-Level CNN | Achieved strong character-pattern detection performance                     |
| Hybrid Fusion       | Combines both model outputs for final Safe, Warn, or Block decision         |
| SHAP XAI            | Provides feature-level explanation for prediction transparency              |

The project demonstrates that combining Random Forest and Character-Level CNN improves phishing detection because both models analyze URLs from different perspectives.

---

## Setup Instructions

### Prerequisites

* Python 3.10+
* pip
* Git
* Google Chrome
* Firebase project
* Visual Studio Code or any preferred IDE

---

### 1. Clone the Repository

```bash
git clone https://github.com/username10-10/-Real-Time-Phishing-Detection-System-.git
cd -Real-Time-Phishing-Detection-System-
```

---

### 2. Create Virtual Environment

```bash
python -m venv venv
```

Activate virtual environment:

```bash
venv\Scripts\activate
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Firebase Configuration

This repository does **not** include private Firebase credentials, Firebase API configuration files, service account keys, or environment files for security reasons.

To fully run the system, users must create their own Firebase project and configure:

* Firebase Authentication
* Firestore Database
* Firebase Web App configuration
* Firebase Admin SDK service account file

Private Firebase files are excluded from this repository.

---

### 5. Run the Backend

```bash
uvicorn backend.main:app --reload
```

The backend will run at:

```text
http://127.0.0.1:8000
```

---

### 6. Load the Chrome Extension

1. Open Google Chrome.
2. Go to:

```text
chrome://extensions/
```

3. Enable **Developer Mode**.
4. Click **Load unpacked**.
5. Select the `extension/` folder.
6. Login using Firebase Authentication.
7. Start browsing to test phishing URL detection.

---

## Important Notice

This repository is uploaded for academic, portfolio, and demonstration purposes.

The following files are not included in this repository:

* Firebase service account key
* Firebase API configuration files
* `.env` files
* Raw dataset files
* Large Random Forest model file `model/rf_model.pkl`

These files are excluded for security and file size reasons.

---

## Dataset

The phishing URL datasets used during model training are not included in this repository due to file size and storage limitations.

The project uses URL-based datasets containing legitimate and phishing URLs. The data is processed into binary labels:

| Label | Meaning                  |
| ----- | ------------------------ |
| 0     | Benign / Legitimate URL  |
| 1     | Phishing / Malicious URL |

---

## Model File Notice

The large Random Forest model file `model/rf_model.pkl` is not included in this repository due to file size limitations.

However, the training script is provided:

```bash
python -m ml.train_rf
```

After training, the generated model file should be placed inside:

```text
model/rf_model.pkl
```

---

## Security Considerations

* Firebase credentials are not exposed in the repository.
* Service account keys are excluded using `.gitignore`.
* Authentication is handled using Firebase Authentication.
* Detection history is stored in Firestore.
* The system supports warning and blocking actions for suspicious and phishing URLs.
* SHAP explanations help improve transparency of phishing predictions.

---

## Project Status

This project was developed as a functional academic prototype for real-time phishing detection. It is intended for academic evaluation, demonstration, and portfolio purposes.

---

## Disclaimer

This project is developed for educational and academic purposes only. It is not intended to replace enterprise-grade phishing protection systems. Users must configure their own Firebase project and credentials before running the system.

---

## Author

**MIOR MUHAMMAD IDHAM BIN MIOR DARUL RIDZUAN**
Student ID: 52215124313
Programme: Bachelor of Information Technology (Hons.) in Computer Security
University: Universiti Kuala Lumpur — Malaysian Institute of Information Technology (UniKL MIIT)
