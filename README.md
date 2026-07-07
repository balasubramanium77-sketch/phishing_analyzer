# 🛡️ SOC Email Analysis Terminal

**SOC Email Analysis Terminal** is a full-stack cybersecurity application designed to assist Security Operations Center (SOC) analysts in investigating suspicious emails. Built with **FastAPI**, **HTML**, **CSS**, and **JavaScript**, the platform analyzes raw email content, extracts critical metadata, inspects embedded links, and produces an automated security assessment using live threat intelligence.

The application provides an intuitive dashboard that helps analysts quickly identify phishing attempts, spoofed senders, and potentially malicious URLs through real-time analysis.

🌐 **Live Demo:**  
https://balasubramanium77-sketch.github.io/phishing_analyzer/

---

# ✨ Features

- 📧 Analyze raw email headers and message content
- 🔍 Extract sender, recipient, subject, and routing information
- 🛡 Verify email authentication using **SPF**, **DKIM**, and **DMARC**
- 🌐 Identify and inspect URLs embedded within email messages
- 🚨 Perform live reputation checks using the **VirusTotal API**
- 📊 Generate an overall security verdict with categorized risk levels
- 💻 Modern SOC-inspired dashboard with a responsive dark interface
- ⚡ Fast asynchronous backend for efficient processing

---

# 📸 Preview

> *(Add your application screenshot here)*

```md
![SOC Email Analysis Terminal](assets/screenshot.png)
```

---

# ⚙️ Workflow

The application processes suspicious emails through the following stages:

```text
Raw Email Source
        │
        ▼
Header & Body Parsing
        │
        ▼
Metadata Extraction
        │
        ▼
Authentication Validation
(SPF • DKIM • DMARC)
        │
        ▼
URL Detection
        │
        ▼
Threat Intelligence Lookup
        │
        ▼
Risk Evaluation
        │
        ▼
Security Report
```

---

# 🔎 Analysis Capabilities

The system automatically examines multiple aspects of an email, including:

- Sender information
- Recipient details
- Email subject
- Message headers
- Authentication records
- Embedded hyperlinks
- Domain reputation
- Overall phishing indicators

Each result is presented in an organized dashboard to simplify investigation.

---

# 🧠 Detection Process

The backend performs several analysis steps:

- Parses RFC 822 formatted emails
- Extracts authentication-related headers
- Detects domains and hyperlinks
- Queries external threat intelligence
- Calculates an overall security assessment
- Returns structured results to the frontend instantly

---

# 🛠️ Technology Stack

### Frontend

- HTML5
- CSS3
- JavaScript (ES6)

### Backend

- Python 3
- FastAPI
- Uvicorn

### APIs & Libraries

- VirusTotal API
- Python Email Library
- Requests

---

# 📂 Project Structure

```text
SOC-Email-Analysis-Terminal/
│── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── backend/
│   ├── main.py
│   ├── analyzer.py
│   ├── requirements.txt
│   └── utils.py
│
└── README.md
```

---

# 🚀 Getting Started

### Prerequisites

- Python 3.8 or later
- VirusTotal API Key

### Installation

```bash
git clone https://github.com/your-username/Email-analyzer.git

cd Email-analyzer

pip install -r requirements.txt

uvicorn main:app --reload
```

Open the frontend in your browser and begin analyzing email samples.

---

# 🌟 Future Enhancements

- Attachment malware scanning
- AI-powered phishing detection
- IP reputation analysis
- Email risk history
- Export reports in PDF format
- Multi-language support
- Dashboard analytics

---

# 👨‍💻 Author

**Bala Subramanium**

⭐ If this project was helpful, consider starring the repository on GitHub.
