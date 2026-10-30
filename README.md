# 🛡️ PhishGuard — URL Phishing Detection System

PhishGuard is a URL analysis tool designed to identify potentially suspicious URLs by examining their structural characteristics and security-related indicators.

It uses a C++ analysis engine, a Python Flask backend, an SQLite database, and an HTML, CSS, and JavaScript frontend.

The system classifies URLs into three risk levels:

- **LOW** — No significant structural indicators detected.
- **MEDIUM** — Some suspicious structural indicators detected.
- **HIGH** — Multiple suspicious indicators detected.

**Note:** PhishGuard is an educational prototype. Its results are based on URL structure and do not guarantee whether a website is safe or malicious.

---

## ✨ Features

- Analyze URLs for suspicious characteristics.
- Detect URLs without HTTPS.
- Identify IP-address-based hosts.
- Check suspicious symbols such as `@` and `%`.
- Examine URL length and domain structure.
- Detect suspicious hyphens and multiple subdomains.
- Classify URLs into LOW, MEDIUM, and HIGH risk levels.
- Display analysis results through a web interface.
- Store analysis history in an SQLite database.
- Display recent analysis records.
- Show a dashboard with risk distribution.
- Provide API endpoints for URL analysis and history.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| C++ | URL analysis engine |
| Python | Backend programming |
| Flask | Web API |
| Flask-Limiter | API rate limiting |
| SQLite | Store analysis history |
| HTML | Frontend structure |
| CSS | Frontend styling |
| JavaScript | Frontend interaction |
| JSON | Data exchange between components |
| GitHub | Source code management |

---

## 📁 Project Structure

```text
PhishGuard/
│
├── .gitignore
├── README.md
│
├── engine/
│   └── analyzer.cpp
│
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   │
│   └── static/
│       └── index.html
│
└── tests/
    └── test_engine.py
```

---

## ⚙️ How PhishGuard Works

PhishGuard follows a simple multi-layer architecture.

1. **User Input:** The user enters a URL through the web interface.
2. **Frontend:** JavaScript sends the URL to the Flask backend.
3. **Backend:** Flask validates the input and calls the C++ analysis engine.
4. **C++ Engine:** The engine examines URL characteristics and calculates a risk level.
5. **JSON Response:** The engine returns its analysis results in JSON format.
6. **Database:** Flask stores the analysis result in SQLite.
7. **Dashboard:** The frontend displays the result, statistics, and recent analysis history.

### Architecture

```text
        User
         |
         v
   HTML / CSS / JS
      Frontend
         |
         v
     Flask API
      Backend
         |
         v
    C++ Analyzer
         |
         v
    JSON Result
         |
         v
    SQLite Database
         |
         v
 Dashboard & History
```

---

## 🔍 URL Analysis Indicators

PhishGuard examines different URL characteristics, including:

- **HTTPS:** Checks whether the URL uses HTTPS.
- **URL Length:** Examines unusually long URLs.
- **Dots:** Counts dots in the hostname.
- **Subdomains:** Examines the number of subdomains.
- **IP Address:** Checks whether the hostname is an IP address.
- **@ Symbol:** Detects the presence of `@`.
- **Hyphen:** Checks for hyphens in the hostname.
- **Percent Encoding:** Detects percent-encoded characters.

These indicators are used to estimate the structural risk level of a URL.

---

## 🌐 API Endpoints

The Flask backend provides the following endpoints:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Opens the frontend |
| POST | `/analyze` | Analyzes a submitted URL |
| GET | `/history` | Retrieves recent analysis history |
| GET | `/analysis/<id>` | Retrieves a specific analysis |
| GET | `/stats` | Retrieves dashboard statistics |

### Example: Analyze URL

**Request:**

```json
{
  "url": "https://www.example.com"
}
```

The backend processes the URL and returns the analysis result in JSON format.

---

## 📦 Installation Requirements

To run the complete project, you need:

- Python 3
- A C++ compiler
- Flask
- Flask-Limiter
- SQLite

### Install Python Dependencies

```bash
pip install -r backend/requirements.txt
```

### Compile the C++ Engine

On Linux:

```bash
g++ engine/analyzer.cpp -o engine/analyzer
```

On Windows:

```bash
g++ engine/analyzer.cpp -o engine/analyzer.exe
```

### Run the Backend

```bash
python backend/app.py
```

Open the application in your browser:

```text
http://localhost:5000
```

---

## 🧪 Testing

The project includes a test script:

```text
tests/test_engine.py
```

It contains sample URLs with expected risk classifications.

The tests check whether the C++ engine returns the expected LOW, MEDIUM, or HIGH classification.

**Note:** Compile the C++ engine before running the tests. The test script requires the Python environment and the compiled executable.

---

## 🔐 Security and Limitations

- Risk classifications are based on structural URL indicators.
- A HIGH result does not prove that a website is malicious.
- A LOW result does not guarantee that a website is safe.
- The system does not currently verify website ownership or reputation through external threat-intelligence databases.
- Further testing and security improvements are required before production use.

---

## 🚀 Future Improvements

- Integrate external threat-intelligence APIs.
- Add machine learning-based URL classification.
- Improve detection accuracy.
- Add URL reputation checking.
- Improve dashboard visualizations.
- Add user authentication.
- Deploy the application online.

---

## 🎯 Project Purpose

The purpose of PhishGuard is to demonstrate how C++, Python, web technologies, and databases can work together to build a basic URL phishing-risk analysis system.

This project is developed for educational and learning purposes.

---

**Project Name:** PhishGuard  
**Project Type:** URL Phishing Detection System  
**Status:** Development  
**Repository:** GitHub
