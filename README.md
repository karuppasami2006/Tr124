# SecureFlow AI — Real-Time DevSecOps Security Assistant

SecureFlow AI is a hackathon-winning DevSecOps tool designed to overcome the limitations of traditional SAST scanners. By leveraging LLM-based reasoning and a dual-layer validation system, it provides high-precision vulnerability detection with actionable fix suggestions directly in the developer workflow.

## 🚀 Key Features
- **Real-Time Diff Analysis**: Scans code changes instantly before merging.
- **AI-Powered Validation**: Dual-prompt architecture (Detection + Validation) to prune false positives.
- **Actionable Remediation**: Provides "Before vs After" code snippets and exploit scenarios.
- **CI/CD Integration**: Realistic pipeline status determination (PASS/WARNING/FAIL).
- **GitHub PR Simulation**: Previews how security findings look as pull request comments.

## 🛠️ Tech Stack
- **Frontend**: React (Vite), Tailwind CSS, Framer Motion, Lucide Icons.
- **Backend**: FastAPI (Python), Google Gemini API (1.5 Flash).
- **Communication**: REST API.

## 📁 Project Structure
```
/
├── backend/
│   ├── main.py        # FastAPI Server
│   ├── scanner.py     # AI & Risk Logic
│   ├── prompts.py     # LLM Prompt Templates
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── App.jsx    # Complete Dashboard UI
    │   └── index.css  # Design System
    ├── tailwind.config.js
    └── ...
```

## ⚡ Quick Start

### 1. Backend Setup
```bash
cd backend
pip install -r requirements.txt
# Set your API Key (Optional: Scanner has mock fallback for demo)
# export GEMINI_API_KEY="your-key"
python main.py
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## 🎯 Winning Strategy
- **Visual Impact**: Modern dark-mode dashboard with glassmorphism and animations.
- **Reliability**: Built-in mock data ensures the demo works even without an internet connection or API keys.
- **Workflow Focus**: It doesn't just find bugs; it simulates the entire lifecycle from developer commit to PR comment.
