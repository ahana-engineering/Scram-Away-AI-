# Scram-Away-AI-
Scam Detection Platform

Scram Away AI !!! - Scam Detection Platform

Tiered AI-powered phishing and scam detection platform for SMS and email

Built for Finbehaviour Hackthon by Nova Pulse.

The Problem

Phishing SMS and emails are getting harder to catch because scammers now use AI too — flawless grammar, no typos, and messages tailored to look exactly like a real bank, government agency, or delivery service. Traditional spam filters that rely on matching known bad keywords are falling behind.

The Solution

Scram Away AI!!! uses a three-tier escalation pipeline — fast rule-based filtering, ML-style pattern scoring, and Google Gemini AI reasoning — to detect both known and brand-new scam patterns in real time, with every verdict explained in plain language across English, Hindi, and Tamil.

Key Features
Feature	Description
🛡️ Tiered detection	Rules → ML scoring → Gemini reasoning, escalating only when needed
🔍 Explainable AI	Every flagged message shows exactly which red flags triggered it and why
🌐 Multilingual	Detects and explains scams in English, Hindi, and Tamil — not just translated output
⚡ Zero-day detection	A dedicated badge highlights messages caught by AI reasoning alone, with no keyword/pattern match
📊 Live analytics	Pie and bar charts of risk-level distribution, updated after every scan
🚨 Real-time alerts	In-page toast notifications plus native browser notifications on High/Critical results
👥 Multi-user support	Login system with per-user analytics, sender history, and scan logs
📰 Scam awareness feed	Searchable, filterable financial news and scam-alert articles
🎧 Customer support	In-app complaint/question submission with ticket history and FAQ
🔌 Detection sources panel	Preview UI for planned Gmail/Outlook/SMS integrations
🔒 Privacy-first	Anonymized snippets only, consent-forward design, no long-term raw message storage


Why this design: most legitimate messages resolve at the free, instant tiers. Only ambiguous or suspicious messages reach the paid Gemini call — this keeps the system fast and cheap at scale while still catching scams that don't match any known pattern.

Tech Stack
Tool	Purpose
Python	Backend language
Flask	Web framework — routing, sessions, API
Google Gemini API	Tier 3 AI reasoning
HTML / CSS / JavaScript	Frontend — no framework, single-page app
Chart.js	Analytics visualizations
Regex	Tier 1/2 pattern matching
python-dotenv	Loading the Gemini API key from .env
Project Structure
Scram Away AI/
├── app.py                    # Flask server: routes, sessions, per-user state
├── detection_engine.py       # Core detection logic: all 3 tiers + aggregation
├── requirements.txt
├── .env                      # Your Gemini API key (not committed to git)
├── static/
│   ├── index.html            # Main dashboard (single-page app)
│   └── login.html            # Login page

Setup
1. Install dependencies
bash
pip install -r requirements.txt
2. Add your Gemini API key

Get a free key at aistudio.google.com/apikey, then create a .env file in the project root:

GEMINI_API_KEY=your_key_here
3. Run the app
bash
python app.py

4. Open it

Go to http://localhost:5000 — you'll be redirected to a login page. Any username/password works; a new username automatically creates an account (this is a demo-grade login, not production authentication).

Usage
Log in (or create an account on the fly)
On the Detector Engine tab, choose SMS / Email / URL, paste in content, optionally add a sender ID, pick a language, and click Analyze message
Review the risk score, warning level, detected red flags, and plain-language explanation
Check News Feed for scam-awareness articles (searchable, filterable by category)
Check Analytics for your session's risk-level breakdown
Check Scan Logs for your full scan history
Use Support to ask a question or report an issue
Known Limitations (by design, for hackathon scope)
Login is demo-grade — plaintext in-memory credential storage, not real authentication. A production version would use proper password hashing and/or OAuth.
All data is in-memory — restarting the server clears users, analytics, logs, and tickets. No database is connected.
Gmail / Outlook / SMS integrations are not live — the sidebar panel is a UI preview only, showing illustrative demo numbers. Real integration would use the Gmail API, Microsoft Graph API, and an SMS provider API, each via proper OAuth consent.
News feed content is illustrative, not pulled from a real news API — written to demonstrate the intended feature.
Free-tier Gemini quota — heavy testing can hit rate limits; the app gracefully falls back to Tier 1/2-only scoring if Tier 3 is unavailable.
What Makes This Different

Enterprise tools (Bolster, StrongestLayer) protect companies from brand impersonation, not individuals. Bitdefender protects individuals but is a paid subscription, mostly English, and doesn't explain its reasoning. Its free tool, Scamio, is the closest comparison — but it's a manual chatbot that doesn't explain why a message is flagged, and it's English-only.

 is free, explains every verdict, and genuinely detects scams in Hindi and Tamil — not just translated output.

Team Members : 
Ahana H 
Nishitha Chinni Hariram
N P Shrinidhi Vyairavi

License : Built for Finbehaviour Hackathon, 2026.  Not for production use as-is — see Known Limitations above
