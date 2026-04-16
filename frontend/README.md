# IntelliWall — AI-Powered Next Generation Firewall

> *Traditional firewalls block what they know. IntelliWall learns behavior, deceives attackers, predicts what they'll do next, and shares intelligence globally.*

---

## The Problem

Traditional firewalls use static rules — they only block attacks they already know. Modern attackers use encrypted traffic, zero-day exploits, AI-powered tools, and coordinated botnets that signature-based firewalls are completely blind to. Meanwhile 80% of internet traffic is now encrypted, and attackers deliberately craft packets to evade detection.

---

## What We Built

IntelliWall is an AI-powered NGFW that combines federated machine learning, honeypot deception technology, zero trust scoring, and real-time threat intelligence in one unified open-source system.

**Tech Stack:** Python 3.9, FastAPI, Scapy, Scikit-learn, SQLite, WebSocket, Next.js, React, Leaflet, Recharts

---

## Core Innovations

**Federated Learning Engine**
Three independent Isolation Forest models score every packet separately. Final decision is the ensemble average. Harder to fool than any single model — attackers cannot craft traffic to bypass three independently trained models simultaneously.

**Deception Escalation Engine**
Unlike traditional honeypots that block immediately, IntelliWall escalates deception over 4 stages. Hit 1 gives fake viewer access, hit 2 gives fake admin access, hit 3 gives a fake database dump, hit 4 triggers a full block. By stage 3 the attacker has revealed their complete toolset, credentials they're trying, and attack patterns — without touching any real system.

**Attacker Intent Classifier**
AI classifies why the attacker is there — not just what they're doing. Classifies intent as Data Theft, Sabotage, Espionage, Ransomware Prep, Cryptomining, or Competitor Intel with a confidence percentage and business risk statement. Translates technical attacks into language any CEO can understand.

**MITRE ATT&CK Kill Chain Mapping**
Automatically maps each attack to the correct kill chain stage — Reconnaissance, Exploitation, C2 Channel, Exfiltration, or Impact — and predicts the next likely stage before it occurs.

**Threat Actor Attribution**
Pattern-matches attack behavior to known APT groups including APT28 Fancy Bear, APT41 Double Dragon, Lazarus Group, and Kimsuky based on country, ISP, tools used, and traffic patterns.

**Federated Threat Sharing**
When any node blocks a high-risk attacker, the IP is instantly shared to all federated nodes worldwide. Delhi, Bangalore, Singapore, and London pre-block the IP before the attacker can reach them. One attack anywhere means everyone is protected everywhere.

**Attack Pattern Correlation Engine**
Detects coordinated botnet campaigns by correlating multiple IPs attacking within the same time window. Traditional firewalls see 5 individual events. IntelliWall sees one organized campaign and fires a real-time alert.

**Attacker Behavioral DNA**
Generates a unique visual barcode per attacker from their behavioral features — packet count, entropy, timing, attack patterns. Same threat actor using different IPs produces visually similar DNA, making IP rotation visible.

**Attacker Conversation Log**
Shows the real-time exchange between attacker and honeypot in chat format. Attacker sends POST /login, server returns fake token. Attacker goes deeper, server gives fake superadmin access. Judges instantly understand the deception without any security knowledge.

**Zero Trust Score Card**
Breaks down exactly why an IP was denied — geo risk, proxy detection, hosting network, behavioral history, trust decay — each factor shown with its contribution. Nothing is trusted by default. Everything must earn access.

**Two-Layer Fingerprinting**
Application layer captures HTTP scanner signatures, credentials attempted, and path probed. Network layer captures packet count, byte rate, entropy, and suspicious flags. Both shown side by side when any log row is expanded.

**Live WebSocket Threat Notifications**
Real-time popup alerts the instant a threat is detected. No 3-second polling delay. Color-coded by threat type with auto-dismiss timer.

---

## Running the Project

**Backend**
```bash
cd backend
venv\Scripts\activate
uvicorn app.main:app --reload 
```

**Frontend**
```bash
cd frontend
npm run dev
```

Open `http://localhost:3000` — login with `admin@intelliwall.io` / `admin123`
email=admin@sentinel.com / pass=admin123

**Demo**
Click the Reset button, then click Demo Attack. A 7-stage attack scenario fires live — Port Scan, Service Probe, Exploit Attempt, Credential Brute Force, Honeypot Trigger, DDoS Burst, DDoS Escalation. Watch the dashboard update in real time.

---

## Why It Matters

Palo Alto and Darktrace charge $50,000–$100,000 per year and still don't include honeypot deception, intent classification, or attacker DNA in a single product. IntelliWall combines all of this in one open-source system — designed for the reality that modern attacks are AI-powered, coordinated, and encrypted.

*"Every feature solves a specific gap in traditional firewalls. Together — 13 innovations in one system."*
