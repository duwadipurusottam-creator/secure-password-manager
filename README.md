# Secure Password Manager  
**ICT306 – Advanced Cybersecurity | Assessment 3**

A security-first, zero-knowledge password manager built using **Python (Flask)** that demonstrates the full implementation of the **Secure Software Development Lifecycle (SSDLC)**.  
The application focuses on strong cryptography, secure authentication, defense-in-depth, and comprehensive security testing.

---

## Project Overview

This project implements a **web-based secure password manager** where all sensitive data is encrypted using a master password derived key.  
The system is designed so that **no plaintext passwords are ever stored**, and the server cannot access user credentials without the correct master password.

The project was developed following **OWASP best practices** and demonstrates practical security controls against common attack vectors.

---

## Key Security Features

- **Zero-Knowledge Architecture**  
  - Master password is never stored or transmitted
  - Encryption key derived using PBKDF2

- **Strong Cryptography**
  - PBKDF2 with SHA-256
  - 100,000 iterations
  - 32-byte cryptographically secure salt
  - Fernet encryption (AES with HMAC integrity)

- **Rate Limiting & Brute Force Protection**
  - Account locked after 5 failed login attempts
  - 5-minute lockout window

- **Secure Session Management**
  - HTTPOnly, Secure, SameSite cookies
  - Automatic session timeout after 15 minutes of inactivity

- **Clipboard Protection**
  - Auto-clear clipboard after 30 seconds

- **Input Validation & Sanitization**
  - Regex-based password validation
  - Length limits to prevent DoS attacks
  - XSS-safe rendering

- **Security Headers**
  - Content Security Policy (CSP)
  - HSTS
  - X-Frame-Options
  - X-Content-Type-Options

---

## SSDLC Phases Implemented

1. **Security Requirements & Planning**
2. **Threat Modeling (STRIDE)**
3. **Secure Design (Defense in Depth, Least Privilege)**
4. **Secure Implementation (OWASP Guidelines)**
5. **Security Testing (SAST, DAST, OWASP Top 10)**
6. **Secure Deployment**
7. **Maintenance & Monitoring (Security Logging)**

---

## Security Testing Summary

- **Total Tests Conducted:** 36  
- **Pass Rate:** 100%

### Testing Techniques Used:
- **SAST:** Bandit static analysis (Python)
- **DAST:** Manual attack simulation
- **OWASP Top 10 Validation**
- **Authentication & Session Abuse Testing**
- **Rate Limiting & Lockout Validation**

All critical vulnerabilities were either mitigated or fully prevented.

---

## Technology Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Cryptography:** `cryptography` library (PBKDF2, Fernet)
- **Testing:** Bandit (SAST), manual DAST
- **Version Control:** Git, GitHub

---

## How to Run the Application

### Prerequisites
- Python 3.10+
- pip

### Setup
```bash
pip install flask cryptography

