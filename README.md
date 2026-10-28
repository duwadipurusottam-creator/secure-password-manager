# Secure Password Manager

**ICT306 – Advanced Cybersecurity | Assessment 3**

A small web-based password manager written in Python with Flask. This is a solo learning project, built with AI-assisted development, to practise applying basic security controls in a real app.

## What it does

- **Create a vault** with a master password. The password must be at least 12 characters and include an uppercase letter, a lowercase letter, a number and a special character. This is checked in the browser and again on the server.
- **Key derivation:** the server turns the master password into an encryption key using PBKDF2 with SHA-256, 100,000 iterations and a random 32-byte salt.
- **Encryption:** each saved entry (website, username, password) is encrypted with Fernet from the `cryptography` library (AES with an HMAC integrity check).
- **Unlock check:** a small encrypted token is stored with the vault, so a wrong master password is rejected.
- **Brute-force protection:** after 5 unlock attempts without success, unlocking is blocked for 5 minutes.
- **Session cookies** are set to HttpOnly, Secure and SameSite=Strict.
- **Passwords stay hidden** in the list until you click "Show Password".
- **Copy to clipboard**, and the page tries to clear the clipboard after 30 seconds.
- **Lock vault** clears the session and removes the encryption key from server memory.
- Website and username are HTML-escaped before they are shown on the page.
- Security events (vault created, unlocked, failed unlock, locked) are printed to the console.

## Tech stack

- Python, Flask
- HTML, CSS, JavaScript (single page in `templates/index.html`)
- `cryptography` library (PBKDF2, Fernet)

## How to run

You need Python 3 and pip.

```bash
python -m venv venv
```

Activate the virtual environment:

- Windows: `venv\Scripts\activate`
- macOS / Linux: `source venv/bin/activate`

Install the dependencies and start the app:

```bash
pip install flask cryptography
```

```bash
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

## Known limitations

- **Memory only:** all data is kept in memory and is lost when the app stops.
- **One vault:** the app only supports a single vault.
- **No session timeout** yet. The vault stays unlocked until you lock it.
- **No security headers** yet (such as CSP, HSTS or X-Frame-Options).
- **Master password is sent to the server.** Encryption happens on the server, not in the browser, and the key is held in server memory while the vault is unlocked.

## Next steps

- Save the encrypted vault to a file or database.
- Support more than one vault or user.
- Add an inactivity timeout that locks the vault automatically.
- Add security headers.
- Move key derivation and encryption into the browser so the master password never leaves the user's device.
