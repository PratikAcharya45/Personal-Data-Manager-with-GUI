# Personal-Data-Manager-with-GUI
Keep your datas secured

Personal Data Manager (PDM)

A simple, secure password manager built with NiceGUI and Python. This app lets you store, view, edit, and delete your credentials for different websites, all protected by encryption and your master password.

Features:
- User sign up and login
- Secure password storage using encryption (Fernet + PBKDF2)
- Add, view, edit, and delete credentials
- Dark mode toggle
- Simple, modern web interface

Requirements:
- Python 3.8+
- NiceGUI
- cryptography

Installation:
1. Clone this repository or copy the files to your project folder.
2. Install dependencies:
   pip install nicegui cryptography

Usage:
1. Run the app:
   python pdm.py
2. Open your browser and go to:
   http://localhost:8000
3. Sign up for a new account or log in with an existing one.
4. Add, view, edit, or delete your credentials as needed.

How it works:
- Each user has their own encrypted data file in the user_data/ folder.
- Passwords and user IDs are encrypted using a key derived from your master password.
- The app never stores your plain password or encryption key.

Security Notes:
- This is a demo/educational project.
- The salt for key derivation is hardcoded for simplicity. In production, use a unique, secret salt (e.g., from an environment variable).
- Always use strong, unique passwords for your accounts.
- Do not use this for real, sensitive data without further security review.

Customization:
- You can change the port or run in native window mode by editing the NATIVE and WINDOW_SIZE variables in pdm.py.
- To reset all data, delete the user_data/ folder.

License:
This project is for educational purposes. Feel free to modify and use it as you like. 
