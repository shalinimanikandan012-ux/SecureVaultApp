# SecureVaultApp 🔐

## About the Project

SecureVaultApp is a Python Flask-based cybersecurity application designed to store notes and files securely using encryption. It provides a simple dashboard where users can add, view, download, and delete their stored data.

## Features

* 🔑 Master password authentication
* 🔒 Secure encryption for notes and uploaded files
* 📝 Add and manage secure notes
* 📁 Upload and download files
* 🗑️ Delete saved notes and files
* 🛡️ CSRF protection for form submissions
* ⏱️ Automatic session lock after inactivity
* 💻 Simple and user-friendly interface

## Technologies Used

* Python
* Flask
* SQLite
* HTML
* CSS
* JavaScript
* AES-256-GCM encryption
* Argon2id password-based key derivation

## Project Structure

```text
SecureVaultApp/
├── app.py
├── requirements.txt
├── .gitignore
├── README.md
├── templates/
│   ├── login.html
│   └── dashboard.html
├── static/
│   ├── style.css
│   └── app.js
└── instance/
    └── vault.db
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/shalinimanikandan012-ux/SecureVaultApp.git
cd SecureVaultApp
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the Application

```bash
python app.py
```

Open your browser and visit:
`http://127.0.0.1:5000`

## Security Notes

* Use a strong master password.
* Never upload real confidential files to a demo deployment.
* Configure a secure session secret using an environment variable.
* This project is an educational prototype and has not been independently audited for production use.
* SQLite data may not persist on hosting platforms with ephemeral storage.

## Project Purpose

This project demonstrates basic web application development and cybersecurity concepts, including authentication, encryption, secure file handling, and web form protection.

## Author

Shalini M.

## License

This project is intended for educational and demonstration purposes.
