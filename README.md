# 🔐 Secure Data Vault — Pro

A secure Streamlit app with encryption, license key system, and Gumroad webhook integration.

## 🚀 Features

User registration & login with encrypted passwords

Store & retrieve encrypted text and files

License key required for access (auto-generated on Gumroad purchase)

Admin panel to generate/manage keys & view logs

Gumroad webhook: sends license key to buyer via email

## 📦 Installation
- git clone https://github.com/yourusername/secure-data-vault-pro.git
- cd secure-data-vault-pro
- pip install -r requirements.txt

## ⚙️ Environment Variables

Create a .env file with:

- ADMIN_KEY=your_admin_key
- SMTP_SERVER=your_smtp_server
- SMTP_PORT=587
- SMTP_USERNAME=your_email
- SMTP_PASSWORD=your_password

## ▶️ Run
streamlit run pro_vault_pro.py
