# Fakemon Vulnerable Web Application

A deliberately insecure web application for security training and vulnerability practice.

**Author:** Nancy Burgos 2025

## Description

Fakemon is a vulnerable web application designed for educational purposes. It contains intentional security vulnerabilities to help students learn about web application security, penetration testing, and secure coding practices.

## Vulnerabilities Included

- SQL Injection in `/search` (unparameterized query)
- Stored XSS via comment content (rendered unsafely with |safe in templates)
- Reflected XSS via echoed query param on some templates
- Broken access control / IDOR via client-controlled cookie and simple admin token
- Weak authentication: login sets client-trustable cookie w/o password checks


## Running Locally 

1. Install Python 3.11+
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database:
   ```bash
   python init_db.py
   ```
4. Run the application:
   ```bash
   python app.py
   ```

## Available on Dockerhub

### Pull 

```bash
docker pull ncburgosb/fakemon
docker run -d -p 5000:5000 --name fakemon ncburgosb/fakemon
```

### Build Locally

```bash
docker build -t fakemon .
docker run -d -p 5000:5000 --name fakemon fakemon
```

Access the application at: `http://localhost:5000`

## Default Credentials

- `admin` / `admin123`
- `test` / `test123`
- `nancy` / `password`

## Lab Guide

Download the full lab guide PDF from the footer of the application.

## Important Security Notice

 **This application is intentionally vulnerable and should ONLY be used in isolated, controlled environments for educational purposes. Do NOT deploy this application to production or expose it to the internet.**

## License

This project is for educational purposes only.

