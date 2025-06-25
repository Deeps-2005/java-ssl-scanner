---
title: SSL/HTTPS Vulnerability Scanner
emoji: 🔐
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
---

# 🔐 SSL/HTTPS Vulnerability Scanner & Auto-Patcher

## 📘 Project Overview

This application is a comprehensive tool designed to enhance the security of Java applications by identifying and automatically patching common SSL/HTTPS vulnerabilities. It provides a user-friendly web interface for developers to analyze their code and apply security fixes effortlessly.

### Key Features

*   **Multiple Input Methods**: Analyze code by uploading single `.java` files, pasting code directly into a text area, or uploading a `.zip` archive containing multiple Java files.
*   **Vulnerability Detection**: Scans for a wide range of insecure practices, including:
    *   Improperly configured `X509TrustManager` and `HostnameVerifier`.
    *   Use of weak or outdated TLS/SSL protocols (e.g., SSLv3, TLSv1.0).
    *   Inclusion of weak cipher suites.
    *   Hardcoded passwords and sensitive credentials.
    *   Insecure `SecureRandom` instantiation.
*   **Automated Patching**: Offers an "Auto-Patch" feature that modifies the source code to apply security best practices, replacing insecure implementations with robust alternatives.
*   **Detailed Reporting**: Provides clear, actionable reports for each detected vulnerability, including severity levels, detailed suggestions, and secure code examples.

## 🛠️ Tech Stack

*   **Frontend**: A responsive web interface built with **Streamlit** and also **HTML and Tailwind CSS**.
*   **Backend**: A robust API powered by **FastAPI**.
*   **Core Analyzer**: A static analysis engine written in **Java**, utilizing the **JavaParser** library to inspect the Abstract Syntax Tree (AST) of the source code.
*   **Deployment**: Containerized with **Docker** and designed for easy deployment on platforms like Hugging Face Spaces and render.

---

This project is intended to demonstrate best practices in secure coding and automated code analysis.
