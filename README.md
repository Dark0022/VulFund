# Vulnerability Scanner

A simple command-line vulnerability scanner that checks web pages for common security vulnerabilities. This tool analyzes various aspects of a webpage and identifies potential risks.

## Features

- **XSS Detection**: Scans for potential Cross-Site Scripting vulnerabilities by looking for `<script>` tags.
- **SQL Injection Checks**: Analyzes form action URLs for potentially dangerous characters.
- **CSRF Protection**: Checks for the presence of CSRF tokens in POST forms.
- **Open Redirect Detection**: Identifies potential open redirects in links.
- **Insecure Cookie Checks**: Verifies the presence of `HttpOnly` and `Secure` flags on cookies.
- **Sensitive Path Identification**: Checks for common sensitive paths (e.g., `/admin`, `/config`).
- **Security Header Checks**: Ensures critical security headers are present.

"This is a small update to trigger a commit!" 
"This is a small update to trigger a commit!" 
