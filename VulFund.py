import requests
from bs4 import BeautifulSoup

# List of domains to whitelist
WHITELIST_DOMAINS = ["google.com", "facebook.com"]

def get_domain(url):
    # Extract domain from URL
    return url.split("//")[-1].split("/")[0]

def analyze_page(url):
    vulnerabilities = []

    domain = get_domain(url)
    if domain in WHITELIST_DOMAINS:
        vulnerabilities.append(f"{domain} is in the whitelist, skipping detailed vulnerability scan.")
        return vulnerabilities

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for XSS (High Risk)
        if soup.find_all('script'):
            vulnerabilities.append("[High] Potential XSS vulnerability: script tags found.")

import requests
from bs4 import BeautifulSoup
import asyncio
import aiohttp
import json
import os

# List of domains to whitelist
WHITELIST_DOMAINS = {"google.com", "facebook.com"}

class VulnerabilityScanner:
    def __init__(self, url, options=None):
        self.url = url
        self.vulnerabilities = []
        self.options = options or {}

    def get_domain(self):
        return self.url.split("//")[-1].split("/")[0]

    async def fetch(self, session, url):
        async with session.get(url) as response:
            return await response.text(), response.cookies, response.headers

    async def analyze_page(self):
        domain = self.get_domain()
        if domain in WHITELIST_DOMAINS:
            self.vulnerabilities.append(f"{domain} is in the whitelist, skipping detailed vulnerability scan.")
            return self.vulnerabilities

        async with aiohttp.ClientSession() as session:
            try:
                page_content, cookies, headers = await self.fetch(session, self.url)
                soup = BeautifulSoup(page_content, 'html.parser')

                if self.options.get("check_xss"):
                    self.check_xss(soup)
                if self.options.get("check_sql_injection"):
                    self.check_sql_injection(soup)
                if self.options.get("check_csrf"):
                    self.check_csrf(soup)
                if self.options.get("check_open_redirect"):
                    self.check_open_redirect(soup)
                if self.options.get("check_insecure_cookies"):
                    self.check_insecure_cookies(cookies)
                if self.options.get("check_sensitive_paths"):
                    await self.check_sensitive_paths(session)
                if self.options.get("check_security_headers"):
                    self.check_security_headers(headers)

                return self.vulnerabilities or ["No vulnerabilities found."]

            except Exception as e:
                self.vulnerabilities.append(f"Error: {str(e)}")
                return self.vulnerabilities

    def check_xss(self, soup):
        if soup.find_all('script'):
            self.vulnerabilities.append("[High] Potential XSS vulnerability: script tags found.")

    def check_sql_injection(self, soup):
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if any(char in action for char in ["'", ";", "--"]):
                self.vulnerabilities.append("[High] Potential SQL Injection risk in form action URL.")

    def check_csrf(self, soup):
        forms = soup.find_all('form')
        for form in forms:
            if form.get('method', '').lower() == "post" and not form.find('input', {'name': 'csrf_token'}):
                self.vulnerabilities.append("[Medium] Potential CSRF risk: missing CSRF token in POST form.")

    def check_open_redirect(self, soup):
        links = soup.find_all('a')
        if any("redirect" in link.get('href', '') for link in links):
            self.vulnerabilities.append("[Medium] Potential Open Redirect found.")

    def check_insecure_cookies(self, cookies):
        for cookie in cookies:
            if not cookie.has_nonstandard_attr('HttpOnly'):
                self.vulnerabilities.append(f"[Low] Cookie '{cookie.name}' is missing HttpOnly flag.")
            if not cookie.has_nonstandard_attr('Secure') and self.url.startswith("https"):
                self.vulnerabilities.append(f"[Low] Cookie '{cookie.name}' is missing Secure flag.")

    async def check_sensitive_paths(self, session):
        sensitive_paths = ['/admin', '/config', '/backup']
        for path in sensitive_paths:
            head_url = self.url + path
            async with session.head(head_url) as response:
                if response.status == 200:
                    self.vulnerabilities.append(f"[High] Sensitive path found: {head_url}")

    def check_security_headers(self, headers):
        missing_headers = []
        if 'X-Frame-Options' not in headers:
            missing_headers.append("X-Frame-Options")
        if 'Content-Security-Policy' not in headers:
            missing_headers.append("Content Security Policy")

        if missing_headers:
            self.vulnerabilities.append(f"[Medium] Missing headers: {', '.join(missing_headers)}.")

    def generate_report(self):
        report = {
            "url": self.url,
            "vulnerabilities": self.vulnerabilities,
        }
        with open("vulnerability_report.json", "w") as f:
            json.dump(report, f, indent=4)

def chatbot():
    print("Chatbot is ready! Type 'exit' to quit.")
    while True:
        user_input = input("You: ")
        if user_input.lower() == "exit":
            break
        elif user_input.lower().startswith("scan "):
            url = user_input.split("scan ", 1)[1].strip()
            options = {
                "check_xss": True,
                "check_sql_injection": True,
                "check_csrf": True,
                "check_open_redirect": True,
                "check_insecure_cookies": True,
                "check_sensitive_paths": True,
                "check_security_headers": True,
            }
            scanner = VulnerabilityScanner(url, options)
            results = asyncio.run(scanner.analyze_page())
            for result in results:
                print("Bot:", result)
            scanner.generate_report()
            print("Bot: Vulnerability report generated as 'vulnerability_report.json'.")
        else:
            print("Bot: You can ask me to 'scan [URL]' to check for vulnerabilities.")

# Run the chatbot
if __name__ == "__main__":
    chatbot()