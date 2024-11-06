import asyncio
import aiohttp
import json
import logging
from bs4 import BeautifulSoup
import os
import csv
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of domains to whitelist
WHITELIST_DOMAINS = {"google.com", "facebook.com"}

class FetchError(Exception):
    """Custom exception for fetch errors."""
    pass

class VulnerabilityScanner:
    def __init__(self, url, options=None):
        self.url = url
        self.vulnerabilities = []
        self.options = options or {}
        self.session = None

    def get_domain(self):
        return self.url.split("//")[-1].split("/")[0]

    async def fetch(self, session, url):
        headers = {'User-Agent': self.options.get('user_agent', 'Mozilla/5.0')}
        try:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    raise FetchError(f"Failed to fetch {url}: HTTP {response.status}")
                return await response.text(), response.cookies, response.headers
        except Exception as e:
            logging.error(f"Error fetching {url}: {e}")
            raise FetchError(f"Error fetching {url}")

    async def fetch_with_limit(self, session, url, semaphore):
        async with semaphore:
            return await self.fetch(session, url)

    async def analyze_page(self):
        domain = self.get_domain()
        if domain in WHITELIST_DOMAINS:
            self.vulnerabilities.append(f"{domain} is in the whitelist, skipping detailed vulnerability scan.")
            return self.vulnerabilities

        async with aiohttp.ClientSession() as session:
            self.session = session
            semaphore = asyncio.Semaphore(5)  # Limit to 5 concurrent requests
            try:
                page_content, cookies, headers = await self.fetch_with_limit(session, self.url, semaphore)
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
                    await self.check_sensitive_paths(session, semaphore)
                if self.options.get("check_security_headers"):
                    self.check_security_headers(headers)

                return self.vulnerabilities or ["No vulnerabilities found."]
            except FetchError as e:
                self.vulnerabilities.append(f"Error: {str(e)}")
                return self.vulnerabilities

    def check_xss(self, soup):
        if soup.find_all('script'):
            message = "[High] Potential XSS vulnerability: script tags found."
            logging.info(message)
            self.vulnerabilities.append(message)

    def check_sql_injection(self, soup):
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if any(char in action for char in ["'", ";", "--"]):
                message = "[High] Potential SQL Injection risk in form action URL."
                logging.info(message)
                self.vulnerabilities.append(message)

    def check_csrf(self, soup):
        forms = soup.find_all('form')
        for form in forms:
            if form.get('method', '').lower() == "post" and not form.find('input', {'name': 'csrf_token'}):
                message = "[Medium] Potential CSRF risk: missing CSRF token in POST form."
                logging.info(message)
                self.vulnerabilities.append(message)

    def check_open_redirect(self, soup):
        links = soup.find_all('a')
        if any("redirect" in link.get('href', '') for link in links):
            message = "[Medium] Potential Open Redirect found."
            logging.info(message)
            self.vulnerabilities.append(message)

    def check_insecure_cookies(self, cookies):
        for cookie in cookies:
            if not cookie.get('HttpOnly'):
                message = f"[Low] Cookie '{cookie.name}' is missing HttpOnly flag."
                logging.info(message)
                self.vulnerabilities.append(message)
            if not cookie.get('Secure') and self.url.startswith("https"):
                message = f"[Low] Cookie '{cookie.name}' is missing Secure flag."
                logging.info(message)
                self.vulnerabilities.append(message)

    async def check_sensitive_paths(self, session, semaphore):
        sensitive_paths = ['/admin', '/config', '/backup']
        tasks = [self.fetch_with_limit(session, self.url + path, semaphore) for path in sensitive_paths]
        responses = await asyncio.gather(*tasks)

        for path, (page_content, _, _) in zip(sensitive_paths, responses):
            if page_content:  # Assuming any non-empty response indicates a valid path
                message = f"[High] Sensitive path found: {self.url + path}"
                logging.info(message)
                self.vulnerabilities.append(message)

    def check_security_headers(self, headers):
        missing_headers = []
        if 'X-Frame-Options' not in headers:
            missing_headers.append("X-Frame-Options")
        if 'Content-Security-Policy' not in headers:
            missing_headers.append("Content Security Policy")

        if missing_headers:
            message = f"[Medium] Missing headers: {', '.join(missing_headers)}."
            logging.info(message)
            self.vulnerabilities.append(message)

    def generate_report(self, format='json'):
        report = {
            "url": self.url,
            "vulnerabilities": self.vulnerabilities,
        }

        filename = f"vulnerability_report.{format}"
        if format == 'json':
            with open(filename, "w") as f:
                json.dump(report, f, indent=4)
        elif format == 'md':
            with open(filename, "w") as f:
                f.write(f"# Vulnerability Report for {self.url}\n\n")
                for vuln in self.vulnerabilities:
                    f.write(f"- {vuln}\n")
        elif format == 'csv':
            with open(filename, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Description"])
                for vuln in self.vulnerabilities:
                    writer.writerow([vuln])

        logging.info(f"Report generated: {filename}")

def load_config(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def chatbot(options):
    print("Chatbot is ready! Type 'exit' to quit.")
    while True:
        user_input = input("You: ")
        if user_input.lower() == "exit":
            break
        elif user_input.lower().startswith("scan "):
            url = user_input.split("scan ", 1)[1].strip()
            scanner = VulnerabilityScanner(url, options)
            results = asyncio.run(scanner.analyze_page())
            for result in results:
                print("Bot:", result)
            scanner.generate_report(format='json')  # You can change format here
            print("Bot: Vulnerability report generated.")
        elif user_input.lower().startswith("set user-agent "):
            options['user_agent'] = user_input.split("set user-agent ", 1)[1].strip()
            print("Bot: User-Agent updated.")
        else:
            print("Bot: You can ask me to 'scan [URL]' to check for vulnerabilities or 'set user-agent [string]' to change the User-Agent.")

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument('--config', type=str, default='config.json', help='Path to configuration file')
    parser.add_argument('--format', type=str, choices=['json', 'md', 'csv'], default='json', help='Report format')
    args = parser.parse_args()

    options = load_config(args.config)
    chatbot(options)

if __name__ == "__main__":
    main()
