#!/usr/bin/env python3
"""
Web Scanner Module for CyberSentinel Pro
Provides comprehensive web vulnerability assessment and security analysis
"""

import asyncio
import json
import logging
import re
import socket
import ssl
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
    from bs4 import BeautifulSoup
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("Required packages not installed. Please run: pip install requests beautifulsoup4 urllib3")
    sys.exit(1)

class WebScanner:
    """Advanced web vulnerability scanner"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.verify = False  # Allow self-signed certificates
        self.executor = ThreadPoolExecutor(max_workers=5)

        # Common XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
        ]

        # Common SQL injection payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' UNION SELECT NULL--",
            "admin'--",
        ]

        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'X-Content-Type-Options': 'MIME sniffing protection not enabled',
            'X-Frame-Options': 'Clickjacking protection not enabled',
            'X-XSS-Protection': 'XSS protection not enabled',
            'Content-Security-Policy': 'CSP not implemented',
            'Referrer-Policy': 'Referrer policy not set',
            'Permissions-Policy': 'Permissions policy not set',
        }

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Helper method to make HTTP requests with proper timeout"""
        kwargs.setdefault('timeout', 10)
        if method.lower() == 'get':
            return self.session.get(url, **kwargs)
        elif method.lower() == 'post':
            return self.session.post(url, **kwargs)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    async def scan_website(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive web vulnerability scan

        Args:
            url: Target website URL

        Returns:
            Dict containing scan results
        """
        try:
            self.logger.info(f"Starting web scan of {url}")

            # Validate and normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                return {"error": "Invalid URL format"}

            results = {
                "scan_time": datetime.now().isoformat(),
                "target_url": url,
                "domain": parsed_url.netloc,
                "vulnerabilities": [],
                "security_headers": {},
                "ssl_info": {},
                "technologies": [],
                "forms": [],
                "links": []
            }

            # Run all scan types concurrently
            tasks = [
                self._check_security_headers(url),
                self._analyze_ssl_certificate(url),
                self._detect_technologies(url),
                self._scan_for_xss(url),
                self._scan_for_sqli(url),
                self._check_common_vulnerabilities(url),
                self._crawl_and_analyze(url)
            ]

            scan_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for i, result in enumerate(scan_results):
                if isinstance(result, Exception):
                    self.logger.error(f"Scan task {i} failed: {result}")
                    continue

                if i == 0:  # Security headers
                    results["security_headers"] = result
                elif i == 1:  # SSL info
                    results["ssl_info"] = result
                elif i == 2:  # Technologies
                    results["technologies"] = result
                elif i == 3:  # XSS scan
                    if result:
                        results["vulnerabilities"].extend(result)
                elif i == 4:  # SQLi scan
                    if result:
                        results["vulnerabilities"].extend(result)
                elif i == 5:  # Common vulnerabilities
                    if result:
                        results["vulnerabilities"].extend(result)
                elif i == 6:  # Crawl results
                    crawl_data = result
                    results["forms"] = crawl_data.get("forms", [])
                    results["links"] = crawl_data.get("links", [])

            # Calculate overall risk score
            results["risk_score"] = self._calculate_risk_score(results)

            self.logger.info(f"Web scan completed. Found {len(results['vulnerabilities'])} vulnerabilities")
            return results

        except Exception as e:
            self.logger.error(f"Error during web scan: {e}")
            return {"error": str(e), "vulnerabilities": []}

    async def _check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check for security headers"""
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor, self._make_request, 'get', url
            )

            headers = response.headers
            security_analysis = {}

            for header, description in self.security_headers.items():
                if header in headers:
                    security_analysis[header] = {
                        "present": True,
                        "value": headers[header],
                        "status": "Good"
                    }
                else:
                    security_analysis[header] = {
                        "present": False,
                        "value": None,
                        "status": "Missing",
                        "risk": description
                    }

            return security_analysis

        except Exception as e:
            self.logger.error(f"Security headers check failed: {e}")
            return {}

    async def _analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    ssl_info = {
                        "valid": True,
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "version": cert.get('version'),
                        "serial_number": str(cert.get('serialNumber')),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "cipher": ssock.cipher()
                    }

                    # Check expiration
                    from datetime import datetime
                    try:
                        not_after_str = cert.get('notAfter')
                        if not_after_str:
                            not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                            if not_after < datetime.now():
                                ssl_info["expired"] = True
                                ssl_info["risk"] = "SSL certificate has expired"
                            else:
                                ssl_info["expired"] = False
                        else:
                            ssl_info["expired"] = False
                    except (ValueError, TypeError) as e:
                        self.logger.warning(f"Could not parse certificate expiration date: {e}")
                        ssl_info["expired"] = False

                    return ssl_info

        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            return {"valid": False, "error": str(e)}

    async def _detect_technologies(self, url: str) -> List[str]:
        """Detect web technologies used"""
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor, self._make_request, 'get', url
            )

            technologies = []
            headers = response.headers
            content = response.text.lower()

            # Check server header
            if 'server' in headers:
                technologies.append(f"Server: {headers['server']}")

            # Check common technologies
            tech_indicators = {
                'wordpress': 'WordPress',
                'drupal': 'Drupal',
                'joomla': 'Joomla',
                'jquery': 'jQuery',
                'bootstrap': 'Bootstrap',
                'angular': 'Angular',
                'react': 'React',
                'vue': 'Vue.js',
                'php': 'PHP',
                'asp.net': 'ASP.NET',
                'nodejs': 'Node.js',
                'apache': 'Apache',
                'nginx': 'Nginx',
                'iis': 'IIS'
            }

            for indicator, tech in tech_indicators.items():
                if indicator in content or indicator in str(headers).lower():
                    technologies.append(tech)

            return technologies

        except Exception as e:
            self.logger.error(f"Technology detection failed: {e}")
            return []

    async def _scan_for_xss(self, url: str) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []

        try:
            # Get forms from the page
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor, self._make_request, 'get', url
            )

            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')

                # Test each input field
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')

                    if input_name and input_type in ['text', 'search', 'url', 'email']:
                        for payload in self.xss_payloads[:2]:  # Test with first 2 payloads
                            test_data = {input_name: payload}

                            try:
                                if method == 'post':
                                    test_response = await asyncio.get_event_loop().run_in_executor(
                                        self.executor, self._make_request, 'post', urljoin(url, action), data=test_data, timeout=5
                                    )
                                else:
                                    test_response = await asyncio.get_event_loop().run_in_executor(
                                        self.executor, self._make_request, 'get', urljoin(url, action), params=test_data, timeout=5
                                    )

                                # Check if payload is reflected
                                if payload in test_response.text:
                                    vulnerabilities.append({
                                        "type": "XSS",
                                        "severity": "High",
                                        "url": urljoin(url, action),
                                        "parameter": input_name,
                                        "payload": payload,
                                        "description": "Cross-Site Scripting vulnerability found",
                                        "recommendation": "Implement proper input validation and output encoding"
                                    })
                                    break  # Found vulnerability, no need to test more payloads

                            except Exception as e:
                                continue

        except Exception as e:
            self.logger.error(f"XSS scan failed: {e}")

        return vulnerabilities

    async def _scan_for_sqli(self, url: str) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []

        try:
            # Get forms and test for SQLi
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor, self._make_request, 'get', url
            )

            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')

                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')

                    if input_name and input_type in ['text', 'search', 'url', 'email']:
                        for payload in self.sqli_payloads[:2]:  # Test with first 2 payloads
                            test_data = {input_name: payload}

                            try:
                                if method == 'post':
                                    test_response = await asyncio.get_event_loop().run_in_executor(
                                        self.executor, self._make_request, 'post', urljoin(url, action), data=test_data, timeout=5
                                    )
                                else:
                                    test_response = await asyncio.get_event_loop().run_in_executor(
                                        self.executor, self._make_request, 'get', urljoin(url, action), params=test_data, timeout=5
                                    )

                                # Check for SQL error patterns
                                error_patterns = [
                                    'sql syntax', 'mysql error', 'postgresql error',
                                    'sqlite error', 'oracle error', 'sql server error'
                                ]

                                response_text = test_response.text.lower()
                                if any(pattern in response_text for pattern in error_patterns):
                                    vulnerabilities.append({
                                        "type": "SQL Injection",
                                        "severity": "Critical",
                                        "url": urljoin(url, action),
                                        "parameter": input_name,
                                        "payload": payload,
                                        "description": "SQL Injection vulnerability found",
                                        "recommendation": "Use prepared statements and input validation"
                                    })
                                    break

                            except Exception as e:
                                continue

        except Exception as e:
            self.logger.error(f"SQLi scan failed: {e}")

        return vulnerabilities

    async def _check_common_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Check for common web vulnerabilities"""
        vulnerabilities = []

        try:
            # Check for directory listing
            common_dirs = ['/admin/', '/backup/', '/config/', '/db/', '/logs/', '/tmp/']

            for directory in common_dirs:
                test_url = urljoin(url, directory)
                try:
                    response = await asyncio.get_event_loop().run_in_executor(
                        self.executor, self._make_request, 'get', test_url, timeout=5
                    )

                    if response.status_code == 200:
                        # Check if it looks like directory listing
                        if 'index of' in response.text.lower() or 'parent directory' in response.text.lower():
                            vulnerabilities.append({
                                "type": "Directory Listing",
                                "severity": "Medium",
                                "url": test_url,
                                "description": "Directory listing is enabled",
                                "recommendation": "Disable directory listing in web server configuration"
                            })

                except Exception:
                    continue

            # Check for common vulnerable files
            vulnerable_files = [
                '/.git/HEAD',
                '/.env',
                '/wp-config.php',
                '/config.php',
                '/web.config',
                '/crossdomain.xml',
                '/clientaccesspolicy.xml'
            ]

            for file_path in vulnerable_files:
                test_url = urljoin(url, file_path)
                try:
                    response = await asyncio.get_event_loop().run_in_executor(
                        self.executor, self._make_request, 'get', test_url, timeout=5
                    )

                    if response.status_code == 200:
                        vulnerabilities.append({
                            "type": "Information Disclosure",
                            "severity": "Medium",
                            "url": test_url,
                            "description": f"Sensitive file {file_path} is accessible",
                            "recommendation": "Restrict access to sensitive files"
                        })

                except Exception:
                    continue

        except Exception as e:
            self.logger.error(f"Common vulnerabilities check failed: {e}")

        return vulnerabilities

    async def _crawl_and_analyze(self, url: str) -> Dict[str, Any]:
        """Crawl website and analyze structure"""
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor, self._make_request, 'get', url
            )

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract forms
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    "action": form.get('action', ''),
                    "method": form.get('method', 'get'),
                    "inputs": []
                }

                for input_field in form.find_all('input'):
                    form_data["inputs"].append({
                        "name": input_field.get('name'),
                        "type": input_field.get('type', 'text'),
                        "value": input_field.get('value', '')
                    })

                forms.append(form_data)

            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href and not href.startswith(('mailto:', 'tel:', 'javascript:')):
                    full_url = urljoin(url, href)
                    links.append({
                        "url": full_url,
                        "text": link.get_text().strip(),
                        "external": urlparse(full_url).netloc != urlparse(url).netloc
                    })

            return {
                "forms": forms,
                "links": links[:50]  # Limit to first 50 links
            }

        except Exception as e:
            self.logger.error(f"Crawling failed: {e}")
            return {"forms": [], "links": []}

    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score"""
        score = 0.0

        # Vulnerabilities scoring
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Low')
            if severity == 'Critical':
                score += 3.0
            elif severity == 'High':
                score += 2.0
            elif severity == 'Medium':
                score += 1.0
            elif severity == 'Low':
                score += 0.5

        # Missing security headers
        security_headers = results.get('security_headers', {})
        missing_headers = sum(1 for h in security_headers.values() if not h.get('present', False))
        score += missing_headers * 0.5

        # SSL issues
        ssl_info = results.get('ssl_info', {})
        if ssl_info.get('expired') or not ssl_info.get('valid'):
            score += 2.0

        # Cap at 10.0
        return min(score, 10.0)
