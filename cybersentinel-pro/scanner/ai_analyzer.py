#!/usr/bin/env python3
"""
AI Analyzer Module for CyberSentinel Pro
Provides AI-powered threat analysis and security recommendations using OpenAI
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    import openai
except ImportError:
    print("OpenAI package not installed. Please run: pip install openai")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("requests package not installed. Please run: pip install requests")
    sys.exit(1)

class AIAnalyzer:
    """AI-powered security analysis using OpenAI"""

    def __init__(self, api_key: Optional[str] = None):
        self.logger = logging.getLogger(__name__)

        # Initialize OpenAI client
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if self.api_key:
            openai.api_key = self.api_key
        else:
            self.logger.warning("No OpenAI API key provided. AI analysis will be limited.")

        # Fallback analysis templates when OpenAI is not available
        self.fallback_templates = {
            "network_scan": """
Based on the network scan results, here are the key findings:

**Risk Assessment:**
- {host_count} hosts discovered
- {open_ports} total open ports identified
- Risk score: {risk_score}/10

**Critical Findings:**
{vulnerabilities}

**Recommendations:**
1. Close unnecessary ports
2. Implement firewall rules
3. Regular security audits
4. Monitor for suspicious activity
            """,

            "web_scan": """
Web vulnerability assessment completed:

**Security Headers Analysis:**
{missing_headers}

**Vulnerabilities Found:**
{vulnerabilities}

**SSL/TLS Status:**
{ssl_status}

**Risk Score:** {risk_score}/10

**Immediate Actions Required:**
1. Implement missing security headers
2. Fix identified vulnerabilities
3. Renew SSL certificate if expired
4. Regular security testing
            """,

            "threat_intel": """
Threat Intelligence Analysis for: {indicator}

**Analysis:**
Limited analysis available without OpenAI API key.

**Basic Assessment:**
- Type: {indicator_type}
- Potential Risk: Unknown (API key required for detailed analysis)

**Recommendations:**
1. Configure OpenAI API key for full analysis
2. Manual investigation required
3. Consider blocking suspicious indicators
            """
        }

    def set_api_key(self, api_key: str) -> None:
        """Update the OpenAI API key at runtime and configure the client.

        Args:
            api_key: The OpenAI API key to use for subsequent requests.
        """
        try:
            # Update local state and global OpenAI client
            self.api_key = api_key
            openai.api_key = api_key
            self.logger.info("OpenAI API key updated at runtime")
        except Exception as e:
            # Do not raise further; keep fallback path available
            self.logger.error(f"Failed to set OpenAI API key: {e}")

    async def analyze_scan_results(self, scan_data: Dict[str, Any]) -> str:
        """
        Analyze scan results using AI

        Args:
            scan_data: Scan results from network or web scanner

        Returns:
            AI-generated analysis and recommendations
        """
        try:
            if not self.api_key:
                return self._fallback_analysis(scan_data)

            # Determine scan type
            scan_type = self._determine_scan_type(scan_data)

            # Prepare analysis prompt
            prompt = self._create_analysis_prompt(scan_data, scan_type)

            # Get AI analysis
            analysis = await self._get_openai_analysis(prompt)

            return analysis

        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return self._fallback_analysis(scan_data)

    async def get_threat_intelligence(self, indicator: str) -> str:
        """
        Get threat intelligence for an indicator

        Args:
            indicator: IP, domain, hash, or other indicator

        Returns:
            Threat intelligence analysis
        """
        try:
            if not self.api_key:
                return self._fallback_threat_intel(indicator)

            # Determine indicator type
            indicator_type = self._classify_indicator(indicator)

            # Create threat intel prompt
            prompt = f"""
Analyze the following security indicator for potential threats:

Indicator: {indicator}
Type: {indicator_type}

Please provide:
1. Risk assessment (Low/Medium/High/Critical)
2. Known associations with malicious activity
3. Recommended actions
4. Additional context or intelligence

Be specific and provide actionable intelligence.
            """

            # Get AI analysis
            analysis = await self._get_openai_analysis(prompt)

            return analysis

        except Exception as e:
            self.logger.error(f"Threat intelligence failed: {e}")
            return self._fallback_threat_intel(indicator)

    async def _get_openai_analysis(self, prompt: str) -> str:
        """Get analysis from OpenAI API"""
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert providing detailed security analysis and recommendations. Be thorough, technical, and actionable."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.3
                )
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            self.logger.error(f"OpenAI API call failed: {e}")
            return f"AI analysis unavailable: {str(e)}"

    def _determine_scan_type(self, scan_data: Dict[str, Any]) -> str:
        """Determine the type of scan from the data"""
        if 'hosts' in scan_data:
            return 'network_scan'
        elif 'vulnerabilities' in scan_data and 'security_headers' in scan_data:
            return 'web_scan'
        else:
            return 'unknown'

    def _create_analysis_prompt(self, scan_data: Dict[str, Any], scan_type: str) -> str:
        """Create appropriate analysis prompt based on scan type"""
        if scan_type == 'network_scan':
            return self._create_network_analysis_prompt(scan_data)
        elif scan_type == 'web_scan':
            return self._create_web_analysis_prompt(scan_data)
        else:
            return f"Analyze the following security scan data: {json.dumps(scan_data, indent=2)}"

    def _create_network_analysis_prompt(self, scan_data: Dict[str, Any]) -> str:
        """Create prompt for network scan analysis"""
        hosts = scan_data.get('hosts', [])
        host_count = len(hosts)

        open_ports = sum(len(host.get('ports', [])) for host in hosts
                       if isinstance(host.get('ports'), list))

        vulnerabilities = []
        for host in hosts:
            if 'vulnerabilities' in host:
                vulnerabilities.extend(host['vulnerabilities'])

        prompt = f"""
Analyze this network scan results:

**Scan Summary:**
- Total hosts discovered: {host_count}
- Total open ports: {open_ports}
- Target: {scan_data.get('target', 'Unknown')}

**Hosts Found:**
{json.dumps(hosts, indent=2)}

**Vulnerabilities Identified:**
{json.dumps(vulnerabilities, indent=2)}

Please provide:
1. Overall security assessment
2. Critical vulnerabilities and their impact
3. Risk prioritization
4. Specific remediation steps
5. Monitoring recommendations
6. Compliance considerations

Be specific about ports, services, and potential attack vectors.
        """
        return prompt

    def _create_web_analysis_prompt(self, scan_data: Dict[str, Any]) -> str:
        """Create prompt for web scan analysis"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        security_headers = scan_data.get('security_headers', {})
        ssl_info = scan_data.get('ssl_info', {})

        prompt = f"""
Analyze this web vulnerability scan results:

**Target:** {scan_data.get('target_url', 'Unknown')}

**Vulnerabilities Found:**
{json.dumps(vulnerabilities, indent=2)}

**Security Headers:**
{json.dumps(security_headers, indent=2)}

**SSL/TLS Information:**
{json.dumps(ssl_info, indent=2)}

**Risk Score:** {scan_data.get('risk_score', 'Unknown')}/10

Please provide:
1. Vulnerability severity assessment
2. Missing security controls analysis
3. SSL/TLS security evaluation
4. Exploitation risk assessment
5. Priority remediation steps
6. Web application security best practices
7. Compliance implications

Focus on OWASP Top 10 and real-world exploitation scenarios.
        """
        return prompt

    def _classify_indicator(self, indicator: str) -> str:
        """Classify the type of security indicator"""
        import re
        import ipaddress

        # IP address
        try:
            ipaddress.ip_address(indicator)
            return "IP Address"
        except ValueError:
            pass

        # Domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', indicator):
            return "Domain"

        # Hash
        if re.match(r'^[a-fA-F0-9]{32,128}$', indicator):
            if len(indicator) == 32:
                return "MD5 Hash"
            elif len(indicator) == 40:
                return "SHA-1 Hash"
            elif len(indicator) == 64:
                return "SHA-256 Hash"
            else:
                return "File Hash"

        # Email
        if '@' in indicator and '.' in indicator.split('@')[1]:
            return "Email Address"

        return "Unknown"

    def _fallback_analysis(self, scan_data: Dict[str, Any]) -> str:
        """Provide fallback analysis when OpenAI is not available"""
        scan_type = self._determine_scan_type(scan_data)

        if scan_type == 'network_scan':
            hosts = scan_data.get('hosts', [])
            host_count = len(hosts)
            open_ports = sum(len(host.get('ports', [])) for host in hosts
                           if isinstance(host.get('ports'), list))

            vulnerabilities = []
            for host in hosts:
                if 'vulnerabilities' in host:
                    vulnerabilities.extend(host['vulnerabilities'])

            risk_score = scan_data.get('risk_score', 0)

            vuln_text = "\n".join([f"- {v.get('description', 'Unknown vulnerability')}" for v in vulnerabilities[:5]])

            return self.fallback_templates["network_scan"].format(
                host_count=host_count,
                open_ports=open_ports,
                risk_score=risk_score,
                vulnerabilities=vuln_text or "None identified"
            )

        elif scan_type == 'web_scan':
            vulnerabilities = scan_data.get('vulnerabilities', [])
            security_headers = scan_data.get('security_headers', {})
            ssl_info = scan_data.get('ssl_info', {})

            missing_headers = []
            for header, info in security_headers.items():
                if not info.get('present', False):
                    missing_headers.append(f"- {header}: {info.get('risk', 'Missing')}")

            vuln_text = "\n".join([f"- {v.get('type', 'Unknown')}: {v.get('description', '')}" for v in vulnerabilities[:5]])

            ssl_status = "Valid"
            if ssl_info.get('expired'):
                ssl_status = "EXPIRED - Critical security issue"
            elif not ssl_info.get('valid'):
                ssl_status = "Invalid or not configured"

            risk_score = scan_data.get('risk_score', 0)

            return self.fallback_templates["web_scan"].format(
                missing_headers="\n".join(missing_headers) or "All critical headers present",
                vulnerabilities=vuln_text or "None identified",
                ssl_status=ssl_status,
                risk_score=risk_score
            )

        else:
            return "Unable to analyze scan results. Please configure OpenAI API key for detailed AI analysis."

    def _fallback_threat_intel(self, indicator: str) -> str:
        """Provide fallback threat intelligence"""
        indicator_type = self._classify_indicator(indicator)

        return self.fallback_templates["threat_intel"].format(
            indicator=indicator,
            indicator_type=indicator_type
        )

    async def generate_report(self, scan_data: Dict[str, Any], analysis: str) -> Dict[str, Any]:
        """
        Generate comprehensive security report

        Args:
            scan_data: Original scan data
            analysis: AI analysis results

        Returns:
            Complete report dictionary
        """
        try:
            report = {
                "report_title": "CyberSentinel Pro Security Assessment",
                "generated_at": datetime.now().isoformat(),
                "scan_data": scan_data,
                "ai_analysis": analysis,
                "recommendations": self._extract_recommendations(analysis),
                "risk_summary": self._calculate_overall_risk(scan_data),
                "compliance_status": self._check_compliance(scan_data)
            }

            return report

        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {
                "error": str(e),
                "scan_data": scan_data,
                "ai_analysis": analysis
            }

    def _extract_recommendations(self, analysis: str) -> List[str]:
        """Extract actionable recommendations from analysis"""
        # Simple extraction based on keywords
        recommendations = []

        if "implement" in analysis.lower():
            recommendations.append("Implement recommended security controls")
        if "update" in analysis.lower() or "upgrade" in analysis.lower():
            recommendations.append("Update vulnerable software and systems")
        if "monitor" in analysis.lower():
            recommendations.append("Implement continuous monitoring")
        if "firewall" in analysis.lower():
            recommendations.append("Configure firewall rules")
        if "ssl" in analysis.lower() or "tls" in analysis.lower():
            recommendations.append("Renew and properly configure SSL/TLS certificates")

        if not recommendations:
            recommendations = ["Conduct regular security assessments", "Implement security best practices"]

        return recommendations

    def _calculate_overall_risk(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        risk_score = 0.0
        critical_issues = 0
        high_issues = 0

        # Network scan risk
        if 'hosts' in scan_data:
            for host in scan_data['hosts']:
                if 'risk_score' in host:
                    risk_score = max(risk_score, host['risk_score'])
                if 'vulnerabilities' in host:
                    for vuln in host['vulnerabilities']:
                        if vuln.get('risk') == 'High':
                            high_issues += 1
                        elif vuln.get('risk') == 'Critical':
                            critical_issues += 1

        # Web scan risk
        if 'risk_score' in scan_data:
            risk_score = max(risk_score, scan_data['risk_score'])

        if 'vulnerabilities' in scan_data:
            for vuln in scan_data['vulnerabilities']:
                severity = vuln.get('severity', 'Low')
                if severity == 'Critical':
                    critical_issues += 1
                elif severity == 'High':
                    high_issues += 1

        # Determine overall risk level
        if critical_issues > 0 or risk_score >= 8.0:
            risk_level = "Critical"
        elif high_issues > 0 or risk_score >= 6.0:
            risk_level = "High"
        elif risk_score >= 4.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "level": risk_level,
            "score": risk_score,
            "critical_issues": critical_issues,
            "high_issues": high_issues
        }

    def _check_compliance(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check compliance status against common standards"""
        compliance = {
            "pci_dss": {"status": "Unknown", "issues": []},
            "hipaa": {"status": "Unknown", "issues": []},
            "gdpr": {"status": "Unknown", "issues": []},
            "owasp": {"status": "Unknown", "issues": []}
        }

        # Basic compliance checks
        if 'security_headers' in scan_data:
            headers = scan_data['security_headers']
            if not headers.get('Strict-Transport-Security', {}).get('present'):
                compliance["pci_dss"]["issues"].append("Missing HSTS header")
                compliance["owasp"]["issues"].append("Missing security headers")

        if 'ssl_info' in scan_data:
            ssl_info = scan_data['ssl_info']
            if ssl_info.get('expired'):
                for standard in compliance.values():
                    standard["issues"].append("Expired SSL certificate")

        # Update status based on issues
        for standard, data in compliance.items():
            if data["issues"]:
                data["status"] = "Non-Compliant"
            else:
                data["status"] = "Compliant"

        return compliance
