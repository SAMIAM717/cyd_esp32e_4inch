#!/usr/bin/env python3
"""
Network Scanner Module for CyberSentinel Pro
Provides comprehensive network discovery and port scanning capabilities
"""

import asyncio
import json
import logging
import socket
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor
import ipaddress

try:
    import nmap
except ImportError:
    print("python-nmap not installed. Please run: pip install python-nmap")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1, ICMP
except ImportError:
    print("scapy not installed. Please run: pip install scapy")
    sys.exit(1)

class NetworkScanner:
    """Advanced network scanner using Nmap and Scapy"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        self.executor = ThreadPoolExecutor(max_workers=10)

    async def scan_network(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """
        Perform comprehensive network scan

        Args:
            target: IP address, hostname, or CIDR range
            ports: Port range to scan (e.g., "1-1000", "80,443,8080")

        Returns:
            Dict containing scan results
        """
        try:
            self.logger.info(f"Starting network scan of {target} on ports {ports}")

            # Validate target
            if not self._validate_target(target):
                return {"error": "Invalid target format"}

            # Discover live hosts first
            live_hosts = await self._discover_hosts(target)

            if not live_hosts:
                return {"error": "No live hosts found", "hosts": []}

            # Scan ports on discovered hosts
            scan_results = await self._scan_ports(live_hosts, ports)

            # Perform service detection and OS fingerprinting
            detailed_results = await self._detailed_scan(scan_results)

            result = {
                "scan_time": datetime.now().isoformat(),
                "target": target,
                "ports_scanned": ports,
                "hosts_found": len(live_hosts),
                "hosts": detailed_results
            }

            self.logger.info(f"Network scan completed. Found {len(live_hosts)} hosts")
            return result

        except Exception as e:
            self.logger.error(f"Error during network scan: {e}")
            return {"error": str(e), "hosts": []}

    async def _discover_hosts(self, target: str) -> List[str]:
        """Discover live hosts using ARP scan or ping sweep"""
        try:
            # Try ARP scan first for local networks
            if self._is_local_network(target):
                return await self._arp_scan(target)
            else:
                # Use ping sweep for remote networks
                return await self._ping_sweep(target)
        except Exception as e:
            self.logger.error(f"Host discovery failed: {e}")
            return []

    async def _arp_scan(self, target: str) -> List[str]:
        """Perform ARP scan to discover hosts"""
        try:
            # Create ARP request
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send packet and receive responses
            result = srp(packet, timeout=3, verbose=0)[0]

            live_hosts = []
            for sent, received in result:
                live_hosts.append(received.psrc)

            return live_hosts

        except Exception as e:
            self.logger.error(f"ARP scan failed: {e}")
            return []

    async def _ping_sweep(self, target: str) -> List[str]:
        """Perform ping sweep to discover hosts"""
        try:
            # Parse target to get IP range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            else:
                hosts = [target]

            live_hosts = []

            # Ping hosts concurrently
            tasks = []
            for host in hosts[:254]:  # Limit to prevent excessive scanning
                tasks.append(self._ping_host(host))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, str):
                    live_hosts.append(result)

            return live_hosts

        except Exception as e:
            self.logger.error(f"Ping sweep failed: {e}")
            return []

    async def _ping_host(self, host: str) -> Optional[str]:
        """Ping a single host"""
        try:
            # Create ICMP echo request
            ip = IP(dst=host)
            icmp = ICMP()
            packet = ip/icmp

            # Send packet and wait for response
            response = sr1(packet, timeout=2, verbose=0)

            if response:
                return host
            return None

        except Exception:
            return None

    async def _scan_ports(self, hosts: List[str], ports: str) -> List[Dict[str, Any]]:
        """Scan ports on discovered hosts using Nmap"""
        try:
            results = []

            for host in hosts:
                try:
                    self.logger.info(f"Scanning ports on {host}")

                    # Use Nmap for port scanning
                    scan_args = f"-p {ports} -T4 -A -v"
                    self.nm.scan(host, ports=ports, arguments=scan_args)

                    if host in self.nm.all_hosts():
                        host_data = self.nm[host]

                        # Extract port information
                        ports_info = []
                        if 'tcp' in host_data:
                            for port in host_data['tcp']:
                                port_info = host_data['tcp'][port]
                                ports_info.append({
                                    "port": port,
                                    "protocol": "tcp",
                                    "state": port_info['state'],
                                    "service": port_info.get('name', 'unknown'),
                                    "version": port_info.get('version', ''),
                                    "product": port_info.get('product', '')
                                })

                        host_result = {
                            "ip": host,
                            "hostname": host_data.get('hostname', ''),
                            "state": host_data.get('status', {}).get('state', 'unknown'),
                            "ports": ports_info,
                            "os_fingerprint": host_data.get('osmatch', []),
                            "mac_address": host_data.get('addresses', {}).get('mac', '')
                        }

                        results.append(host_result)

                except Exception as e:
                    self.logger.error(f"Error scanning {host}: {e}")
                    results.append({
                        "ip": host,
                        "error": str(e),
                        "ports": []
                    })

            return results

        except Exception as e:
            self.logger.error(f"Port scanning failed: {e}")
            return []

    async def _detailed_scan(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform detailed analysis on scan results"""
        try:
            for host in hosts:
                if 'ports' in host:
                    # Analyze open ports for vulnerabilities
                    host['vulnerabilities'] = self._analyze_ports(host['ports'])

                    # Calculate risk score
                    host['risk_score'] = self._calculate_risk_score(host)

            return hosts

        except Exception as e:
            self.logger.error(f"Detailed scan failed: {e}")
            return hosts

    def _analyze_ports(self, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze ports for potential vulnerabilities"""
        vulnerabilities = []

        dangerous_ports = {
            21: "FTP - Unencrypted file transfer",
            23: "Telnet - Unencrypted remote access",
            25: "SMTP - May allow relay attacks",
            53: "DNS - May be vulnerable to cache poisoning",
            110: "POP3 - Unencrypted email access",
            143: "IMAP - Unencrypted email access",
            445: "SMB - May be vulnerable to EternalBlue",
            3389: "RDP - Remote Desktop Protocol"
        }

        for port_info in ports:
            if port_info['state'] == 'open':
                port = port_info['port']
                if port in dangerous_ports:
                    vulnerabilities.append({
                        "port": port,
                        "service": port_info.get('service', 'unknown'),
                        "risk": "High",
                        "description": dangerous_ports[port],
                        "recommendation": f"Consider using encrypted alternatives or restrict access to port {port}"
                    })

        return vulnerabilities

    def _calculate_risk_score(self, host: Dict[str, Any]) -> float:
        """Calculate risk score for a host"""
        score = 0.0

        if 'ports' in host:
            open_ports = [p for p in host['ports'] if p.get('state') == 'open']
            score += len(open_ports) * 0.1  # 0.1 per open port

        if 'vulnerabilities' in host:
            score += len(host['vulnerabilities']) * 0.5  # 0.5 per vulnerability

        # Cap at 10.0
        return min(score, 10.0)

    def _validate_target(self, target: str) -> bool:
        """Validate target format"""
        try:
            # Try to parse as IP network
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            try:
                # Try to resolve as hostname
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False

    def _is_local_network(self, target: str) -> bool:
        """Check if target is on local network"""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Check if target is in local subnet
            if "/" in target:
                target_network = ipaddress.ip_network(target, strict=False)
            else:
                target_ip = ipaddress.ip_address(target)
                target_network = ipaddress.ip_network(f"{target}/24", strict=False)

            local_network = ipaddress.ip_network(f"{local_ip}/24", strict=False)

            return target_network.overlaps(local_network)

        except Exception:
            return False
