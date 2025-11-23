#!/usr/bin/env python3
"""
CyberSentinel Pro - AI-Powered Cybersecurity Platform
Main CLI Interface
"""

import os
import sys
import json
import time
import asyncio
from datetime import datetime
from pathlib import Path

# Add scanner directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'scanner'))

try:
    from scanner.network_scanner import NetworkScanner
    from scanner.web_scanner import WebScanner
    from scanner.ai_analyzer import AIAnalyzer
except ImportError as e:
    print(f"Error importing scanner modules: {e}")
    print("Please ensure all scanner modules are installed properly.")
    sys.exit(1)

class CyberSentinelCLI:
    def __init__(self):
        self.network_scanner = None
        self.web_scanner = None
        self.ai_analyzer = None
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)

    def initialize_scanners(self):
        """Initialize scanner instances with error handling"""
        try:
            print("🔧 Initializing CyberSentinel scanners...")
            self.network_scanner = NetworkScanner()
            self.web_scanner = WebScanner()
            self.ai_analyzer = AIAnalyzer()
            print("✅ Scanners initialized successfully!")
            return True
        except Exception as e:
            print(f"❌ Error initializing scanners: {e}")
            return False

    def display_banner(self):
        """Display the CyberSentinel Pro banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  CyberSentinel Pro 🛡️                     ║
║              AI-Powered Cybersecurity Platform              ║
║                Professional Penetration Testing             ║
╚══════════════════════════════════════════════════════════════╝

🔥 Advanced Features:
   • Network Discovery & Port Scanning
   • Web Vulnerability Assessment
   • AI-Powered Threat Analysis
   • Comprehensive Security Reports
   • Professional-Grade Tools
        """
        print(banner)

    def display_menu(self):
        """Display the main menu options"""
        menu = """
┌─────────────── 🛡️  Main Menu 🛡️ ───────────────┐
│                                               │
│  1. 🌐 Network Scan                          │
│  2. 🕸️  Web Vulnerability Scan               │
│  3. 🤖 AI Security Analysis                   │
│  4. 📊 View Scan Results                     │
│  5. ⚙️  Configuration                         │
│  6. 📖 Help & Documentation                   │
│  7. 🚪 Exit                                   │
│                                               │
└───────────────────────────────────────────────┘
        """
        print(menu)

    def get_user_choice(self):
        """Get and validate user menu choice"""
        while True:
            try:
                choice = input("\n🎯 Select option (1-7): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6', '7']:
                    return choice
                else:
                    print("❌ Invalid choice! Please select 1-7.")
            except KeyboardInterrupt:
                print("\n\n👋 Exiting CyberSentinel Pro...")
                sys.exit(0)
            except Exception as e:
                print(f"❌ Error reading input: {e}")

    def network_scan_menu(self):
        """Network scanning interface with proper error handling"""
        print("\n" + "="*60)
        print("🌐 NETWORK SCANNING MODULE")
        print("="*60)

        if not self.network_scanner:
            print("❌ Network scanner not initialized!")
            return

        try:
            # Get target input
            target = input("🎯 Enter target (IP/hostname/range): ").strip()
            if not target:
                print("❌ No target specified!")
                return

            # Validate target format
            if not self.validate_target(target):
                print("❌ Invalid target format!")
                return

            # Get scan type
            print("\n📋 Scan Types:")
            print("1. Quick Scan (Top 100 ports)")
            print("2. Full Scan (All 65535 ports)")
            print("3. Custom Port Range")

            scan_type = input("Select scan type (1-3): ").strip()

            ports = None
            if scan_type == "1":
                ports = "1-100"
            elif scan_type == "2":
                ports = "1-65535"
            elif scan_type == "3":
                ports = input("Enter port range (e.g., 80,443,8080 or 1-1000): ").strip()
            else:
                print("❌ Invalid scan type!")
                return

            print(f"\n🚀 Starting network scan of {target}...")
            print("⏳ This may take several minutes depending on scope...")

            # Perform the scan
            results = asyncio.run(self.network_scanner.scan_network(target, ports))

            if results and results.get('hosts'):
                print(f"\n✅ Scan completed! Found {len(results['hosts'])} hosts")
                self.save_results(results, f"network_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                self.display_network_results(results)
            else:
                print("❌ No results found or scan failed!")

        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
        except Exception as e:
            print(f"❌ Error during network scan: {e}")
            print("Please check your target and try again.")

    def web_scan_menu(self):
        """Web vulnerability scanning interface"""
        print("\n" + "="*60)
        print("🕸️  WEB VULNERABILITY SCANNING MODULE")
        print("="*60)

        if not self.web_scanner:
            print("❌ Web scanner not initialized!")
            return

        try:
            target_url = input("🎯 Enter target URL (e.g., https://example.com): ").strip()
            if not target_url:
                print("❌ No URL specified!")
                return

            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url

            print(f"\n🚀 Starting web vulnerability scan of {target_url}...")
            print("⏳ Scanning for common vulnerabilities...")

            results = asyncio.run(self.web_scanner.scan_website(target_url))

            if results:
                print(f"\n✅ Web scan completed!")
                self.save_results(results, f"web_scan_{target_url.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                self.display_web_results(results)
            else:
                print("❌ Web scan failed or no results!")

        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
        except Exception as e:
            print(f"❌ Error during web scan: {e}")

    def ai_analysis_menu(self):
        """AI-powered security analysis interface"""
        print("\n" + "="*60)
        print("🤖 AI SECURITY ANALYSIS MODULE")
        print("="*60)

        if not self.ai_analyzer:
            print("❌ AI analyzer not initialized!")
            return

        try:
            print("📋 Analysis Options:")
            print("1. Analyze latest scan results")
            print("2. Upload custom report for analysis")
            print("3. Threat intelligence lookup")

            choice = input("Select option (1-3): ").strip()

            if choice == "1":
                # Find latest results
                result_files = list(self.results_dir.glob("*.json"))
                if not result_files:
                    print("❌ No scan results found!")
                    return

                latest_file = max(result_files, key=os.path.getctime)
                print(f"\n🔍 Analyzing: {latest_file.name}")

                with open(latest_file, 'r') as f:
                    scan_data = json.load(f)

                analysis = asyncio.run(self.ai_analyzer.analyze_scan_results(scan_data))
                if analysis:
                    print("\n🤖 AI Analysis Results:")
                    print(analysis)
                    self.save_results({"ai_analysis": analysis}, f"ai_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

            elif choice == "2":
                file_path = input("📁 Enter path to report file: ").strip()
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    analysis = asyncio.run(self.ai_analyzer.analyze_scan_results(data))
                    if analysis:
                        print("\n🤖 AI Analysis Results:")
                        print(analysis)
                else:
                    print("❌ File not found!")

            elif choice == "3":
                indicator = input("🔍 Enter IoC (IP, domain, hash): ").strip()
                if indicator:
                    threat_intel = asyncio.run(self.ai_analyzer.get_threat_intelligence(indicator))
                    if threat_intel:
                        print("\n🛡️ Threat Intelligence:")
                        print(threat_intel)
                else:
                    print("❌ No indicator provided!")

            else:
                print("❌ Invalid choice!")

        except Exception as e:
            print(f"❌ Error during AI analysis: {e}")

    def view_results_menu(self):
        """View saved scan results"""
        print("\n" + "="*60)
        print("📊 SCAN RESULTS VIEWER")
        print("="*60)

        result_files = list(self.results_dir.glob("*.json"))
        if not result_files:
            print("❌ No scan results found!")
            return

        print(f"📁 Found {len(result_files)} result files:\n")
        for i, file in enumerate(result_files, 1):
            file_time = datetime.fromtimestamp(file.stat().st_mtime)
            print(f"{i}. {file.name} - {file_time.strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            choice = int(input(f"\nSelect file to view (1-{len(result_files)}): "))
            if 1 <= choice <= len(result_files):
                selected_file = result_files[choice-1]
                with open(selected_file, 'r') as f:
                    data = json.load(f)
                print(f"\n📄 Contents of {selected_file.name}:")
                print(json.dumps(data, indent=2))
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Please enter a valid number!")
        except Exception as e:
            print(f"❌ Error reading file: {e}")

    def configuration_menu(self):
        """Configuration and settings"""
        print("\n" + "="*60)
        print("⚙️  CONFIGURATION MENU")
        print("="*60)

        print("🔧 Current Settings:")
        print(f"   • Results Directory: {self.results_dir}")
        print(f"   • Network Scanner: {'✅ Ready' if self.network_scanner else '❌ Not initialized'}")
        print(f"   • Web Scanner: {'✅ Ready' if self.web_scanner else '❌ Not initialized'}")
        print(f"   • AI Analyzer: {'✅ Ready' if self.ai_analyzer else '❌ Not initialized'}")

        print("\n📋 Configuration Options:")
        print("1. Reinitialize scanners")
        print("2. Set OpenAI API key")
        print("3. View system info")
        print("4. Back to main menu")

        choice = input("Select option (1-4): ").strip()

        if choice == "1":
            if self.initialize_scanners():
                print("✅ Scanners reinitialized successfully!")
            else:
                print("❌ Failed to initialize scanners!")
        elif choice == "2":
            api_key = input("🔑 Enter OpenAI API key: ").strip()
            if api_key:
                os.environ['OPENAI_API_KEY'] = api_key
                print("✅ API key set!")
            else:
                print("❌ No API key provided!")
        elif choice == "3":
            self.show_system_info()
        elif choice == "4":
            return
        else:
            print("❌ Invalid choice!")

    def show_help(self):
        """Display help and documentation"""
        help_text = """
📖 CYBERSENTINEL PRO HELP

🛡️  OVERVIEW:
CyberSentinel Pro is an AI-powered cybersecurity platform designed for
security professionals to conduct comprehensive penetration testing and
vulnerability assessments.

🌐 NETWORK SCANNING:
• Discover live hosts on networks
• Port scanning with service detection
• OS fingerprinting and banner grabbing
• Custom port ranges and scan types

🕸️  WEB VULNERABILITY SCANNING:
• HTTP security headers analysis
• Common vulnerability detection (XSS, SQLi, etc.)
• Directory and file enumeration
• SSL/TLS certificate analysis

🤖 AI ANALYSIS:
• Automated vulnerability assessment
• Threat intelligence correlation
• Risk scoring and prioritization
• Remediation recommendations

📊 RESULTS MANAGEMENT:
• Automatic report generation
• JSON and HTML export formats
• Historical scan comparison
• Customizable report templates

⚙️  CONFIGURATION:
• Scanner optimization settings
• API integration management
• Custom wordlists and payloads
• Output format preferences

🆘 SUPPORT:
For technical support or feature requests, please visit:
https://github.com/cybersentinel-pro

Press Enter to continue...
        """
        print(help_text)
        input()

    def show_system_info(self):
        """Display system information"""
        import platform
        import psutil

        print("\n💻 SYSTEM INFORMATION:")
        print(f"   • Platform: {platform.platform()}")
        print(f"   • Python Version: {sys.version}")
        print(f"   • CPU Cores: {psutil.cpu_count()}")
        print(f"   • Memory: {psutil.virtual_memory().total // (1024**3)} GB")
        print(f"   • Disk Space: {psutil.disk_usage('/').free // (1024**3)} GB free")

    def validate_target(self, target):
        """Validate target format"""
        import re
        # Simple validation for IP, hostname, or CIDR
        patterns = [
            r'^(\d{1,3}\.){3}\d{1,3}$',  # IP
            r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',  # CIDR
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Domain
            r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$'  # IP range
        ]
        return any(re.match(pattern, target) for pattern in patterns)

    def save_results(self, results, filename):
        """Save scan results to file"""
        try:
            filepath = self.results_dir / f"{filename}.json"
            with open(filepath, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'results': results
                }, f, indent=2)
            print(f"💾 Results saved to: {filepath}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")

    def display_network_results(self, results):
        """Display network scan results summary"""
        print("\n🌐 NETWORK SCAN SUMMARY:")
        print("="*50)

        if 'hosts' in results:
            for host in results['hosts'][:5]:  # Show first 5 hosts
                print(f"🖥️  Host: {host.get('ip', 'Unknown')}")
                if 'ports' in host:
                    open_ports = [p for p in host['ports'] if p.get('state') == 'open']
                    print(f"   📡 Open Ports: {len(open_ports)}")
                    for port in open_ports[:3]:  # Show first 3 ports
                        service = port.get('service', 'unknown')
                        print(f"      • {port['port']}/{port.get('protocol', 'tcp')} - {service}")
                print()

            if len(results['hosts']) > 5:
                print(f"... and {len(results['hosts']) - 5} more hosts")

    def display_web_results(self, results):
        """Display web scan results summary"""
        print("\n🕸️  WEB SCAN SUMMARY:")
        print("="*50)

        if 'vulnerabilities' in results:
            vuln_count = len(results['vulnerabilities'])
            print(f"🔍 Vulnerabilities Found: {vuln_count}")

            for vuln in results['vulnerabilities'][:3]:  # Show first 3
                severity = vuln.get('severity', 'Unknown')
                print(f"   ⚠️  {vuln.get('type', 'Unknown')} - {severity}")
                print(f"      Description: {vuln.get('description', 'No description')}")
                print()

    def run(self):
        """Main application loop"""
        try:
            self.display_banner()

            # Initialize scanners
            if not self.initialize_scanners():
                print("⚠️  Some scanners failed to initialize. Some features may be limited.")
                input("Press Enter to continue anyway...")

            while True:
                self.display_menu()
                choice = self.get_user_choice()

                if choice == '1':
                    self.network_scan_menu()
                elif choice == '2':
                    self.web_scan_menu()
                elif choice == '3':
                    self.ai_analysis_menu()
                elif choice == '4':
                    self.view_results_menu()
                elif choice == '5':
                    self.configuration_menu()
                elif choice == '6':
                    self.show_help()
                elif choice == '7':
                    print("\n👋 Thank you for using CyberSentinel Pro!")
                    break

                input("\nPress Enter to continue...")

        except KeyboardInterrupt:
            print("\n\n👋 Exiting CyberSentinel Pro...")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            print("Please report this issue if it persists.")

def main():
    """Entry point for CyberSentinel Pro CLI"""
    cli = CyberSentinelCLI()
    cli.run()

if __name__ == "__main__":
    main()
