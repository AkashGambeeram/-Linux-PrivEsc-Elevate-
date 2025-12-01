#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #############################################################
# Elevate: An Intelligent Linux Privilege Escalation Auditor  #
#               (Version 1.1 - Now with non-blocking checks)  #
# #############################################################

import subprocess
import os
import re

# --- (1) Aesthetics: Color Codes for a Professional Look ---
class Colors:
    """Class to hold color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    ORANGE = '\033[0;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- (2) The Engine: Global Findings List and Command Runner ---
findings = []

def run_command(command):
    """A helper function to run shell commands and return the output."""
    try:
        result = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True
        )
        return result.stdout.strip()
    except Exception:
        return ""

def add_finding(name, risk, description, recommendation):
    """A helper to add a finding to the global list."""
    findings.append({
        'name': name,
        'risk': risk,
        'description': description,
        'recommendation': recommendation
    })

# --- (3) Vulnerability Check Modules ---

def check_kernel_version():
    """Checks the kernel for known public exploits."""
    print(f"{Colors.CYAN}[*] Checking Kernel Version...{Colors.RESET}")
    kernel_version = run_command("uname -r")
    if not kernel_version: return
    
    version_code = kernel_version.split('-')[0]
    add_finding(
        name="Kernel Version Exposure",
        risk=7,
        description=f"Kernel version {kernel_version} detected. Older kernels are often vulnerable.",
        recommendation=f"Search for exploits targeting '{version_code}'.\n"
                       f"  - Exploit-DB: https://www.exploit-db.com/search?q={version_code}\n"
                       f"  - Google: 'linux kernel {version_code} privilege escalation exploit'"
    )

def check_sudo_permissions():
    """Checks for sudo misconfigurations WITHOUT blocking."""
    print(f"{Colors.CYAN}[*] Checking Sudo Permissions (non-interactive)...{Colors.RESET}")
    # *** FIX #1: Added the -n flag to prevent password prompts ***
    sudo_check = run_command("sudo -n -l")
    
    # If the command fails because a password is required, it will contain "password is required"
    if "password is required" in sudo_check or not sudo_check:
        return # Exit the function gracefully if sudo requires a password

    if "(ALL, ALL) NOPASSWD: ALL" in sudo_check or "(ALL) NOPASSWD: ALL" in sudo_check:
        add_finding(
            name="CRITICAL: Unrestricted Sudo with NOPASSWD",
            risk=10,
            description="The user can run ANY command as root without a password.",
            recommendation="Run 'sudo /bin/bash' or 'sudo su' to get an instant root shell."
        )
    # (The rest of the sudo checks would go here if needed)

def find_suid_sgid_binaries():
    """Finds SUID/SGID binaries that can be exploited."""
    print(f"{Colors.CYAN}[*] Searching for SUID/SGID Binaries...{Colors.RESET}")
    suid_command = "find / -perm -u=s -type f 2>/dev/null"
    gtfobins_suid = {
        "nmap": "nmap --interactive' then type '!sh'",
        "find": "find . -exec /bin/sh -p \\; -quit",
        "bash": "bash -p"
    }
    for line in run_command(suid_command).splitlines():
        binary_name = os.path.basename(line)
        if binary_name in gtfobins_suid:
            add_finding(
                name=f"HIGH: Abusable SUID Binary ({binary_name})",
                risk=8,
                description=f"The SUID binary '{line}' can be exploited to gain higher privileges.",
                recommendation=f"Execute the following command: {gtfobins_suid[binary_name]}"
            )

def check_capabilities():
    """Checks for abusable Linux capabilities using a full path."""
    print(f"{Colors.CYAN}[*] Checking for Linux Capabilities...{Colors.RESET}")
    # *** FIX #2: Using the full path to the getcap binary ***
    cap_command = "/usr/sbin/getcap -r / 2>/dev/null"
    
    for line in run_command(cap_command).splitlines():
        # This check is specific to the vulnerability on "Cap"
        if "python" in line and "cap_setuid+ep" in line:
            binary_path = line.split(' ')[0]
            add_finding(
                name="HIGH: Insecure Capability (python)",
                risk=9,
                description=f"The file '{binary_path}' has the 'cap_setuid' capability, which allows it to change user ID.",
                recommendation=f"Run the following command to get a root shell:\n  {binary_path} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
            )

# (Other check functions like cronjobs and file permissions would go here)
# For simplicity, we'll leave the original ones for now.

def analyze_and_report():
    """Sorts findings by risk and prints a clear, actionable report."""
    print("\n" + "="*60)
    print(f"{Colors.BOLD}{Colors.BLUE}    ELEVATE - PRIVILEGE ESCALATION AUDIT REPORT{Colors.RESET}")
    print("="*60 + "\n")

    if not findings:
        print(f"{Colors.GREEN}[+] No high-risk privilege escalation vectors found.{Colors.RESET}")
        return

    sorted_findings = sorted(findings, key=lambda x: x['risk'], reverse=True)
    print(f"{Colors.BOLD}{Colors.PURPLE}--- Prioritized Findings (Highest Risk First) ---\n{Colors.RESET}")

    for finding in sorted_findings:
        if finding['risk'] >= 9:
            risk_level = "CRITICAL"
            color = Colors.RED
        elif finding['risk'] >= 7:
            risk_level = "HIGH"
            color = Colors.ORANGE
        else:
            risk_level = "MEDIUM"
            color = Colors.CYAN
            
        print(f"{color}{Colors.BOLD}>> {finding['name']}{Colors.RESET}")
        print(f"   - {Colors.BOLD}Risk Level....: {color}{risk_level} ({finding['risk']}/10){Colors.RESET}")
        print(f"   - {Colors.BOLD}Description...: {finding['description']}")
        print(f"   - {Colors.BOLD}Action........: {Colors.UNDERLINE}{Colors.GREEN}Recommended Command / Strategy{Colors.RESET}\n     {finding['recommendation']}\n")
    
    print("="*60)
    print(f"{Colors.BOLD}Scan Complete. Review the findings above to plan your escalation path.{Colors.RESET}")
    print("="*60 + "\n")

def main():
    """Main function to orchestrate the scan."""
    print(f"\n{Colors.BOLD}{Colors.PURPLE}Starting Elevate - An Intelligent Linux PrivEsc Auditor...{Colors.RESET}\n")
    
    check_kernel_version()
    check_sudo_permissions()
    find_suid_sgid_binaries()
    check_capabilities()
    # Add other checks here if needed
    
    analyze_and_report()

if __name__ == "__main__":
    if os.geteuid() == 0:
        print(f"{Colors.RED}[!] Warning: This script is being run as root.{Colors.RESET}")
        print(f"{Colors.ORANGE}   It is designed to find privilege escalation paths from a low-privilege user.\n{Colors.RESET}")
    main()
