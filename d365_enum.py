import sys
import argparse
import requests
import random
import string
import time
import colorama
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL Warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Initialize Colors
colorama.init()
GREEN = colorama.Fore.GREEN
RED = colorama.Fore.RED
BLUE = colorama.Fore.BLUE
CYAN = colorama.Fore.CYAN
YELLOW = colorama.Fore.YELLOW
RESET = colorama.Fore.RESET
GRAY = colorama.Fore.LIGHTBLACK_EX

# --- ENUMERATION WORDLISTS ---

# 1. Core Platform Paths
core_paths = [
    '/main.aspx', 
    '/default.aspx',
    '/loader.aspx',
    '/_root/homepage.aspx',
    '/About/About.aspx',
    '/web.config',
    '/clientaccesspolicy.xml',
    '/crossdomain.xml',
    '/robots.txt'
]

# 2. Debugging & ASP.NET Leaks
debug_paths = [
    '/Help',
    '/api/help',
    '/trace.axd',
    '/elmah.axd',
    '/error.aspx',
    '/_common/error/errorhandler.aspx'
]

# 3. API Discovery
api_paths = [
    '/XRMServices/2011/Organization.svc',
    '/XRMServices/2011/Discovery.svc',
    '/XRMServices/2011/OrganizationData.svc',
    '/api/data/v9.0/',
    '/api/data/v9.1/',
    '/api/data/v9.2/',
    '/api/discovery/v9.0/',
    '/api/discovery/v9.1/'
]

# 4. Solution Fingerprinting
solutions_db = {
    "ClickDimensions (Marketing)": "/_static/clickdimensions.css",
    "Field Service": "/WebResources/msdyn_/FieldService/System.js",
    "Project Service": "/WebResources/msdyn_/ProjectService/System.js",
    "LinkedIn Sales Navigator": "/WebResources/li_linkedinloader.js",
    "Voice of the Customer": "/WebResources/msdyn_voc/voc.js",
    "Unified Service Desk": "/WebResources/msdyusd_/USD_Global.js",
    "AdxStudio (Legacy Portal)": "/_layouts/1033/settings.js"
}

# 5. Portal Specifics
portal_paths = [
    '/_services/about',
    '/_services/registry',
    '/SignIn',
    '/Account/Login/LogOff',
    '/_odata/contacts',
    '/_odata/accounts'
]

def banner():
    print(rf"""{CYAN}
________                              .__                ___________                     
\______ \ ___.__. ____ _____    _____ |__| ____   ______ \_   _____/ ____  __ __  _____  
 |    |  <   |  |/    \\__  \  /     \|  |/ ___\ /  ___/  |    __)_ /    \|  |  \/     \ 
 |    `   \___  |   |  \/ __ \|  Y Y  \  \  \___ \___ \   |        \   |  \  |  /  Y Y  \
/_______  / ____|___|  (____  /__|_|  /__|\___  >____  > /_______  /___|  /____/|__|_|  /
        \/\/         \/     \/      \/        \/     \/          \/     \/            \/ 
    D365 Enumeration Tool v3.0 | Enum Mode
    Created by Sierra312 https://github.com/Sierra312 | In memory of Noble 6 
    {RESET}""")

def get_random_string(length=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def auto_calibrate(url, proxies, headers):
    """Detects soft 404 size and code."""
    print(f"{BLUE}[*] Calibrating (Detecting default error pages)...{RESET}")
    random_path = f"/{get_random_string()}"
    full_url = url + random_path
    
    try:
        r = requests.get(full_url, headers=headers, verify=False, proxies=proxies, timeout=10)
        print(f"{GRAY}    Baseline Request: {random_path} -> Code: {r.status_code}, Size: {len(r.content)} bytes{RESET}")
        return r.status_code, len(r.content)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"{RED}[!] Calibration failed: {e}{RESET}")
        return None, None

def scan_endpoint(url, path, label, headers, proxies, filters):
    full_url = url + path
    try:
        if filters['delay'] > 0: time.sleep(filters['delay'])

        r = requests.get(full_url, headers=headers, verify=False, proxies=proxies, timeout=8)
        code = r.status_code
        size = len(r.content)

        # Filtering Logic
        if filters['mc'] and code not in filters['mc']: return
        if filters['fc'] and code in filters['fc']: return
        if filters['fs'] and size in filters['fs']: return

        # Output Coloring
        status_color = GREEN if code == 200 else YELLOW if code in [401, 403, 500] else GRAY
        print(f"[{status_color}{code}{RESET}] Size: {size:<6} | {full_url} {GRAY}({label}){RESET}")
        
    except KeyboardInterrupt:
        # CRITICAL FIX: This ensures Ctrl+C works by re-raising the interrupt
        raise
    except Exception:
        # This catches connection errors (timeouts, etc.) but lets Ctrl+C pass through
        pass

def fingerprint_solutions(url, headers, proxies, filters):
    print(f"\n{BLUE}[*] Fingerprinting Installed Solutions...{RESET}")
    for name, path in solutions_db.items():
        scan_endpoint(url, path, f"Solution: {name}", headers, proxies, filters)

def main():
    # Custom Help Text
    examples = f"""
{YELLOW}EXAMPLES:{RESET}
  1. Standard Scan (Auto-Calibrate):
     {GREEN}python3 d365_enum.py -u https://org.crm.dynamics.com{RESET}

  2. Strict Mode (Only show 200 OK and 401 Auth Required):
     {GREEN}python3 d365_enum.py -u https://target.com -mc 200,401{RESET}

  3. Filter Specific Size (e.g., hide 1024 byte login pages):
     {GREEN}python3 d365_enum.py -u https://target.com -fs 1024{RESET}
     
  4. WAF Evasion (1 second delay between requests):
     {GREEN}python3 d365_enum.py -u https://target.com -d 1.0{RESET}
    """

    parser = argparse.ArgumentParser(
        description=f"{CYAN}Dynamics 365 Enumeration Tool v3.0{RESET}\nPassive discovery tool for Microsoft Dynamics 365 / Power Platform.",
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Core Arguments
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://org.crm.dynamics.com)", required=True)
    parser.add_argument("-p", "--proxy", help="Proxy URL (http://127.0.0.1:8080)")
    
    # Filtering Arguments
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument("-mc", "--match-code", help="Match status codes (only show these). Example: 200,401", default="")
    filter_group.add_argument("-fc", "--filter-code", help="Filter status codes (hide these). Default: 404", default="404")
    filter_group.add_argument("-fs", "--filter-size", help="Filter response size (hide these). Example: 3200", default="")
    filter_group.add_argument("--no-calibrate", action="store_true", help="Disable auto-calibration (soft 404 detection)")
    
    # Performance
    parser.add_argument("-d", "--delay", type=float, default=0.0, help="Delay between requests in seconds (WAF evasion)")

    args = parser.parse_args()
    
    banner()
    
    target = args.url.rstrip('/')
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    print(f"{BLUE}[*] Target: {target}{RESET}")

    # 1. Filters Setup
    mc_list = [int(x) for x in args.match_code.split(',')] if args.match_code else []
    fc_list = [int(x) for x in args.filter_code.split(',')] if args.filter_code else []
    fs_list = [int(x) for x in args.filter_size.split(',')] if args.filter_size else []

    # 2. Calibration
    try:
        if not args.no_calibrate:
            cal_code, cal_size = auto_calibrate(target, proxies, headers)
            if cal_code:
                print(f"{YELLOW}[!] Auto-adding filters: Hide Code {cal_code}, Hide Size {cal_size}{RESET}")
                fc_list.append(cal_code)
                fs_list.append(cal_size)
        
        filters = {'mc': set(mc_list), 'fc': set(fc_list), 'fs': set(fs_list), 'delay': args.delay}

        # 3. Execution Phase
        print(f"\n{BLUE}[*] Scanning Core & API Endpoints...{RESET}")
        all_standard_paths = core_paths + debug_paths + api_paths + portal_paths
        for path in all_standard_paths:
            scan_endpoint(target, path, "Core", headers, proxies, filters)

        # 4. Solution Fingerprinting Phase
        fingerprint_solutions(target, headers, proxies, filters)
        
        print(f"\n{GREEN}[+] Enumeration Complete.{RESET}")

    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] Scan interrupted by user (Ctrl+C). Exiting...{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
