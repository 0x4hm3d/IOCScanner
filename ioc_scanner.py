import argparse
import asyncio
import datetime
import hashlib
import ipaddress
import os
import re
import sys
import time
from urllib.parse import urlparse

import aiohttp
import colorama
import pandas as pd

# Initialize colorama
colorama.init(autoreset=True)

class IOCScanner:
    def __init__(self):
        self.start_time = time.time()
        self.api_keys = {'virustotal': None, 'abuseipdb': None}
        self.last_api_call = 0
        self.request_delay = 30  # 30 seconds between API calls
        self.results = []
        self.total_iocs = 0
        self.processed_iocs = 0

    def display_banner(self):
        """Display the program banner with improved formatting"""
        banner = r"""
 ▄█   ▄██████▄   ▄████████    ▄████████  ▄████████    ▄████████ ███▄▄▄▄   ███▄▄▄▄      ▄████████    ▄████████ 
███  ███    ███ ███    ███   ███    ███ ███    ███   ███    ███ ███▀▀▀██▄ ███▀▀▀██▄   ███    ███   ███    ███ 
███▌ ███    ███ ███    █▀    ███    █▀  ███    █▀    ███    ███ ███   ███ ███   ███   ███    █▀    ███    ███ 
███▌ ███    ███ ███          ███        ███          ███    ███ ███   ███ ███   ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
███▌ ███    ███ ███        ▀███████████ ███        ▀███████████ ███   ███ ███   ███ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
███  ███    ███ ███    █▄           ███ ███    █▄    ███    ███ ███   ███ ███   ███   ███    █▄  ▀███████████ 
███  ███    ███ ███    ███    ▄█    ███ ███    ███   ███    ███ ███   ███ ███   ███   ███    ███   ███    ███ 
█▀    ▀██████▀  ████████▀   ▄████████▀  ████████▀    ███    █▀   ▀█   █▀   ▀█   █▀    ██████████   ███    ███ 
                                                                                                   ███    ███ 
"""
        print(f"\033[96m{banner}\033[0m")
        print("\033[96m╔══════════════════════════════════════════════════════════════╗\033[0m")
        print("\033[96m║\033[0m \033[93mIOC Scanner v2.0 - IP/URL/Hash Analysis Tool\033[0m                 \033[96m║\033[0m")
        print("\033[96m╠══════════════════════════════════════════════════════════════╣\033[0m")
        print("\033[96m║\033[0m Author: \033[94mAhmed ElHabashi\033[0m                                      \033[96m║\033[0m")
        print("\033[96m║\033[0m X:  \033[94m@iahmedelhabashy\033[0m                                         \033[96m║\033[0m")
        print("\033[96m║\033[0m Features: \033[92mHash Support (MD5/SHA1/SHA256)\033[0m                     \033[96m║\033[0m")
        print("\033[96m║\033[0m          \033[92m30-second API rate limiting\033[0m                         \033[96m║\033[0m")
        print("\033[96m╚══════════════════════════════════════════════════════════════╝\033[0m")
        print()

    async def rate_limit(self):
        """Enforce 30-second delay between API calls with progress indicator"""
        elapsed = time.time() - self.last_api_call
        if elapsed < self.request_delay:
            wait = self.request_delay - elapsed
            print(f"\033[93m[*]\033[0m Rate limiting: Waiting {wait:.1f} seconds...", end='\r')
            await asyncio.sleep(wait)
            print(' ' * 50, end='\r')  # Clear line
        self.last_api_call = time.time()

    def validate_ioc(self, ioc):
        """Determine and validate IOC type with improved regex patterns"""
        ioc = ioc.strip()
        if not ioc:
            return None

        # Check for IP address (IPv4)
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\s|$|\[|/|:)"
        if re.match(ip_pattern, ioc):
            ip = re.sub(r'[\[\]/:]', '', ioc.split()[0])
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_reserved:
                    return ('ip', ip)
            except ValueError:
                pass
        
        # Check for URL with improved validation
        url_pattern = r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
        if re.match(url_pattern, ioc, re.IGNORECASE):
            try:
                parsed = urlparse(ioc)
                if parsed.scheme and parsed.netloc and '.' in parsed.netloc:
                    return ('url', ioc)
            except:
                pass
        
        # Check for hashes with strict validation
        clean_hash = re.sub(r'[^a-fA-F0-9]', '', ioc)
        if len(clean_hash) == 32 and re.match(r'^[a-fA-F0-9]{32}$', clean_hash):
            return ('md5', clean_hash.lower())
        elif len(clean_hash) == 40 and re.match(r'^[a-fA-F0-9]{40}$', clean_hash):
            return ('sha1', clean_hash.lower())
        elif len(clean_hash) == 64 and re.match(r'^[a-fA-F0-9]{64}$', clean_hash):
            return ('sha256', clean_hash.lower())
        
        return None

    async def load_api_keys(self, key_file):
        """Load API keys from file with better error handling"""
        try:
            if not os.path.isfile(key_file):
                raise FileNotFoundError(f"API key file not found: {key_file}")

            with open(key_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle both space and equals sign as separators
                    if '=' in line:
                        key, value = line.split('=', 1)
                    else:
                        parts = line.split(maxsplit=1)
                        if len(parts) != 2:
                            continue
                        key, value = parts
                    
                    key = key.lower().strip()
                    if key in self.api_keys:
                        self.api_keys[key] = value.strip()
            
            # Validate we have keys for enabled services
            missing_keys = [k for k, v in self.api_keys.items() if not v]
            if missing_keys:
                raise ValueError(f"Missing API keys for: {', '.join(missing_keys)}")
            
            print("\033[32m[+]\033[0m API keys loaded successfully")
            return True
        except Exception as e:
            print(f"\033[91m[!]\033[0m Error loading API keys: {str(e)}")
            return False

    async def process_file(self, file_path):
        """Extract IOCs from input file with better file handling"""
        try:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"Input file not found: {file_path}")

            print(f"\033[32m[+]\033[0m Processing file: {os.path.basename(file_path)}")
            
            content = []
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.txt':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().splitlines()
            elif file_ext == '.csv':
                try:
                    df = pd.read_csv(file_path)
                    content = df.columns.tolist() + df.values.ravel().tolist()
                    content = [str(x).strip() for x in content if not pd.isna(x) and str(x).strip()]
                except Exception as e:
                    raise ValueError(f"Error reading CSV: {str(e)}")
            elif file_ext in ('.xlsx', '.xls'):
                try:
                    df = pd.read_excel(file_path)
                    content = df.columns.tolist() + df.values.ravel().tolist()
                    content = [str(x).strip() for x in content if not pd.isna(x) and str(x).strip()]
                except Exception as e:
                    raise ValueError(f"Error reading Excel file: {str(e)}")
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")
            
            # Process and validate IOCs
            iocs = {'ip': [], 'url': [], 'md5': [], 'sha1': [], 'sha256': []}
            for item in content:
                ioc_type = self.validate_ioc(item)
                if ioc_type:
                    iocs[ioc_type[0]].append(ioc_type[1])
            
            self.total_iocs = sum(len(v) for v in iocs.values())
            if not self.total_iocs:
                raise ValueError("No valid IOCs found in the input file")
            
            print(f"\033[32m[+]\033[0m Found {self.total_iocs} valid IOCs to scan")
            return iocs
            
        except Exception as e:
            print(f"\033[91m[!]\033[0m Error processing file: {str(e)}")
            return None

    async def check_virustotal(self, session, ioc_type, value):
        """Check IOC with VirusTotal with improved error handling"""
        await self.rate_limit()
        
        if not self.api_keys['virustotal']:
            return None

        try:
            if ioc_type == 'ip':
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
            elif ioc_type == 'url':
                url_id = hashlib.sha256(value.encode()).hexdigest()
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:  # hash
                url = f"https://www.virustotal.com/api/v3/files/{value}"
            
            headers = {"x-apikey": self.api_keys['virustotal']}
            
            async with session.get(url, headers=headers) as resp:
                self.processed_iocs += 1
                print(f"\033[34m[*]\033[0m Processing {ioc_type} {value} ({self.processed_iocs}/{self.total_iocs})", end='\r')
                
                if resp.status == 200:
                    data = await resp.json()
                    result = {
                        'type': ioc_type,
                        'value': value,
                        'service': 'VirusTotal',
                        'malicious': data['data']['attributes']['last_analysis_stats']['malicious'],
                        'suspicious': data['data']['attributes']['last_analysis_stats'].get('suspicious', 0),
                        'harmless': data['data']['attributes']['last_analysis_stats']['harmless'],
                        'undetected': data['data']['attributes']['last_analysis_stats']['undetected'],
                        'last_analysis': self._format_timestamp(data['data']['attributes'].get('last_analysis_date', ''))
                    }
                    
                    # Add type-specific fields
                    if ioc_type == 'ip':
                        result.update({
                            'country': data['data']['attributes'].get('country', ''),
                            'asn': data['data']['attributes'].get('asn', ''),
                            'network': data['data']['attributes'].get('network', '')
                        })
                    elif ioc_type == 'url':
                        result.update({
                            'final_url': data['data']['attributes'].get('final_url', value),
                            'categories': ', '.join(data['data']['attributes'].get('categories', {}).values()),
                            'redirection_chain': len(data['data']['attributes'].get('redirection_chain', []))
                        })
                    elif ioc_type in ('md5', 'sha1', 'sha256'):
                        result.update({
                            'type_description': data['data']['attributes'].get('type_description', ''),
                            'size': data['data']['attributes'].get('size', ''),
                            'names': ', '.join(data['data']['attributes'].get('names', [])[:3])
                        })
                    
                    return result
                elif resp.status == 404:
                    print(f"\033[93m[!]\033[0m Not found in VirusTotal: {value}")
                elif resp.status == 429:
                    print(f"\033[91m[!]\033[0m VirusTotal rate limit exceeded for {value}")
                else:
                    error = await resp.text()
                    print(f"\033[91m[!]\033[0m VirusTotal error for {value}: HTTP {resp.status} - {error[:200]}")
        except asyncio.TimeoutError:
            print(f"\033[91m[!]\033[0m Timeout checking {value} with VirusTotal")
        except Exception as e:
            print(f"\033[91m[!]\033[0m Error checking {value} with VirusTotal: {str(e)}")
        return None

    async def check_abuseipdb(self, session, ip):
        """Check IP with AbuseIPDB with improved error handling"""
        await self.rate_limit()
        
        if not self.api_keys['abuseipdb']:
            return None

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': self.api_keys['abuseipdb'], 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            async with session.get(url, headers=headers, params=params) as resp:
                self.processed_iocs += 1
                print(f"\033[34m[*]\033[0m Processing IP {ip} ({self.processed_iocs}/{self.total_iocs})", end='\r')
                
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        'type': 'ip',
                        'value': ip,
                        'service': 'AbuseIPDB',
                        'abuse_confidence': data['data']['abuseConfidenceScore'],
                        'isp': data['data']['isp'],
                        'domain': data['data']['domain'],
                        'country': data['data']['countryCode'],
                        'total_reports': data['data']['totalReports'],
                        'last_reported': self._format_timestamp(data['data']['lastReportedAt'])
                    }
                elif resp.status == 429:
                    print(f"\033[91m[!]\033[0m AbuseIPDB rate limit exceeded for {ip}")
                else:
                    error = await resp.text()
                    print(f"\033[91m[!]\033[0m AbuseIPDB error for {ip}: HTTP {resp.status} - {error[:200]}")
        except asyncio.TimeoutError:
            print(f"\033[91m[!]\033[0m Timeout checking {ip} with AbuseIPDB")
        except Exception as e:
            print(f"\033[91m[!]\033[0m Error checking {ip} with AbuseIPDB: {str(e)}")
        return None

    def _format_timestamp(self, timestamp):
        """Format timestamp from API responses"""
        if not timestamp:
            return ''
        
        try:
            if isinstance(timestamp, int):
                return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(timestamp, str):
                if timestamp.isdigit():
                    return datetime.datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    return timestamp.split('T')[0]  # For ISO format dates
        except:
            return timestamp
        return ''

    async def generate_report(self, output_dir):
        """Generate Excel report with scan results with improved formatting"""
        if not self.results:
            print("\033[91m[!]\033[0m No results to report")
            return False
            
        try:
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(output_dir, f"ioc_scan_results_{timestamp}.xlsx")
            
            df = pd.DataFrame(self.results)
            
            # Define column order and formatting
            column_order = [
                'type', 'value', 'service', 
                'malicious', 'suspicious', 'harmless', 'undetected',
                'abuse_confidence', 'total_reports',
                'country', 'isp', 'asn', 'network', 'domain',
                'type_description', 'size', 'names',
                'last_analysis', 'last_reported',
                'final_url', 'categories', 'redirection_chain'
            ]
            
            # Select only columns that exist in the DataFrame
            columns = [col for col in column_order if col in df.columns]
            columns += [col for col in df.columns if col not in column_order]
            
            try:
                with pd.ExcelWriter(report_path, engine='xlsxwriter') as writer:
                    df[columns].to_excel(writer, index=False, sheet_name='Results')
                    
                    # Apply formatting
                    workbook = writer.book
                    worksheet = writer.sheets['Results']
                    
                    # Header format
                    header_format = workbook.add_format({
                        'bg_color': '#2c3e50',
                        'font_color': 'white',
                        'bold': True,
                        'border': 1,
                        'align': 'center',
                        'valign': 'vcenter'
                    })
                    
                    # Set column widths and formats
                    col_widths = {
                        'type': 8, 'value': 30, 'service': 12,
                        'malicious': 10, 'suspicious': 10, 'harmless': 10, 'undetected': 10,
                        'abuse_confidence': 12, 'total_reports': 12,
                        'country': 8, 'isp': 25, 'asn': 10, 'network': 20, 'domain': 20,
                        'type_description': 25, 'size': 10, 'names': 30,
                        'last_analysis': 18, 'last_reported': 18,
                        'final_url': 40, 'categories': 25, 'redirection_chain': 10
                    }
                    
                    for idx, col in enumerate(columns):
                        # Apply header format
                        worksheet.write(0, idx, col, header_format)
                        
                        # Set column width
                        width = col_widths.get(col, 15)
                        worksheet.set_column(idx, idx, width)
                    
                    # Freeze header row
                    worksheet.freeze_panes(1, 0)
                    
                    # Add autofilter
                    worksheet.autofilter(0, 0, 0, len(columns)-1)
                    
                    print(f"\033[32m[+]\033[0m Report saved to: {report_path}")
                    return True
            except Exception as e:
                print(f"\033[91m[!]\033[0m Error writing Excel file: {str(e)}")
                return False
                
        except Exception as e:
            print(f"\033[91m[!]\033[0m Error generating report: {str(e)}")
            return False

    async def run_scan(self, file_path, output_dir, services):
        """Main scanning workflow with improved progress tracking"""
        self.display_banner()
        
        if not await self.load_api_keys(services['key_file']):
            return False
        
        iocs = await self.process_file(file_path)
        if not iocs:
            return False
        
        print("\033[32m[+]\033[0m Starting scan with 30-second rate limiting between API calls...")
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
                tasks = []
                
                # Process IPs
                if iocs['ip']:
                    print(f"\033[34m[*]\033[0m Checking {len(iocs['ip'])} IP addresses")
                    for ip in iocs['ip']:
                        if services['virustotal']:
                            tasks.append(self.check_virustotal(session, 'ip', ip))
                        if services['abuseipdb']:
                            tasks.append(self.check_abuseipdb(session, ip))
                
                # Process URLs
                if iocs['url'] and services['virustotal']:
                    print(f"\033[34m[*]\033[0m Checking {len(iocs['url'])} URLs")
                    for url in iocs['url']:
                        tasks.append(self.check_virustotal(session, 'url', url))
                
                # Process Hashes
                if services['virustotal']:
                    for hash_type in ('md5', 'sha1', 'sha256'):
                        if iocs[hash_type]:
                            print(f"\033[34m[*]\033[0m Checking {len(iocs[hash_type])} {hash_type.upper()} hashes")
                            for hash_val in iocs[hash_type]:
                                tasks.append(self.check_virustotal(session, hash_type, hash_val))
                
                # Process all tasks
                results = await asyncio.gather(*tasks)
                self.results = [result for result in results if result is not None]
                
        except Exception as e:
            print(f"\033[91m[!]\033[0m Error during scan: {str(e)}")
            return False
        
        # Generate report
        report_success = await self.generate_report(output_dir)
        
        elapsed = (time.time() - self.start_time) / 60
        print(f"\n\033[32m[+]\033[0m Scan completed in {elapsed:.1f} minutes")
        print(f"\033[32m[+]\033[0m Processed {self.processed_iocs} IOCs, found {len(self.results)} results")
        return report_success

def main():
    parser = argparse.ArgumentParser(
        description="IOC Scanner - Check IPs, URLs, and Hashes with VirusTotal/AbuseIPDB",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Example: python ioc_scanner.py -f iocs.txt -k api_keys.txt -o results"
    )
    parser.add_argument("-f", "--file", required=True, 
                        help="Input file containing IOCs (TXT, CSV, XLSX)")
    parser.add_argument("-k", "--api-keys", required=True, 
                        help="File containing API keys (virustotal=KEY, abuseipdb=KEY)")
    parser.add_argument("-o", "--output", default="reports", 
                        help="Output directory for reports")
    parser.add_argument("-v", "--virustotal", action="store_true", 
                        help="Use VirusTotal only")
    parser.add_argument("-a", "--abuseipdb", action="store_true", 
                        help="Use AbuseIPDB only")
    
    args = parser.parse_args()
    
    # Configure services (default to both if neither is specified)
    services = {
        'key_file': args.api_keys,
        'virustotal': args.virustotal or not args.abuseipdb,
        'abuseipdb': args.abuseipdb or not args.virustotal
    }
    
    # Run scanner
    scanner = IOCScanner()
    try:
        success = asyncio.run(scanner.run_scan(args.file, args.output, services))
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\033[91m[!]\033[0m Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\033[91m[!]\033[0m Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
