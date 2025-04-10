import argparse
import logging
from typing import Dict
from modules.xss_scanner import XSSScanner
from modules.sql_injection_scanner import SQLInjectionScanner
from modules.ssh_scanner import SSHScanner

def setup_logging():
    """Configure logging settings."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Web Security Testing Tool')
    parser.add_argument('--target', required=True, help='Target URL or IP address')
    parser.add_argument('--scan-type', choices=['xss', 'sql', 'ssh', 'all'], default='all',
                      help='Type of scan to perform')
    parser.add_argument('--output', default='reports',
                      help='Output directory for reports')
    parser.add_argument('--config', help='Path to configuration file')
    return parser.parse_args()

def run_scan(target: str, scan_type: str, config: Dict = None) -> Dict:
    """Run the specified security scan."""
    results = {}
    
    if scan_type in ['xss', 'all']:
        xss_scanner = XSSScanner(target, config)
        results['xss'] = xss_scanner.scan()
        
    if scan_type in ['sql', 'all']:
        sql_scanner = SQLInjectionScanner(target, config)
        results['sql_injection'] = sql_scanner.scan()
        
    if scan_type in ['ssh', 'all']:
        ssh_scanner = SSHScanner(target, config)
        results['ssh'] = ssh_scanner.scan()
        
    return results

def main():
    """Main entry point for the web security tool."""
    setup_logging()
    args = parse_arguments()
    
    try:
        results = run_scan(args.target, args.scan_type)
        print("\nScan Results:")
        print("=============")
        
        for scan_type, result in results.items():
            print(f"\n{scan_type.upper()} Scan:")
            if result['status'] == 'completed':
                vulnerabilities = result.get('vulnerabilities', [])
                if vulnerabilities:
                    print(f"Found {len(vulnerabilities)} vulnerabilities:")
                    for vuln in vulnerabilities:
                        print(f"- Type: {vuln['type']}")
                        if 'url' in vuln:
                            print(f"  URL: {vuln['url']}")
                        if 'username' in vuln:
                            print(f"  Username: {vuln['username']}")
                        if 'password' in vuln:
                            print(f"  Password: {vuln['password']}")
                        if 'version' in vuln:
                            print(f"  Version: {vuln['version']}")
                        if 'algorithm' in vuln:
                            print(f"  Algorithm: {vuln['algorithm']}")
                        print(f"  Severity: {vuln['severity']}")
                        if 'payload' in vuln:
                            print(f"  Payload: {vuln['payload']}")
                else:
                    print("No vulnerabilities found.")
            else:
                print(f"Scan failed: {result.get('error', 'Unknown error')}")
                
    except Exception as e:
        logging.error(f"An error occurred during scanning: {e}")
        return 1
        
    return 0

if __name__ == '__main__':
    exit(main()) 