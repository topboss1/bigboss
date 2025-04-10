import os
import sys
import logging
from typing import Dict
import time
from datetime import datetime

# 현재 파일의 절대 경로를 기준으로 프로젝트 루트 디렉토리 경로 계산
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

# 프로젝트 루트 디렉토리를 Python 경로에 추가
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from web_security_tool.modules.xss_scanner import XSSScanner
from web_security_tool.modules.sql_injection_scanner import SQLInjectionScanner
from web_security_tool.modules.ssh_scanner import SSHScanner

def setup_logging():
    """로그 설정을 구성합니다."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def print_banner():
    """프로그램 배너를 출력합니다."""
    banner = """
╔══════════════════════════════════════════╗
║           웹 보안 테스트 도구            ║
║                v1.0.0                    ║
╚══════════════════════════════════════════╝
    """
    print(banner)

def get_user_input():
    """사용자로부터 입력을 받습니다."""
    print("\n[*] 스캔 설정")
    print("=" * 50)
    
    # URL 입력
    while True:
        target = input("\n[+] 대상 URL을 입력하세요 (예: http://example.com): ").strip()
        if target:
            if not (target.startswith('http://') or target.startswith('https://')):
                print("[!] URL은 http:// 또는 https://로 시작해야 합니다.")
                continue
            break
        print("[!] URL을 입력해야 합니다.")
    
    # 스캔 유형 선택
    print("\n[+] 스캔 유형을 선택하세요:")
    print("    1. XSS 취약점 검사")
    print("    2. SQL 인젝션 취약점 검사")
    print("    3. SSH 보안 검사")
    print("    4. 모든 스캔 실행")
    
    scan_types = {'1': 'xss', '2': 'sql', '3': 'ssh', '4': 'all'}
    while True:
        choice = input("\n선택 (1-4): ").strip()
        if choice in scan_types:
            scan_type = scan_types[choice]
            break
        print("[!] 1에서 4 사이의 숫자를 입력하세요.")
    
    return target, scan_type

def print_progress(scan_type: str):
    """스캔 진행 상황을 출력합니다."""
    print(f"\n[*] {scan_type.upper()} 스캔 진행 중...")
    for _ in range(3):
        print(".", end="", flush=True)
        time.sleep(0.5)
    print("\n")

def print_vulnerability(vuln: Dict):
    """취약점 정보를 출력합니다."""
    print("-" * 50)
    print(f"[!] 취약점 유형: {vuln['type']}")
    if 'url' in vuln:
        print(f"    URL: {vuln['url']}")
    if 'username' in vuln:
        print(f"    사용자명: {vuln['username']}")
    if 'password' in vuln:
        print(f"    비밀번호: {vuln['password']}")
    if 'version' in vuln:
        print(f"    버전: {vuln['version']}")
    if 'algorithm' in vuln:
        print(f"    알고리즘: {vuln['algorithm']}")
    print(f"    심각도: {vuln['severity']}")
    if 'payload' in vuln:
        print(f"    페이로드: {vuln['payload']}")
    print("-" * 50)

def run_scan(target: str, scan_type: str, config: Dict = None) -> Dict:
    """지정된 보안 스캔을 실행합니다."""
    results = {}
    
    if scan_type in ['xss', 'all']:
        print_progress('XSS')
        xss_scanner = XSSScanner(target, config)
        results['xss'] = xss_scanner.scan()
        
    if scan_type in ['sql', 'all']:
        print_progress('SQL Injection')
        sql_scanner = SQLInjectionScanner(target, config)
        results['sql_injection'] = sql_scanner.scan()
        
    if scan_type in ['ssh', 'all']:
        print_progress('SSH')
        ssh_scanner = SSHScanner(target, config)
        results['ssh'] = ssh_scanner.scan()
        
    return results

def save_report(results: Dict, target: str):
    """스캔 결과를 파일로 저장합니다."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"웹 보안 스캔 보고서\n")
        f.write(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"대상 URL: {target}\n")
        f.write("=" * 50 + "\n\n")
        
        for scan_type, result in results.items():
            f.write(f"\n{scan_type.upper()} 스캔 결과:\n")
            if result['status'] == 'completed':
                vulnerabilities = result.get('vulnerabilities', [])
                if vulnerabilities:
                    f.write(f"발견된 취약점: {len(vulnerabilities)}개\n")
                    for vuln in vulnerabilities:
                        f.write("-" * 30 + "\n")
                        f.write(f"취약점 유형: {vuln['type']}\n")
                        if 'url' in vuln:
                            f.write(f"URL: {vuln['url']}\n")
                        if 'username' in vuln:
                            f.write(f"사용자명: {vuln['username']}\n")
                        if 'password' in vuln:
                            f.write(f"비밀번호: {vuln['password']}\n")
                        if 'version' in vuln:
                            f.write(f"버전: {vuln['version']}\n")
                        if 'algorithm' in vuln:
                            f.write(f"알고리즘: {vuln['algorithm']}\n")
                        f.write(f"심각도: {vuln['severity']}\n")
                        if 'payload' in vuln:
                            f.write(f"페이로드: {vuln['payload']}\n")
                else:
                    f.write("취약점이 발견되지 않았습니다.\n")
            else:
                f.write(f"스캔 실패: {result.get('error', '알 수 없는 오류')}\n")
    
    print(f"\n[+] 스캔 보고서가 {filename}에 저장되었습니다.")

def main():
    """웹 보안 도구의 메인 진입점입니다."""
    setup_logging()
    print_banner()
    
    try:
        target, scan_type = get_user_input()
        print(f"\n[*] 스캔 시작: {target}")
        print(f"[*] 스캔 유형: {scan_type.upper()}")
        print("=" * 50)
        
        start_time = time.time()
        results = run_scan(target, scan_type)
        end_time = time.time()
        
        print("\n[*] 스캔 결과")
        print("=" * 50)
        
        total_vulns = 0
        for scan_type, result in results.items():
            print(f"\n[+] {scan_type.upper()} 스캔 결과:")
            if result['status'] == 'completed':
                vulnerabilities = result.get('vulnerabilities', [])
                if vulnerabilities:
                    total_vulns += len(vulnerabilities)
                    print(f"발견된 취약점: {len(vulnerabilities)}개")
                    for vuln in vulnerabilities:
                        print_vulnerability(vuln)
                else:
                    print("취약점이 발견되지 않았습니다.")
            else:
                print(f"스캔 실패: {result.get('error', '알 수 없는 오류')}")
        
        print("\n[*] 스캔 완료")
        print(f"[*] 소요 시간: {end_time - start_time:.2f}초")
        print(f"[*] 총 발견된 취약점: {total_vulns}개")
        
        # 결과 저장
        save_report(results, target)
        
    except KeyboardInterrupt:
        print("\n\n[!] 사용자에 의해 스캔이 중단되었습니다.")
        return 1
    except Exception as e:
        logging.error(f"스캔 중 오류 발생: {e}")
        print(f"\n[!] 오류 발생: {str(e)}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())