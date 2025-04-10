import os
import sys
import logging
from typing import Dict
import time
from datetime import datetime
import threading
from tqdm import tqdm
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows support
init()

# Color definitions
COLORS = {
    'HEADER': Fore.MAGENTA + Style.BRIGHT,
    'INFO': Fore.CYAN + Style.BRIGHT,
    'SUCCESS': Fore.GREEN + Style.BRIGHT,
    'WARNING': Fore.YELLOW + Style.BRIGHT,
    'ERROR': Fore.RED + Style.BRIGHT,
    'RESET': Style.RESET_ALL
}

# 현재 파일의 절대 경로를 기준으로 프로젝트 루트 디렉토리 경로 계산
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

# 프로젝트 루트 디렉토리를 Python 경로에 추가
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from web_security_tool.modules.xss_scanner import XSSScanner
from web_security_tool.modules.sql_injection_scanner import SQLInjectionScanner
from web_security_tool.modules.ssh_scanner import SSHScanner
from web_security_tool.modules.payload_generator import PayloadGenerator
from web_security_tool.modules.auto_exploit import AutoExploit
from web_security_tool.modules.reverse_shell import ReverseShell
from web_security_tool.modules.nmap_scan import NmapScanner
from web_security_tool.modules.ssh_cracker import SSHCracker

def setup_logging():
    """로그 설정을 구성합니다."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def print_banner():
    """프로그램 배너를 출력합니다."""
    banner = f"""{COLORS['HEADER']}
    ██╗    ██╗███████╗██████╗ ███████╗███████╗ ██████╗
    ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
    ██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██║     
    ██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     
    ╚███╔███╔╝███████╗██████╔╝███████║███████╗╚██████╗
     ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
    {COLORS['INFO']}        웹 보안 테스트 도구 v1.0.0{COLORS['RESET']}
    """
    print(banner)
    print(f"{COLORS['INFO']}=" * 60 + f"{COLORS['RESET']}")

def animate_progress():
    """진행 상태 애니메이션을 표시합니다."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not animate_progress.done:
        sys.stdout.write(f'\r{COLORS["INFO"]}[{chars[i % len(chars)]}] 스캔 진행 중...{COLORS["RESET"]}')
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write('\r' + ' ' * 30 + '\r')
    sys.stdout.flush()

animate_progress.done = True

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
    print("    4. 리버스 쉘 생성")
    print("    5. Nmap 포트 스캔")
    print("    6. SSH 크래킹")
    print("    7. 모든 스캔 실행")
    
    scan_types = {
        '1': 'xss',
        '2': 'sql',
        '3': 'ssh',
        '4': 'reverse_shell',
        '5': 'nmap',
        '6': 'ssh_crack',
        '7': 'all'
    }
    while True:
        choice = input("\n선택 (1-7): ").strip()
        if choice in scan_types:
            scan_type = scan_types[choice]
            break
        print("[!] 1에서 7 사이의 숫자를 입력하세요.")
    
    return target, scan_type

def print_progress(scan_type: str):
    """스캔 진행 상황을 출력합니다."""
    print(f"\n{COLORS['INFO']}[*] {scan_type.upper()} 스캔 진행 중...{COLORS['RESET']}")
    
    # 진행 상태 애니메이션 시작
    animate_progress.done = False
    progress_thread = threading.Thread(target=animate_progress)
    progress_thread.start()
    
    # 진행바 표시
    with tqdm(total=100, 
             desc=f"{COLORS['INFO']}진행률{COLORS['RESET']}", 
             bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}',
             ncols=75) as pbar:
        for i in range(100):
            time.sleep(0.05)  # 실제 스캔에서는 이 부분이 실제 작업으로 대체됨
            pbar.update(1)
    
    # 진행 상태 애니메이션 종료
    animate_progress.done = True
    progress_thread.join()
    print(f"\n{COLORS['SUCCESS']}[+] {scan_type.upper()} 스캔 완료{COLORS['RESET']}\n")

def print_vulnerability(vuln: Dict):
    """취약점 정보를 출력합니다."""
    print(f"{COLORS['WARNING']}" + "=" * 60 + f"{COLORS['RESET']}")
    print(f"{COLORS['ERROR']}[!] 취약점 유형: {vuln['type']}{COLORS['RESET']}")
    if 'url' in vuln:
        print(f"{COLORS['INFO']}    URL: {COLORS['RESET']}{vuln['url']}")
    if 'username' in vuln:
        print(f"{COLORS['INFO']}    사용자명: {COLORS['RESET']}{vuln['username']}")
    if 'password' in vuln:
        print(f"{COLORS['INFO']}    비밀번호: {COLORS['RESET']}{vuln['password']}")
    if 'version' in vuln:
        print(f"{COLORS['INFO']}    버전: {COLORS['RESET']}{vuln['version']}")
    if 'algorithm' in vuln:
        print(f"{COLORS['INFO']}    알고리즘: {COLORS['RESET']}{vuln['algorithm']}")
    print(f"{COLORS['INFO']}    심각도: {COLORS['WARNING']}{vuln['severity']}{COLORS['RESET']}")
    
    # 자동 페이로드 생성 및 표시
    payload = PayloadGenerator.generate_custom_payload(vuln['type'])
    print(f"{COLORS['INFO']}    생성된 페이로드: {COLORS['WARNING']}{payload}{COLORS['RESET']}")
    
    # 자동 익스플로잇 시도
    if 'url' in vuln:
        print(f"\n{COLORS['INFO']}[*] 자동 익스플로잇 시도 중...{COLORS['RESET']}")
        exploit = AutoExploit(vuln['url'])
        exploit_result = exploit.auto_exploit(vuln['type'], payload, vuln.get('params', {}))
        
        if exploit_result['success']:
            print(f"{COLORS['SUCCESS']}[+] 익스플로잇 성공!{COLORS['RESET']}")
            if 'response' in exploit_result:
                print(f"{COLORS['INFO']}    응답: {COLORS['RESET']}{exploit_result['response']}")
        else:
            print(f"{COLORS['ERROR']}[-] 익스플로잇 실패: {exploit_result.get('error', '알 수 없는 오류')}{COLORS['RESET']}")
    
    print(f"{COLORS['WARNING']}" + "=" * 60 + f"{COLORS['RESET']}")

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
        
    if scan_type == 'reverse_shell':
        print("\n[*] 리버스 쉘 생성")
        print("=" * 50)
        
        # 리버스 쉘 설정
        lhost = input("\n[+] 리스너 IP 주소를 입력하세요: ").strip()
        lport = int(input("[+] 리스너 포트를 입력하세요: ").strip())
        
        print("\n[+] 사용 가능한 쉘 타입:")
        print("    1. Python")
        print("    2. Bash")
        print("    3. PHP")
        print("    4. Perl")
        print("    5. Ruby")
        print("    6. Netcat")
        print("    7. Java")
        print("    8. PowerShell")
        
        shell_types = {
            '1': 'python',
            '2': 'bash',
            '3': 'php',
            '4': 'perl',
            '5': 'ruby',
            '6': 'nc',
            '7': 'java',
            '8': 'powershell'
        }
        
        while True:
            choice = input("\n선택 (1-8): ").strip()
            if choice in shell_types:
                shell_type = shell_types[choice]
                break
            print("[!] 1에서 8 사이의 숫자를 입력하세요.")
        
        # 리버스 쉘 생성 및 실행
        reverse_shell = ReverseShell(lhost, lport)
        payload = reverse_shell.generate_payload(shell_type)
        encoded_payload = reverse_shell.generate_encoded_payload(shell_type)
        
        print(f"\n{Fore.GREEN}[+] 리버스 쉘 페이로드가 생성되었습니다.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] 일반 페이로드:{Style.RESET_ALL}")
        print(payload)
        print(f"\n{Fore.YELLOW}[*] Base64 인코딩된 페이로드:{Style.RESET_ALL}")
        print(encoded_payload)
        
        # 페이로드 실행 여부 확인
        execute = input("\n[+] 페이로드를 실행하시겠습니까? (y/n): ").strip().lower()
        if execute == 'y':
            if reverse_shell.execute_payload(payload):
                print(f"{Fore.GREEN}[+] 리버스 쉘이 실행되었습니다.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] 리버스 쉘 실행에 실패했습니다.{Style.RESET_ALL}")
        
        results['reverse_shell'] = {
            'status': 'completed',
            'payload': payload,
            'encoded_payload': encoded_payload
        }
        
    if scan_type == 'nmap':
        print("\n[*] Nmap 포트 스캔")
        print("=" * 50)
        
        # Nmap 스캐너 초기화
        nmap_scanner = NmapScanner()
        
        # IP 주소 입력
        while True:
            target_ip = input("\n[+] 스캔할 IP 주소를 입력하세요: ").strip()
            if nmap_scanner.validate_ip(target_ip):
                break
            print("[!] 올바른 IP 주소를 입력하세요.")
        
        # Tor 서비스 시작
        if not nmap_scanner.start_tor_service():
            print(f"{Fore.RED}[!] Tor 서비스 시작에 실패했습니다. 익명 스캔이 불가능합니다.{Style.RESET_ALL}")
            continue_scan = input("\n[+] Tor 없이 스캔을 계속하시겠습니까? (y/n): ").strip().lower()
            if continue_scan != 'y':
                return {'status': 'failed', 'error': 'Tor 서비스 시작 실패'}
        
        # ProxyChains 설정 확인
        if not nmap_scanner.check_proxychains_config():
            print(f"{Fore.RED}[!] ProxyChains 설정에 실패했습니다. 익명 스캔이 불가능합니다.{Style.RESET_ALL}")
            continue_scan = input("\n[+] ProxyChains 없이 스캔을 계속하시겠습니까? (y/n): ").strip().lower()
            if continue_scan != 'y':
                return {'status': 'failed', 'error': 'ProxyChains 설정 실패'}
        
        # 스캔 실행
        print_progress('Nmap')
        scan_result = nmap_scanner.scan_ports(target_ip)
        
        if scan_result['status'] == 'completed':
            results['nmap'] = scan_result
            
            # 취약점 출력
            if scan_result.get('vulnerabilities'):
                print(f"\n{Fore.YELLOW}[*] 발견된 취약점:{Style.RESET_ALL}")
                for vuln in scan_result['vulnerabilities']:
                    print(f"\n{Fore.RED}[!] 취약점 유형: {vuln['type']}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}    포트: {vuln['port']}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}    서비스: {vuln['service']}{Style.RESET_ALL}")
                    if vuln.get('version'):
                        print(f"{Fore.CYAN}    버전: {vuln['version']}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}    심각도: {vuln['severity']}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}[+] 발견된 취약점이 없습니다.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[-] 스캔 실패: {scan_result.get('error', '알 수 없는 오류')}{Style.RESET_ALL}")
            results['nmap'] = scan_result
            
    if scan_type == 'ssh_crack':
        print("\n[*] SSH 크래킹")
        print("=" * 50)
        
        # SSHCracker 인스턴스 생성
        cracker = SSHCracker()
        
        # 사용자 입력 받기
        host, port, thread_count, timeout, wait_time = cracker.get_user_input()
        
        # 공격 확인
        print(f'\n{Fore.YELLOW}[*] 공격 설정:')
        print(f'    - 대상 서버: {host}:{port}')
        print(f'    - 스레드 수: {thread_count}')
        print(f'    - 타임아웃: {timeout}초')
        print(f'    - 대기 시간: {wait_time}ms{Style.RESET_ALL}')
        
        input(f'\n{Fore.YELLOW}[!] 공격을 시작하려면 ENTER를 누르세요...{Style.RESET_ALL}')
        
        # 공격 실행
        print(f'\n{Fore.CYAN}[*] 공격을 시작합니다...{Style.RESET_ALL}')
        result = cracker.run_attack(host, port, thread_count, timeout, wait_time)
        
        if result['status'] == 'success':
            results['ssh_crack'] = {
                'status': 'completed',
                'credentials': result['credentials']
            }
        else:
            results['ssh_crack'] = {
                'status': 'failed',
                'error': result.get('error', '알 수 없는 오류')
            }
        
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
                if scan_type == 'nmap':
                    f.write(f"스캔 파일: {result.get('filename', 'N/A')}\n")
                    vulnerabilities = result.get('vulnerabilities', [])
                    if vulnerabilities:
                        f.write(f"발견된 취약점: {len(vulnerabilities)}개\n")
                        for vuln in vulnerabilities:
                            f.write("-" * 30 + "\n")
                            f.write(f"취약점 유형: {vuln['type']}\n")
                            f.write(f"포트: {vuln['port']}\n")
                            f.write(f"서비스: {vuln['service']}\n")
                            if vuln.get('version'):
                                f.write(f"버전: {vuln['version']}\n")
                            f.write(f"심각도: {vuln['severity']}\n")
                    else:
                        f.write("취약점이 발견되지 않았습니다.\n")
                elif scan_type == 'ssh_crack':
                    credentials = result.get('credentials', {})
                    f.write(f"발견된 자격 증명:\n")
                    f.write(f"    사용자 이름: {credentials.get('username', 'N/A')}\n")
                    f.write(f"    비밀번호: {credentials.get('password', 'N/A')}\n")
                else:
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
        print(f"\n{COLORS['INFO']}[*] 스캔 시작: {COLORS['RESET']}{target}")
        print(f"{COLORS['INFO']}[*] 스캔 유형: {COLORS['RESET']}{scan_type.upper()}")
        print(f"{COLORS['INFO']}" + "=" * 60 + f"{COLORS['RESET']}")
        
        start_time = time.time()
        results = run_scan(target, scan_type)
        end_time = time.time()
        
        print(f"\n{COLORS['HEADER']}[*] 스캔 결과{COLORS['RESET']}")
        print(f"{COLORS['INFO']}" + "=" * 60 + f"{COLORS['RESET']}")
        
        total_vulns = 0
        for scan_type, result in results.items():
            print(f"\n{COLORS['INFO']}[+] {scan_type.upper()} 스캔 결과:{COLORS['RESET']}")
            if result['status'] == 'completed':
                if scan_type == 'nmap':
                    vulnerabilities = result.get('vulnerabilities', [])
                    if vulnerabilities:
                        total_vulns += len(vulnerabilities)
                        print(f"{COLORS['WARNING']}발견된 취약점: {len(vulnerabilities)}개{COLORS['RESET']}")
                        for vuln in vulnerabilities:
                            print(f"\n{COLORS['ERROR']}[!] 취약점 유형: {vuln['type']}{COLORS['RESET']}")
                            print(f"{COLORS['INFO']}    포트: {vuln['port']}{COLORS['RESET']}")
                            print(f"{COLORS['INFO']}    서비스: {vuln['service']}{COLORS['RESET']}")
                            if vuln.get('version'):
                                print(f"{COLORS['INFO']}    버전: {vuln['version']}{COLORS['RESET']}")
                            print(f"{COLORS['WARNING']}    심각도: {vuln['severity']}{COLORS['RESET']}")
                    else:
                        print(f"{COLORS['SUCCESS']}취약점이 발견되지 않았습니다.{COLORS['RESET']}")
                elif scan_type == 'ssh_crack':
                    print(f"{COLORS['WARNING']}발견된 자격 증명:{COLORS['RESET']}")
                    credentials = result.get('credentials', {})
                    print(f"    사용자 이름: {credentials.get('username', 'N/A')}")
                    print(f"    비밀번호: {credentials.get('password', 'N/A')}")
                else:
                    vulnerabilities = result.get('vulnerabilities', [])
                    if vulnerabilities:
                        total_vulns += len(vulnerabilities)
                        print(f"{COLORS['WARNING']}발견된 취약점: {len(vulnerabilities)}개{COLORS['RESET']}")
                        for vuln in vulnerabilities:
                            print_vulnerability(vuln)
                    else:
                        print(f"{COLORS['SUCCESS']}취약점이 발견되지 않았습니다.{COLORS['RESET']}")
            else:
                print(f"{COLORS['ERROR']}스캔 실패: {result.get('error', '알 수 없는 오류')}{COLORS['RESET']}")
        
        print(f"\n{COLORS['SUCCESS']}[*] 스캔 완료{COLORS['RESET']}")
        print(f"{COLORS['INFO']}[*] 소요 시간: {end_time - start_time:.2f}초{COLORS['RESET']}")
        print(f"{COLORS['INFO']}[*] 총 발견된 취약점: {COLORS['WARNING']}{total_vulns}개{COLORS['RESET']}")
        
        # 결과 저장
        save_report(results, target)
        
    except KeyboardInterrupt:
        print(f"\n\n{COLORS['ERROR']}[!] 사용자에 의해 스캔이 중단되었습니다.{COLORS['RESET']}")
        return 1
    except Exception as e:
        logging.error(f"스캔 중 오류 발생: {e}")
        print(f"\n{COLORS['ERROR']}[!] 오류 발생: {str(e)}{COLORS['RESET']}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())