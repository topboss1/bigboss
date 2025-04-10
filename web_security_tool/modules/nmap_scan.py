import nmap
from colorama import init, Fore, Style
import itertools
import threading
import time
import sys
import subprocess
from datetime import datetime
import os
import json
import socket
import requests
from typing import Dict, List, Optional, Tuple

# colorama 초기화
init(autoreset=True)

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.done = False
        self.scan_results = {}
        self.vulnerabilities = []
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy'
        }
        self.vulnerability_patterns = {
            'ftp': ['anonymous', 'weak_password'],
            'ssh': ['weak_password', 'old_version'],
            'http': ['xss', 'sql_injection', 'directory_traversal'],
            'https': ['ssl_vulnerability', 'heartbleed'],
            'smb': ['eternalblue', 'smb_vulnerability']
        }
        self.tor_proxy = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

    def print_nmap_options(self):
        """Nmap 주요 옵션 설명을 출력하는 함수"""
        print(f'\n{Style.BRIGHT}{Fore.CYAN}╔════════════════════════════════════════════════════════════╗')
        print(f'║                    {Fore.YELLOW}Nmap 주요 옵션 설명{Fore.CYAN}                    ║')
        print(f'╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}')
        
        # 1. 기본 스캔 옵션
        print(f'\n{Style.BRIGHT}{Fore.YELLOW}1. 기본 스캔 옵션{Style.RESET_ALL}')
        print(f'{Fore.WHITE}┌──────────────────────────────────────────────────────┐')
        print(f'│ {Fore.CYAN}-sS{Fore.WHITE} │ TCP SYN 스캔 (기본 스캔 방식)                    │')
        print(f'│ {Fore.CYAN}-sT{Fore.WHITE} │ TCP 연결 스캔                                  │')
        print(f'│ {Fore.CYAN}-sU{Fore.WHITE} │ UDP 스캔                                       │')
        print(f'│ {Fore.CYAN}-sN{Fore.WHITE} │ TCP NULL 스캔                                  │')
        print(f'│ {Fore.CYAN}-sF{Fore.WHITE} │ TCP FIN 스캔                                   │')
        print(f'│ {Fore.CYAN}-sX{Fore.WHITE} │ TCP Xmas 스캔                                  │')
        print(f'└──────────────────────────────────────────────────────┘')
        
        # 2. 포트 지정 옵션
        print(f'\n{Style.BRIGHT}{Fore.YELLOW}2. 포트 지정 옵션{Style.RESET_ALL}')
        print(f'{Fore.WHITE}┌──────────────────────────────────────────────────────┐')
        print(f'│ {Fore.CYAN}-p{Fore.WHITE}  │ 특정 포트 스캔 (예: -p 80,443)                 │')
        print(f'│ {Fore.CYAN}-p-{Fore.WHITE} │ 모든 포트 스캔 (1-65535)                       │')
        print(f'│ {Fore.CYAN}-F{Fore.WHITE}  │ 빠른 스캔 (일반적인 포트만)                    │')
        print(f'└──────────────────────────────────────────────────────┘')
        
        # 3. 서비스 및 버전 감지
        print(f'\n{Style.BRIGHT}{Fore.YELLOW}3. 서비스 및 버전 감지{Style.RESET_ALL}')
        print(f'{Fore.WHITE}┌──────────────────────────────────────────────────────┐')
        print(f'│ {Fore.CYAN}-sV{Fore.WHITE} │ 서비스 버전 감지                              │')
        print(f'│ {Fore.CYAN}-sC{Fore.WHITE} │ 기본 스크립트 실행                            │')
        print(f'└──────────────────────────────────────────────────────┘')
        
        # 4. OS 감지
        print(f'\n{Style.BRIGHT}{Fore.YELLOW}4. OS 감지{Style.RESET_ALL}')
        print(f'{Fore.WHITE}┌──────────────────────────────────────────────────────┐')
        print(f'│ {Fore.CYAN}-O{Fore.WHITE}  │ 운영체제 감지                                  │')
        print(f'└──────────────────────────────────────────────────────┘')
        
        # 5. 타이밍 옵션
        print(f'\n{Style.BRIGHT}{Fore.YELLOW}5. 타이밍 옵션{Style.RESET_ALL}')
        print(f'{Fore.WHITE}┌──────────────────────────────────────────────────────┐')
        print(f'│ {Fore.CYAN}-T0{Fore.WHITE} │ 매우 느린 스캔                                │')
        print(f'│ {Fore.CYAN}-T1{Fore.WHITE} │ 느린 스캔                                     │')
        print(f'│ {Fore.CYAN}-T2{Fore.WHITE} │ 정상 스캔                                     │')
        print(f'│ {Fore.CYAN}-T3{Fore.WHITE} │ 빠른 스캔 (기본값)                            │')
        print(f'│ {Fore.CYAN}-T4{Fore.WHITE} │ 매우 빠른 스캔                                │')
        print(f'│ {Fore.CYAN}-T5{Fore.WHITE} │ 초고속 스캔                                   │')
        print(f'└──────────────────────────────────────────────────────┘')
        
        print(f'\n{Style.BRIGHT}{Fore.CYAN}╔════════════════════════════════════════════════════════════╗')
        print(f'║ {Fore.WHITE}Tip: 여러 옵션을 조합하여 사용할 수 있습니다. 예: -sS -sV -O{Fore.CYAN}  ║')
        print(f'╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n')

    def check_proxychains_config(self) -> bool:
        """ProxyChains 설정을 확인하고 필요한 경우 수정하는 함수"""
        config_path = '/etc/proxychains4.conf'
        try:
            if not os.path.exists(config_path):
                print(f'{Fore.RED}ProxyChains 설정 파일을 찾을 수 없습니다.')
                return False

            with open(config_path, 'r') as f:
                config = f.read()

            if 'socks5  127.0.0.1 9050' not in config:
                print(f'{Fore.YELLOW}ProxyChains 설정에 Tor 설정을 추가합니다...')
                with open(config_path, 'a') as f:
                    f.write('\nsocks5  127.0.0.1 9050')
                print(f'{Fore.GREEN}ProxyChains 설정이 업데이트되었습니다.')

            return True
        except Exception as e:
            print(f'{Fore.RED}ProxyChains 설정 확인 중 오류 발생: {e}')
            return False

    def check_tor_status(self) -> bool:
        """Tor 서비스의 상태를 확인하는 함수"""
        try:
            status = subprocess.run(['systemctl', 'is-active', 'tor'], 
                                  capture_output=True, text=True)
            return status.stdout.strip() == 'active'
        except Exception:
            return False

    def start_tor_service(self) -> bool:
        """Tor 서비스를 시작하고 상태를 확인하는 함수"""
        try:
            print(f'{Fore.YELLOW}Tor 서비스 상태 확인 중...')
            
            if self.check_tor_status():
                print(f'{Fore.GREEN}Tor 서비스가 이미 실행 중입니다.')
                return True
                
            print(f'{Fore.YELLOW}Tor 서비스 시작 중...')
            subprocess.run(['sudo', 'systemctl', 'start', 'tor'], check=True)
            
            time.sleep(3)
            
            if self.check_tor_status():
                print(f'{Fore.GREEN}Tor 서비스가 성공적으로 시작되었습니다.')
                return True
            else:
                print(f'{Fore.RED}Tor 서비스 시작 실패.')
                return False
                
        except Exception as e:
            print(f'{Fore.RED}Tor 서비스 시작 중 오류 발생: {e}')
            return False

    def validate_nmap_options(self, options: str) -> Tuple[bool, str]:
        """Nmap 옵션의 유효성을 검사하는 함수"""
        valid_options = {
            'sS', 'sT', 'sU', 'sN', 'sF', 'sX',  # 기본 스캔 옵션
            'sV', 'sC',  # 서비스 및 버전 감지
            'O',  # OS 감지
            'p', 'p-', 'F',  # 포트 지정 옵션
            'T0', 'T1', 'T2', 'T3', 'T4', 'T5'  # 타이밍 옵션
        }
        
        option_list = options.replace('-', ' ').split()
        
        for opt in option_list:
            if opt not in valid_options:
                return False, f"잘못된 옵션: {opt}"
        
        return True, ""

    def print_input_prompt(self, prompt: str, required: bool = True) -> str:
        """사용자 입력 프롬프트를 표시하는 함수"""
        print(f'\n{Style.BRIGHT}{Fore.CYAN}╔════════════════════════════════════════════════════════════╗')
        print(f'║                    {Fore.YELLOW}입력{Fore.CYAN}                                    ║')
        print(f'╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}')
        print(f'\n{Fore.WHITE}{prompt}{Style.RESET_ALL}')
        if required:
            print(f'{Fore.YELLOW}* 필수 입력 항목입니다.{Style.RESET_ALL}')
        return input(f'{Fore.GREEN}➤ {Style.RESET_ALL}').strip()

    def print_menu(self, title: str, options: List[str]) -> str:
        """메뉴를 표시하는 함수"""
        print(f'\n{Style.BRIGHT}{Fore.CYAN}╔════════════════════════════════════════════════════════════╗')
        print(f'║                    {Fore.YELLOW}{title}{Fore.CYAN}                                ║')
        print(f'╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}')
        
        for i, option in enumerate(options, 1):
            print(f'\n{Fore.YELLOW}{i}. {option}{Style.RESET_ALL}')
        
        while True:
            choice = input(f'\n{Fore.GREEN}➤ 선택하세요 (1-{len(options)}): {Style.RESET_ALL}').strip()
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return choice
            print(f'{Fore.RED}잘못된 입력입니다. 1-{len(options)} 사이의 숫자를 입력해주세요.{Style.RESET_ALL}')

    def get_scan_options(self) -> Optional[str]:
        """스캔 옵션을 선택하고 반환하는 함수"""
        while True:
            menu_options = [
                '기본 스캔 (-sCV -O -p-)',
                '빠른 스캔 (-sS -F -T4)',
                '서비스 버전 스캔 (-sV -p-)',
                '커스텀 스캔',
                '옵션 설명 보기'
            ]
            
            choice = self.print_menu('스캔 옵션 선택', menu_options)
            
            if choice == '1':
                return '-sCV -O -p-'
            elif choice == '2':
                return '-sS -F -T4'
            elif choice == '3':
                return '-sV -p-'
            elif choice == '4':
                while True:
                    print(f'\n{Style.BRIGHT}{Fore.CYAN}╔════════════════════════════════════════════════════════════╗')
                    print(f'║                    {Fore.YELLOW}커스텀 옵션 입력{Fore.CYAN}                    ║')
                    print(f'╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}')
                    
                    print(f'\n{Fore.WHITE}사용 가능한 옵션 예시:')
                    print(f'{Fore.CYAN}-sS{Fore.WHITE} (TCP SYN 스캔) + {Fore.CYAN}-sV{Fore.WHITE} (버전 감지) + {Fore.CYAN}-O{Fore.WHITE} (OS 감지)')
                    print(f'{Fore.CYAN}-sT{Fore.WHITE} (TCP 연결) + {Fore.CYAN}-p 80,443{Fore.WHITE} (특정 포트) + {Fore.CYAN}-T4{Fore.WHITE} (빠른 스캔)')
                    
                    custom_options = self.print_input_prompt('원하는 옵션을 입력하세요 (예: -sS -sV -O)')
                    
                    if not custom_options:
                        print(f'{Fore.RED}옵션을 입력해주세요!')
                        continue
                    
                    is_valid, error_msg = self.validate_nmap_options(custom_options)
                    if not is_valid:
                        print(f'{Fore.RED}{error_msg}')
                        retry = self.print_menu('다시 시도하시겠습니까?', ['예', '아니오'])
                        if retry == '2':
                            return None
                        continue
                    
                    return custom_options
            elif choice == '5':
                self.print_nmap_options()
                continue

    def run_scan_command(self, command: List[str], filename: str) -> bool:
        """스캔 명령을 실행하고 결과를 처리하는 함수"""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                env=dict(os.environ, PROXYCHAINS_QUIET_MODE='1')
            )

            with open(filename, 'a', encoding='utf-8') as file:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        if not output.strip().startswith('[proxychains]'):
                            print(f'{Fore.WHITE}{output.strip()}')
                            file.write(output)

            return process.poll() == 0
        except Exception as e:
            print(f'{Fore.RED}명령 실행 중 오류 발생: {e}')
            return False

    def check_vulnerabilities(self, port: int, service: str, version: str) -> List[Dict]:
        """특정 서비스의 취약점을 확인하는 함수"""
        vulnerabilities = []
        
        # 서비스별 취약점 체크
        if service.lower() in self.vulnerability_patterns:
            for vuln_type in self.vulnerability_patterns[service.lower()]:
                if self._check_specific_vulnerability(port, service, version, vuln_type):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'port': port,
                        'service': service,
                        'version': version,
                        'severity': self._get_severity_level(vuln_type)
                    })
        
        return vulnerabilities

    def _check_specific_vulnerability(self, port: int, service: str, version: str, vuln_type: str) -> bool:
        """특정 취약점 유형을 체크하는 함수"""
        try:
            if vuln_type == 'anonymous':
                if service.lower() == 'ftp':
                    return self._check_ftp_anonymous(port)
            elif vuln_type == 'weak_password':
                return self._check_weak_password(port, service)
            elif vuln_type == 'old_version':
                return self._check_old_version(service, version)
            elif vuln_type == 'ssl_vulnerability':
                if service.lower() == 'https':
                    return self._check_ssl_vulnerability(port)
            return False
        except Exception:
            return False

    def _check_ftp_anonymous(self, port: int) -> bool:
        """FTP 익명 접속 가능 여부를 체크하는 함수"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', port))
            sock.send(b'USER anonymous\r\n')
            response = sock.recv(1024)
            sock.close()
            return b'230' in response
        except Exception:
            return False

    def _check_weak_password(self, port: int, service: str) -> bool:
        """약한 비밀번호 사용 여부를 체크하는 함수"""
        # 실제 구현에서는 더 복잡한 로직이 필요
        return False

    def _check_old_version(self, service: str, version: str) -> bool:
        """구버전 사용 여부를 체크하는 함수"""
        # 실제 구현에서는 버전 비교 로직이 필요
        return False

    def _check_ssl_vulnerability(self, port: int) -> bool:
        """SSL 취약점을 체크하는 함수"""
        try:
            response = requests.get(f'https://127.0.0.1:{port}', verify=False, timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def _get_severity_level(self, vuln_type: str) -> str:
        """취약점의 심각도 레벨을 반환하는 함수"""
        severity_levels = {
            'anonymous': 'High',
            'weak_password': 'High',
            'old_version': 'Medium',
            'ssl_vulnerability': 'Critical',
            'heartbleed': 'Critical'
        }
        return severity_levels.get(vuln_type, 'Low')

    def scan_ports(self, target: str) -> Dict:
        """포트 스캔을 수행하는 함수"""
        try:
            print(f'{Style.BRIGHT}{Fore.BLUE}포트 스캔을 시작합니다...')
            print(f'{Style.BRIGHT}{Fore.YELLOW}이 스캔은 시간이 다소 걸릴 수 있습니다...')
            
            # 스캔 옵션 선택
            scan_options = self.get_scan_options()
            
            print(f'{Fore.CYAN}Tor를 통한 익명 스캔을 시작합니다...')
            print(f'{Fore.YELLOW}선택된 옵션: {scan_options}')
            
            # 스캔 명령 구성
            command = ['proxychains', '-q', 'nmap'] + scan_options.split() + [target]
            
            # 결과 파일명 생성
            scan_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f'scan_results_{scan_time}.txt'
            
            # 스캔 정보 저장
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(f'스캔 결과 - {target}\n')
                file.write(f'스캔 시작 시간: {scan_time}\n')
                file.write(f'사용된 옵션: {scan_options}\n\n')
            
            # 스캔 실행
            if self.run_scan_command(command, filename):
                print(f'{Style.BRIGHT}{Fore.GREEN}포트 스캔이 완료되었습니다.')
                print(f'결과가 {filename}에 저장되었습니다.')
                
                # 취약점 분석
                self.analyze_vulnerabilities(filename)
                
                return {
                    'status': 'completed',
                    'filename': filename,
                    'vulnerabilities': self.vulnerabilities
                }
            else:
                print(f'{Style.BRIGHT}{Fore.RED}스캔 중 오류가 발생했습니다.')
                return {'status': 'failed', 'error': '스캔 실행 실패'}
            
        except Exception as e:
            print(f'{Fore.RED}스캔 중 오류 발생: {e}')
            return {'status': 'failed', 'error': str(e)}

    def analyze_vulnerabilities(self, filename: str):
        """스캔 결과를 분석하여 취약점을 찾는 함수"""
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
                
                # 포트 정보 추출
                port_matches = re.finditer(r'(\d+)/tcp\s+open\s+(\w+)\s+(.*)', content)
                for match in port_matches:
                    port = int(match.group(1))
                    service = match.group(2)
                    version = match.group(3)
                    
                    # 취약점 체크
                    vulns = self.check_vulnerabilities(port, service, version)
                    self.vulnerabilities.extend(vulns)
                    
        except Exception as e:
            print(f'{Fore.RED}취약점 분석 중 오류 발생: {e}')

    def validate_ip(self, ip: str) -> bool:
        """IP 주소의 유효성을 검사하는 함수"""
        try:
            parts = ip.strip().split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, TypeError):
            return False

    def animate(self):
        """로딩 애니메이션을 표시하는 함수"""
        frames = [
            "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
            "⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷",
            "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
        ]
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
        
        for frame, color in zip(itertools.cycle(frames), itertools.cycle(colors)):
            if self.done:
                break
            sys.stdout.write(f'\r{color}스캔 진행 중... {frame} {Style.RESET_ALL}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        print(f'{Fore.GREEN}✓ 스캔 완료!{Style.RESET_ALL}\n')

    def print_banner(self):
        """프로그램 배너를 출력하는 함수"""
        banner = f"""
{Style.BRIGHT}{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                                                          ║
║  {Fore.YELLOW}███╗   ██╗███╗   ███╗ █████╗ ██████╗  ██████╗ ███████╗{Fore.CYAN}  ║
║  {Fore.YELLOW}████╗  ██║████╗ ████║██╔══██╗██╔══██╗██╔═══██╗██╔════╝{Fore.CYAN}  ║
║  {Fore.YELLOW}██╔██╗ ██║██╔████╔██║███████║██████╔╝██║   ██║███████╗{Fore.CYAN}  ║
║  {Fore.YELLOW}██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ██║   ██║╚════██║{Fore.CYAN}  ║
║  {Fore.YELLOW}██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ╚██████╔╝███████║{Fore.CYAN}  ║
║  {Fore.YELLOW}╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝{Fore.CYAN}  ║
║                                                          ║
║  {Fore.WHITE}Tor 통합 포트 스캐너 v1.0                          {Fore.CYAN}  ║
║  {Fore.WHITE}개발자: bigboss                                 {Fore.CYAN}  ║
║                                                          ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

def main():
    """메인 함수"""
    global done
    
    # 화면 클리어
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # 배너 출력
    print_banner()
    
    print(f'{Style.BRIGHT}{Fore.CYAN}=== Nmap 포트 스캐너 (Tor 전용) ==={Style.RESET_ALL}')
    
    # ProxyChains 설정 확인
    print(f'\n{Fore.YELLOW}ProxyChains 설정을 확인하는 중...{Style.RESET_ALL}')
    if not check_proxychains_config():
        print(f'{Fore.RED}ProxyChains 설정을 확인할 수 없습니다. 프로그램을 종료합니다.{Style.RESET_ALL}')
        sys.exit(1)
    
    print(f'\n{Style.BRIGHT}{Fore.YELLOW}Tor 서비스를 시작합니다...{Style.RESET_ALL}')
    
    # Tor 서비스 시작 시도
    if not start_tor_service():
        print(f'{Fore.RED}Tor 서비스를 시작할 수 없습니다. 프로그램을 종료합니다.{Style.RESET_ALL}')
        sys.exit(1)

    while True:
        # 사용자로부터 IP 주소 입력 받기
        target_ip = print_input_prompt('스캔할 IP 주소를 입력하세요')

        # IP 주소 유효성 검사
        if not validate_ip(target_ip):
            print(f'{Fore.RED}잘못된 IP 주소 형식입니다. 다시 입력해주세요.{Style.RESET_ALL}')
            continue
        break

    # 로딩 애니메이션 시작
    done = False
    t = threading.Thread(target=animate)
    t.start()

    try:
        # 포트 스캔 실행
        scan_ports(target_ip)
    finally:
        # 로딩 애니메이션 종료
        done = True
        t.join()

if __name__ == "__main__":
    main() 