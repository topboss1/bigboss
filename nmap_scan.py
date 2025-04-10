#nmap_scan.py 

import nmap
from colorama import init, Fore, Style
import itertools
import threading
import time
import sys
import subprocess
from datetime import datetime
import os

# colorama 초기화
init(autoreset=True)

def print_nmap_options():
    """Nmap 주요 옵션 설명을 출력하는 함수"""
    print(f'\n{Style.BRIGHT}{Fore.CYAN}=== Nmap 주요 옵션 설명 ==={Style.RESET_ALL}')
    print(f'\n{Style.BRIGHT}{Fore.YELLOW}1. 기본 스캔 옵션:{Style.RESET_ALL}')
    print(f'{Fore.WHITE}┌─────────────────────────────────────────────┐')
    print(f'│ {Fore.CYAN}-sS{Fore.WHITE}: TCP SYN 스캔 (기본 스캔 방식)            │')
    print(f'│ {Fore.CYAN}-sT{Fore.WHITE}: TCP 연결 스캔                          │')
    print(f'│ {Fore.CYAN}-sU{Fore.WHITE}: UDP 스캔                               │')
    print(f'│ {Fore.CYAN}-sN{Fore.WHITE}: TCP NULL 스캔                          │')
    print(f'│ {Fore.CYAN}-sF{Fore.WHITE}: TCP FIN 스캔                           │')
    print(f'│ {Fore.CYAN}-sX{Fore.WHITE}: TCP Xmas 스캔                          │')
    print(f'└─────────────────────────────────────────────┘')
    
    print(f'\n{Style.BRIGHT}{Fore.YELLOW}2. 포트 지정 옵션:{Style.RESET_ALL}')
    print(f'{Fore.WHITE}┌─────────────────────────────────────────────┐')
    print(f'│ {Fore.CYAN}-p{Fore.WHITE}: 특정 포트 스캔 (예: -p 80,443)           │')
    print(f'│ {Fore.CYAN}-p-{Fore.WHITE}: 모든 포트 스캔 (1-65535)               │')
    print(f'│ {Fore.CYAN}-F{Fore.WHITE}: 빠른 스캔 (일반적인 포트만)             │')
    print(f'└─────────────────────────────────────────────┘')
    
    print(f'\n{Style.BRIGHT}{Fore.YELLOW}3. 서비스 및 버전 감지:{Style.RESET_ALL}')
    print(f'{Fore.WHITE}┌─────────────────────────────────────────────┐')
    print(f'│ {Fore.CYAN}-sV{Fore.WHITE}: 서비스 버전 감지                        │')
    print(f'│ {Fore.CYAN}-sC{Fore.WHITE}: 기본 스크립트 실행                      │')
    print(f'└─────────────────────────────────────────────┘')
    
    print(f'\n{Style.BRIGHT}{Fore.YELLOW}4. OS 감지:{Style.RESET_ALL}')
    print(f'{Fore.WHITE}┌─────────────────────────────────────────────┐')
    print(f'│ {Fore.CYAN}-O{Fore.WHITE}: 운영체제 감지                            │')
    print(f'└─────────────────────────────────────────────┘')
    
    print(f'\n{Style.BRIGHT}{Fore.YELLOW}5. 타이밍 옵션:{Style.RESET_ALL}')
    print(f'{Fore.WHITE}┌─────────────────────────────────────────────┐')
    print(f'│ {Fore.CYAN}-T0{Fore.WHITE}: 매우 느린 스캔                          │')
    print(f'│ {Fore.CYAN}-T1{Fore.WHITE}: 느린 스캔                               │')
    print(f'│ {Fore.CYAN}-T2{Fore.WHITE}: 정상 스캔                               │')
    print(f'│ {Fore.CYAN}-T3{Fore.WHITE}: 빠른 스캔 (기본값)                      │')
    print(f'│ {Fore.CYAN}-T4{Fore.WHITE}: 매우 빠른 스캔                          │')
    print(f'│ {Fore.CYAN}-T5{Fore.WHITE}: 초고속 스캔                             │')
    print(f'└─────────────────────────────────────────────┘')
    print(f'\n{Style.BRIGHT}{Fore.CYAN}==========================================={Style.RESET_ALL}\n')

def check_proxychains_config():
    """ProxyChains 설정을 확인하고 필요한 경우 수정하는 함수"""
    config_path = '/etc/proxychains4.conf'
    try:
        # 설정 파일이 있는지 확인
        if not os.path.exists(config_path):
            print(f'{Fore.RED}ProxyChains 설정 파일을 찾을 수 없습니다.')
            return False

        # 설정 파일 읽기
        with open(config_path, 'r') as f:
            config = f.read()

        # Tor 설정 확인
        if 'socks5  127.0.0.1 9050' not in config:
            print(f'{Fore.YELLOW}ProxyChains 설정에 Tor 설정을 추가합니다...')
            with open(config_path, 'a') as f:
                f.write('\nsocks5  127.0.0.1 9050')
            print(f'{Fore.GREEN}ProxyChains 설정이 업데이트되었습니다.')

        return True
    except Exception as e:
        print(f'{Fore.RED}ProxyChains 설정 확인 중 오류 발생: {e}')
        return False

def check_tor_status():
    """Tor 서비스의 상태를 확인하는 함수"""
    try:
        status = subprocess.run(['systemctl', 'is-active', 'tor'], 
                              capture_output=True, text=True)
        return status.stdout.strip() == 'active'
    except Exception:
        return False

def start_tor_service():
    """Tor 서비스를 시작하고 상태를 확인하는 함수"""
    try:
        print(f'{Fore.YELLOW}Tor 서비스 상태 확인 중...')
        
        # Tor가 이미 실행 중인지 확인
        if check_tor_status():
            print(f'{Fore.GREEN}Tor 서비스가 이미 실행 중입니다.')
            return True
            
        print(f'{Fore.YELLOW}Tor 서비스 시작 중...')
        # Tor 서비스 시작
        subprocess.run(['sudo', 'systemctl', 'start', 'tor'], check=True)
        
        # 서비스 시작 대기
        time.sleep(3)
        
        # 상태 확인
        if check_tor_status():
            print(f'{Fore.GREEN}Tor 서비스가 성공적으로 시작되었습니다.')
            return True
        else:
            print(f'{Fore.RED}Tor 서비스 시작 실패.')
            return False
            
    except Exception as e:
        print(f'{Fore.RED}Tor 서비스 시작 중 오류 발생: {e}')
        return False

def get_scan_options():
    """스캔 옵션을 선택하고 반환하는 함수"""
    while True:
        print(f'\n{Style.BRIGHT}{Fore.CYAN}=== Nmap 스캔 옵션 선택 ===')
        print(f'{Fore.YELLOW}1. 기본 스캔 (-sCV -O -p-)')
        print(f'{Fore.YELLOW}2. 빠른 스캔 (-sS -F -T4)')
        print(f'{Fore.YELLOW}3. 서비스 버전 스캔 (-sV -p-)')
        print(f'{Fore.YELLOW}4. 커스텀 스캔')
        
        choice = input(f"{Fore.GREEN}옵션을 선택하세요 (1-4): ").strip()
        
        if choice == '1':
            return '-sCV -O -p-'
        elif choice == '2':
            return '-sS -F -T4'
        elif choice == '3':
            return '-sV -p-'
        elif choice == '4':
            print(f'\n{Fore.YELLOW}옵션 설명을 보시겠습니까? (y/n)')
            if input().lower().strip() == 'y':
                print_nmap_options()
            
            while True:
                custom_options = input(f"{Fore.GREEN}Nmap 옵션을 입력하세요: ").strip()
                if custom_options:
                    return custom_options
                print(f'{Fore.RED}옵션을 입력해주세요!')
        else:
            print(f'{Fore.RED}잘못된 선택입니다. 1-4 중에서 선택해주세요.')

def run_scan_command(command, filename):
    """스캔 명령을 실행하고 결과를 처리하는 함수"""
    try:
        # STDERR를 STDOUT으로 리다이렉트
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
                    # ProxyChains 메시지 필터링
                    if not output.strip().startswith('[proxychains]'):
                        print(f'{Fore.WHITE}{output.strip()}')
                        file.write(output)

        return process.poll() == 0
    except Exception as e:
        print(f'{Fore.RED}명령 실행 중 오류 발생: {e}')
        return False

def scan_ports(target):
    """포트 스캔을 수행하는 함수"""
    try:
        print(f'{Style.BRIGHT}{Fore.BLUE}포트 스캔을 시작합니다...')
        print(f'{Style.BRIGHT}{Fore.YELLOW}이 스캔은 시간이 다소 걸릴 수 있습니다...')
        
        # 스캔 옵션 선택
        scan_options = get_scan_options()
        
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
        if run_scan_command(command, filename):
            print(f'{Style.BRIGHT}{Fore.GREEN}포트 스캔이 완료되었습니다.')
            print(f'결과가 {filename}에 저장되었습니다.')
        else:
            print(f'{Style.BRIGHT}{Fore.RED}스캔 중 오류가 발생했습니다.')
        
    except Exception as e:
        print(f'{Fore.RED}스캔 중 오류 발생: {e}')

def animate():
    """로딩 애니메이션을 표시하는 함수"""
    frames = [
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
        "⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷",
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    ]
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    
    for frame, color in zip(itertools.cycle(frames), itertools.cycle(colors)):
        if done:
            break
        sys.stdout.write(f'\r{color}스캔 진행 중... {frame} {Style.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 50 + '\r')
    print(f'{Fore.GREEN}✓ 스캔 완료!{Style.RESET_ALL}\n')

def print_banner():
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

def validate_ip(ip):
    """IP 주소의 유효성을 검사하는 함수"""
    try:
        parts = ip.strip().split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, TypeError):
        return False

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
        print(f'\n{Fore.GREEN}스캔할 IP 주소를 입력하세요: {Style.RESET_ALL}', end='')
        target_ip = input().strip()

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