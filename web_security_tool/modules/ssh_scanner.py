from typing import Dict, List
import paramiko
import socket
import logging
from ..core.scanner import SecurityScanner

class SSHScanner(SecurityScanner):
    """Scanner for detecting SSH vulnerabilities."""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.port = 22  # 기본 SSH 포트
        self.timeout = 30  # 기본 타임아웃 (초)
        self.logger = logging.getLogger(__name__)
        
    def scan(self) -> Dict:
        """
        Scan for SSH vulnerabilities.
        
        Returns:
            Dict: Results containing found vulnerabilities
        """
        results = {
            'vulnerabilities': [],
            'tested_ports': [],
            'status': 'completed'
        }
        
        try:
            # SSH 서비스 확인
            if not self._check_ssh_service():
                results['status'] = 'failed'
                results['error'] = 'SSH service not found'
                return results
                
            # 취약점 검사
            self._test_weak_passwords(results)
            self._test_ssh_version(results)
            self._test_key_exchange(results)
            
        except Exception as e:
            self.logger.error(f"Error during SSH scan: {e}")
            results['status'] = 'failed'
            results['error'] = str(e)
            
        return results
        
    def _check_ssh_service(self) -> bool:
        """Check if SSH service is running on the target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except Exception as e:
            self.logger.error(f"Error checking SSH service: {e}")
            return False
            
    def _test_weak_passwords(self, results: Dict):
        """Test for weak passwords."""
        common_passwords = [
            'admin', 'password', '123456', 'root',
            'test', 'guest', 'administrator'
        ]
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            for password in common_passwords:
                try:
                    ssh.connect(
                        self.target,
                        port=self.port,
                        username='root',
                        password=password,
                        timeout=self.timeout
                    )
                    results['vulnerabilities'].append({
                        'type': 'weak_password',
                        'username': 'root',
                        'password': password,
                        'severity': 'critical'
                    })
                    break
                except paramiko.AuthenticationException:
                    continue
                except Exception as e:
                    self.logger.error(f"Error testing password {password}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error in weak password test: {e}")
            
    def _test_ssh_version(self, results: Dict):
        """Test for outdated SSH versions."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # SSH 버전 정보 수신
            version = sock.recv(1024).decode().strip()
            sock.close()
            
            # 오래된 버전 확인
            if 'SSH-1.99' in version or 'SSH-1.5' in version:
                results['vulnerabilities'].append({
                    'type': 'outdated_version',
                    'version': version,
                    'severity': 'high'
                })
                
        except Exception as e:
            self.logger.error(f"Error testing SSH version: {e}")
            
    def _test_key_exchange(self, results: Dict):
        """Test for weak key exchange algorithms."""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 취약한 키 교환 알고리즘 목록
            weak_algorithms = [
                'diffie-hellman-group1-sha1',
                'diffie-hellman-group14-sha1'
            ]
            
            transport = ssh.get_transport()
            if transport:
                kex_algorithms = transport.get_security_options().kex
                
                for algorithm in weak_algorithms:
                    if algorithm in kex_algorithms:
                        results['vulnerabilities'].append({
                            'type': 'weak_key_exchange',
                            'algorithm': algorithm,
                            'severity': 'medium'
                        })
                        
        except Exception as e:
            self.logger.error(f"Error testing key exchange: {e}") 