"""
Configuration module for the reverse shell system.
Contains all configuration constants and settings.
"""

import logging

# General configuration
CONFIG = {
    'logging': {
        'level': logging.INFO,
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'handlers': [
            logging.FileHandler('reverse_shell.log'),
            logging.StreamHandler()
        ]
    },
    'timeouts': {
        'connection': 30,
        'execution': 60,
        'shell': 120
    },
    'retries': {
        'connection': 3,
        'execution': 2,
        'shell': 2
    },
    'security': {
        'min_key_length': 32,
        'encryption_algorithm': 'AES-256-GCM',
        'hash_algorithm': 'SHA-256'
    },
    'network': {
        'default_protocol': 'tcp',
        'allowed_ports': range(1024, 65536),
        'banned_ports': [3389, 22, 80, 443]  # Common service ports
    }
}

# Execution sequence configuration
EXECUTION_SEQUENCE = [
    {
        'step': 'preparation',
        'description': '실행 준비',
        'tasks': [
            '환경 설정 확인',
            '필요한 도구 설치',
            '네트워크 연결 확인',
            '타겟 정보 수집'
        ],
        'timeout': 300
    },
    {
        'step': 'payload_generation',
        'description': '페이로드 생성',
        'tasks': [
            '페이로드 타입 선택',
            '암호화 설정',
            '난독화 적용',
            '페이로드 검증'
        ],
        'timeout': 600
    },
    {
        'step': 'delivery',
        'description': '페이로드 전달',
        'tasks': [
            '전달 방법 선택',
            '전달 경로 설정',
            '전달 시도',
            '전달 결과 확인'
        ],
        'timeout': 900
    },
    {
        'step': 'execution',
        'description': '페이로드 실행',
        'tasks': [
            '실행 조건 확인',
            '실행 권한 획득',
            '페이로드 실행',
            '실행 결과 확인'
        ],
        'timeout': 1200
    },
    {
        'step': 'connection',
        'description': '연결 수립',
        'tasks': [
            '리스너 시작',
            '연결 대기',
            '연결 수립',
            '연결 검증'
        ],
        'timeout': 1500
    }
]

# Acquisition sequence configuration
ACQUISITION_SEQUENCE = [
    {
        'step': 'initial_recon',
        'description': '초기 정찰',
        'tasks': [
            '시스템 정보 수집',
            '네트워크 정보 수집',
            '사용자 정보 수집',
            '서비스 정보 수집'
        ],
        'methods': ['nmap', 'whois', 'dns_lookup'],
        'timeout': 300
    },
    {
        'step': 'vulnerability_scan',
        'description': '취약점 스캔',
        'tasks': [
            '포트 스캔',
            '서비스 버전 확인',
            '취약점 확인',
            '익스플로잇 가능성 평가'
        ],
        'methods': ['nmap_vuln', 'nikto', 'sqlmap'],
        'timeout': 600
    },
    {
        'step': 'initial_access',
        'description': '초기 접근',
        'tasks': [
            '접근 방법 선택',
            '인증 시도',
            '접근 권한 획득',
            '접근 지속성 확인'
        ],
        'methods': ['web_shell', 'ssh_brute', 'rdp_brute'],
        'timeout': 900
    },
    {
        'step': 'privilege_escalation',
        'description': '권한 상승',
        'tasks': [
            '현재 권한 확인',
            '상승 방법 선택',
            '상승 시도',
            '상승 결과 확인'
        ],
        'methods': ['sudo_abuse', 'kernel_exploit', 'service_abuse'],
        'timeout': 1200
    },
    {
        'step': 'persistence',
        'description': '지속성 확보',
        'tasks': [
            '지속성 방법 선택',
            '지속성 설정',
            '지속성 확인',
            '백업 방법 설정'
        ],
        'methods': ['cron_job', 'startup_script', 'service_install'],
        'timeout': 300
    }
] 