# P-ALL: 통합 보안 스캐너

## 프로젝트 개요
P-ALL은 웹 애플리케이션 및 시스템의 보안 취약점을 검사하고 평가하는 종합적인 도구입니다. 다양한 모듈을 통합하여 포괄적인 보안 스캐닝을 제공합니다.

## 주요 기능
- 포트 스캐닝
- 웹 취약점 스캐닝 (XSS, SQL Injection)
- SSH 보안 스캐닝
- Nmap 기반 고급 스캐닝
- JavaScript 코드 분석
- 자동 에러 수정 및 복구
- 상세한 보고서 생성

## 프로젝트 구조
```
P-ALL/
├── config/           # 설정 파일
├── core/            # 핵심 기능
├── modules/         # 스캐닝 모듈
├── payloads/        # 페이로드 데이터
├── reports/         # 스캔 보고서
├── services/        # 서비스 모듈
├── utils/           # 유틸리티 함수
├── main.py          # 메인 실행 파일
├── requirements.txt # 의존성 목록
└── README.md        # 프로젝트 문서
```

## 모듈 설명
1. 포트 스캐너 (`port_scanner.py`)
   - TCP/UDP 포트 스캐닝
   - 서비스 식별
   - 취약점 분석

2. 웹 스캐너 (`web_scanner.py`)
   - XSS 취약점 검사
   - SQL Injection 취약점 검사
   - 웹 서버 구성 분석

3. SSH 스캐너 (`ssh_scanner.py`)
   - SSH 서버 구성 검사
   - 인증 메커니즘 분석
   - 암호화 설정 검사

4. Nmap 스캐너 (`nmap_scanner.py`)
   - 고급 포트 스캐닝
   - OS 및 서비스 식별
   - 취약점 스캐닝

5. JavaScript 분석기 (`js_analyzer.py`)
   - JavaScript 코드 분석
   - 보안 취약점 검사
   - 의심스러운 패턴 식별

6. 에러 핸들러 (`error_handler.py`)
   - 자동 에러 감지
   - 에러 수정 시도
   - 복구 메커니즘

## 설치 방법
1. 저장소 클론
```bash
git clone https://github.com/yourusername/P-ALL.git
cd P-ALL
```

2. 가상 환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. 의존성 설치
```bash
pip install -r requirements.txt
```

4. 환경 변수 설정
```bash
cp .env.example .env
# .env 파일을 편집하여 필요한 설정을 입력
```

## 사용 방법
1. 기본 실행
```bash
python main.py
```

2. 특정 모듈 실행
```bash
python main.py --module port
python main.py --module web
```

3. 고급 옵션
```bash
python main.py --target example.com --module all --output report.html
```

## 설정 옵션
- `--target`: 스캔 대상 (URL 또는 IP)
- `--module`: 실행할 모듈 (all, port, web, ssh, nmap, js)
- `--output`: 보고서 출력 형식 (html, pdf, json)
- `--timeout`: 스캔 타임아웃 (초)
- `--threads`: 동시 스캔 스레드 수

## 보안 고려사항
- 법적 및 윤리적 가이드라인 준수
- 대상 시스템의 허가 받은 스캔만 수행
- 민감한 정보 보호
- 스캔 결과의 안전한 저장

## 라이선스
MIT License

## 기여 방법
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 버그 리포트
GitHub Issues를 통해 버그를 리포트해주세요.

## 연락처
- 이메일: your.email@example.com
- 웹사이트: https://example.com 