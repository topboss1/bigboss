웹 보안 테스트 도구 실행 방법
================================

1. 필수 패키지 설치
------------------
먼저 필요한 Python 패키지들을 설치해야 합니다:
pip install -r requirements.txt

2. 기본 실행 방법
----------------
가장 기본적인 실행 방법은 다음과 같습니다:
python web_security_tool/main.py --target https://example.com

3. 스캔 유형 지정
----------------
특정 유형의 취약점만 검사하고 싶을 때는 --scan-type 옵션을 사용합니다:

# XSS 취약점만 검사
python web_security_tool/main.py --target https://example.com --scan-type xss

# SQL 인젝션 취약점만 검사
python web_security_tool/main.py --target https://example.com --scan-type sql

# 모든 취약점 검사 (기본값)
python web_security_tool/main.py --target https://example.com --scan-type all

4. 설정 파일 지정
----------------
사용자 정의 설정 파일을 사용하려면 --config 옵션을 사용합니다:
python web_security_tool/main.py --target https://example.com --config custom_config.json

5. 결과 출력 디렉토리 지정
------------------------
스캔 결과를 저장할 디렉토리를 지정하려면 --output 옵션을 사용합니다:
python web_security_tool/main.py --target https://example.com --output my_reports

6. 모든 옵션을 함께 사용하는 예시
--------------------------------
python web_security_tool/main.py \
    --target https://example.com \
    --scan-type all \
    --config custom_config.json \
    --output my_reports

7. 실행 결과 예시
----------------
스캔이 완료되면 다음과 같은 형식으로 결과가 출력됩니다:

Scan Results:
=============

XSS Scan:
Found 2 vulnerabilities:
- Type: xss
  URL: https://example.com/search
  Severity: high
  Payload: <script>alert(1)</script>

SQL_INJECTION Scan:
Found 1 vulnerability:
- Type: sql_injection
  URL: https://example.com/login
  Severity: critical
  Payload: ' OR '1'='1

8. 주의사항
----------
- 테스트 대상 웹사이트의 소유자에게 허가를 받은 후에만 스캔을 실행하세요
- 프로덕션 환경에서는 주의해서 사용하세요
- 너무 많은 요청을 보내지 않도록 설정 파일에서 적절한 타임아웃과 재시도 횟수를 설정하세요
- 스캔 결과는 보안적으로 중요한 정보이므로 안전하게 보관하세요

9. 도움말 보기
------------
사용 가능한 모든 옵션을 보려면 다음 명령어를 실행하세요:
python web_security_tool/main.py --help 