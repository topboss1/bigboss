# 웹 보안 테스트 도구

웹 애플리케이션의 보안 취약점을 검사하고 평가하는 종합적인 도구입니다.

## 주요 기능

- 웹 애플리케이션 스캔
- 취약점 평가
- 네트워크 보안 테스트
- SSL/TLS 분석
- 자동화된 보안 테스트
- 보고서 생성

## 설치 방법

1. 저장소 복제:
```bash
git clone https://github.com/사용자이름/web_security_tool.git
cd web_security_tool
```

2. 가상 환경 생성 (권장):
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

3. 필요한 패키지 설치:
```bash
pip install -r requirements.txt
```

## 사용 방법

```bash
python main.py [옵션]
```

### 옵션
- `--target`: 테스트 대상 URL 또는 IP 주소
- `--scan-type`: 수행할 검사 유형
- `--output`: 보고서 저장 디렉토리
- `--config`: 설정 파일 경로

## 프로젝트 구조

```
web_security_tool/
├── core/           # 핵심 기능
├── modules/        # 보안 테스트 모듈
├── utils/          # 유틸리티 함수
├── payloads/       # 테스트 페이로드
├── config/         # 설정 파일
├── reports/        # 생성된 보고서
├── requirements.txt
└── README.md
```

## 기여 방법

1. 저장소를 포크합니다
2. 기능 브랜치를 생성합니다 (`git checkout -b feature/새로운기능`)
3. 변경사항을 커밋합니다 (`git commit -m '새로운 기능 추가'`)
4. 브랜치에 푸시합니다 (`git push origin feature/새로운기능`)
5. 풀 리퀘스트를 엽니다

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 LICENSE 파일을 참조하세요.

## 주의사항

이 도구는 교육 및 허가된 테스트 목적으로만 사용해야 합니다. 
시스템을 테스트하기 전에 반드시 적절한 승인을 받으세요. 