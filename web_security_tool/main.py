import os
import sys
import argparse
import logging
from typing import Dict

# 현재 파일의 절대 경로를 기준으로 프로젝트 루트 디렉토리 경로 계산
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

# 프로젝트 루트 디렉토리를 Python 경로에 추가
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from web_security_tool.modules.xss_scanner import XSSScanner
from web_security_tool.modules.sql_injection_scanner import SQLInjectionScanner
from web_security_tool.modules.ssh_scanner import SSHScanner

def setup_logging():
    """로그 설정을 구성합니다."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def parse_arguments():
    """명령줄 인자를 파싱합니다."""
    parser = argparse.ArgumentParser(
        description='웹 보안 테스트 도구',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
사용 예시:
  # 기본 실행
  python main.py --target http://example.com

  # XSS 스캔만 실행
  python main.py --target http://example.com --scan-type xss

  # 모든 스캔 실행
  python main.py --target http://example.com --scan-type all

  # 보고서 저장 위치 지정
  python main.py --target http://example.com --output custom_reports

  # 설정 파일 사용
  python main.py --target http://example.com --config config.json
        '''
    )
    
    parser.add_argument(
        '--target', 
        required=True, 
        help='테스트할 대상 URL 또는 IP 주소 (예: http://example.com)'
    )
    
    parser.add_argument(
        '--scan-type', 
        choices=['xss', 'sql', 'ssh', 'all'], 
        default='all',
        help='''
실행할 스캔 유형:
  xss  - XSS(Cross-Site Scripting) 취약점 검사
  sql  - SQL 인젝션 취약점 검사
  ssh  - SSH 보안 검사
  all  - 모든 스캔 실행 (기본값)
        '''
    )
    
    parser.add_argument(
        '--output', 
        default='reports',
        help='보고서를 저장할 디렉토리 (기본값: reports)'
    )
    
    parser.add_argument(
        '--config', 
        help='설정 파일 경로'
    )
    
    return parser.parse_args()

def run_scan(target: str, scan_type: str, config: Dict = None) -> Dict:
    """Run the specified security scan."""
    results = {}
    
    if scan_type in ['xss', 'all']:
        xss_scanner = XSSScanner(target, config)
        results['xss'] = xss_scanner.scan()
        
    if scan_type in ['sql', 'all']:
        sql_scanner = SQLInjectionScanner(target, config)
        results['sql_injection'] = sql_scanner.scan()
        
    if scan_type in ['ssh', 'all']:
        ssh_scanner = SSHScanner(target, config)
        results['ssh'] = ssh_scanner.scan()
        
    return results

def main():
    """웹 보안 도구의 메인 진입점입니다."""
    setup_logging()
    args = parse_arguments()
    
    try:
        results = run_scan(args.target, args.scan_type)
        print("\n스캔 결과:")
        print("=" * 50)
        
        for scan_type, result in results.items():
            print(f"\n{scan_type.upper()} 스캔 결과:")
            if result['status'] == 'completed':
                vulnerabilities = result.get('vulnerabilities', [])
                if vulnerabilities:
                    print(f"발견된 취약점: {len(vulnerabilities)}개")
                    print("-" * 30)
                    for vuln in vulnerabilities:
                        print(f"취약점 유형: {vuln['type']}")
                        if 'url' in vuln:
                            print(f"  URL: {vuln['url']}")
                        if 'username' in vuln:
                            print(f"  사용자명: {vuln['username']}")
                        if 'password' in vuln:
                            print(f"  비밀번호: {vuln['password']}")
                        if 'version' in vuln:
                            print(f"  버전: {vuln['version']}")
                        if 'algorithm' in vuln:
                            print(f"  알고리즘: {vuln['algorithm']}")
                        print(f"  심각도: {vuln['severity']}")
                        if 'payload' in vuln:
                            print(f"  페이로드: {vuln['payload']}")
                        print("-" * 30)
                else:
                    print("취약점이 발견되지 않았습니다.")
            else:
                print(f"스캔 실패: {result.get('error', '알 수 없는 오류')}")
                
    except Exception as e:
        logging.error(f"스캔 중 오류 발생: {e}")
        return 1
        
    return 0

if __name__ == '__main__':
    exit(main()) 