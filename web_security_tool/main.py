import os
import sys
import argparse
import logging
from typing import Dict
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading

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

class SecurityToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("웹 보안 테스트 도구")
        self.root.geometry("800x600")
        
        self.setup_gui()
        
    def setup_gui(self):
        # 메인 프레임
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # URL 입력
        ttk.Label(main_frame, text="대상 URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # 스캔 유형 선택
        ttk.Label(main_frame, text="스캔 유형:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.scan_type = tk.StringVar(value="all")
        ttk.Radiobutton(main_frame, text="XSS", variable=self.scan_type, value="xss").grid(row=1, column=1, sticky=tk.W)
        ttk.Radiobutton(main_frame, text="SQL 인젝션", variable=self.scan_type, value="sql").grid(row=1, column=2, sticky=tk.W)
        ttk.Radiobutton(main_frame, text="SSH", variable=self.scan_type, value="ssh").grid(row=1, column=3, sticky=tk.W)
        ttk.Radiobutton(main_frame, text="모든 스캔", variable=self.scan_type, value="all").grid(row=1, column=4, sticky=tk.W)
        
        # 시작 버튼
        self.start_button = ttk.Button(main_frame, text="스캔 시작", command=self.start_scan)
        self.start_button.grid(row=2, column=0, columnspan=5, pady=10)
        
        # 결과 표시 영역
        ttk.Label(main_frame, text="스캔 결과:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.result_text = scrolledtext.ScrolledText(main_frame, width=70, height=20)
        self.result_text.grid(row=4, column=0, columnspan=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 상태 표시줄
        self.status_var = tk.StringVar()
        self.status_var.set("준비")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=5, column=0, columnspan=5, sticky=(tk.W, tk.E), pady=5)
        
    def start_scan(self):
        target = self.url_entry.get().strip()
        if not target:
            messagebox.showerror("오류", "URL을 입력해주세요.")
            return
            
        self.start_button.config(state="disabled")
        self.status_var.set("스캔 중...")
        self.result_text.delete(1.0, tk.END)
        
        # 별도 스레드에서 스캔 실행
        scan_thread = threading.Thread(target=self.run_scan_thread, args=(target,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def run_scan_thread(self, target):
        try:
            results = run_scan(target, self.scan_type.get())
            self.display_results(results)
        except Exception as e:
            self.result_text.insert(tk.END, f"스캔 중 오류 발생: {str(e)}\n")
        finally:
            self.start_button.config(state="normal")
            self.status_var.set("준비")
            
    def display_results(self, results):
        self.result_text.insert(tk.END, "\n스캔 결과:\n")
        self.result_text.insert(tk.END, "=" * 50 + "\n")
        
        for scan_type, result in results.items():
            self.result_text.insert(tk.END, f"\n{scan_type.upper()} 스캔 결과:\n")
            if result['status'] == 'completed':
                vulnerabilities = result.get('vulnerabilities', [])
                if vulnerabilities:
                    self.result_text.insert(tk.END, f"발견된 취약점: {len(vulnerabilities)}개\n")
                    self.result_text.insert(tk.END, "-" * 30 + "\n")
                    for vuln in vulnerabilities:
                        self.result_text.insert(tk.END, f"취약점 유형: {vuln['type']}\n")
                        if 'url' in vuln:
                            self.result_text.insert(tk.END, f"  URL: {vuln['url']}\n")
                        if 'username' in vuln:
                            self.result_text.insert(tk.END, f"  사용자명: {vuln['username']}\n")
                        if 'password' in vuln:
                            self.result_text.insert(tk.END, f"  비밀번호: {vuln['password']}\n")
                        if 'version' in vuln:
                            self.result_text.insert(tk.END, f"  버전: {vuln['version']}\n")
                        if 'algorithm' in vuln:
                            self.result_text.insert(tk.END, f"  알고리즘: {vuln['algorithm']}\n")
                        self.result_text.insert(tk.END, f"  심각도: {vuln['severity']}\n")
                        if 'payload' in vuln:
                            self.result_text.insert(tk.END, f"  페이로드: {vuln['payload']}\n")
                        self.result_text.insert(tk.END, "-" * 30 + "\n")
                else:
                    self.result_text.insert(tk.END, "취약점이 발견되지 않았습니다.\n")
            else:
                self.result_text.insert(tk.END, f"스캔 실패: {result.get('error', '알 수 없는 오류')}\n")

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
    
    # GUI 모드로 실행
    root = tk.Tk()
    app = SecurityToolGUI(root)
    root.mainloop()

if __name__ == '__main__':
    exit(main()) 