#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
P-ALL: 통합 보안 스캐너
Author: bigboss
Version: 1.0.0
Description: 웹 애플리케이션 및 시스템의 보안 취약점을 검사하고 평가하는 종합적인 도구
"""

import os
import sys
import logging
import asyncio
import ipaddress
import argparse
from typing import Optional, Dict, Any, List
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.traceback import install
from dotenv import load_dotenv
import re
from urllib.parse import urlparse
from pathlib import Path

# Install rich traceback handler
install()

# Load environment variables
load_dotenv()

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        RichHandler(rich_tracebacks=True, markup=True),
        logging.FileHandler(Path('logs') / f'p-all_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)
console = Console()

# Import modules
from modules.port_scanner import PortScanner
from modules.xss_scanner import XSSScanner
from modules.sql_injection_scanner import SQLInjectionScanner
from modules.ssh_scanner import SSHScanner
from modules.reverse_shell import ReverseShell
from modules.nmap_scanner import NmapScanner
from modules.js_analyzer import JSAnalyzer
from modules.error_handler import ErrorHandler

# ASCII Art Banner with improved styling
BANNER = """[bold magenta]
██████╗     █████╗ ██╗     ██╗     
██╔══██╗   ██╔══██╗██║     ██║     
██████╔╝   ███████║██║     ██║     
██╔═══╝    ██╔══██║██║     ██║     
██║        ██║  ██║███████╗███████╗
╚═╝        ╚═╝  ╚═╝╚══════╝╚══════╝[/bold magenta]
                                    
[cyan]Author:[/cyan] [green]bigboss[/green]
[cyan]Version:[/cyan] [green]1.0.0[/green]
[cyan]Description:[/cyan] [green]통합 보안 스캐너[/green]
[bold blue]═══════════════════════════════════════════════════[/bold blue]
"""

# 모듈 정보 정의
MODULES = {
    'port': {
        'name': '포트 스캐너',
        'description': '대상 시스템의 열린 포트와 서비스를 검사합니다.',
        'requires_url': False,
        'dependencies': [],
        'default_order': 1,
        'timeout': 30,
        'threads': 10
    },
    'web': {
        'name': '웹 취약점 스캐너',
        'description': '웹 애플리케이션의 XSS, SQL Injection 등의 취약점을 검사합니다.',
        'requires_url': True,
        'dependencies': ['port'],
        'default_order': 2,
        'timeout': 60,
        'threads': 5
    },
    'ssh': {
        'name': 'SSH 보안 스캐너',
        'description': 'SSH 서비스의 보안 설정과 취약점을 검사합니다.',
        'requires_url': False,
        'dependencies': ['port'],
        'default_order': 2,
        'timeout': 30,
        'threads': 3
    },
    'nmap': {
        'name': 'Nmap 스캐너',
        'description': 'Nmap을 사용한 고급 포트 스캐닝과 서비스 검사',
        'requires_url': False,
        'dependencies': [],
        'default_order': 1,
        'timeout': 120,
        'threads': 1
    },
    'js': {
        'name': 'JavaScript 분석기',
        'description': '웹 페이지의 JavaScript 코드를 분석하여 보안 취약점을 검사합니다.',
        'requires_url': True,
        'dependencies': ['web'],
        'default_order': 3,
        'timeout': 45,
        'threads': 2
    }
}

class PAllScanner:
    def __init__(self, args: argparse.Namespace):
        self.console = Console()
        self.target_ip: Optional[str] = None
        self.target_url: Optional[str] = None
        self.results: Dict[str, Any] = {}
        self.vulnerabilities: List[Dict] = []
        self.is_url: bool = False
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
        self.selected_modules: List[str] = []
        self.module_order: Dict[str, int] = {}
        self.args = args
        
        # Create necessary directories
        Path('logs').mkdir(exist_ok=True)
        Path('reports').mkdir(exist_ok=True)
        Path('payloads').mkdir(exist_ok=True)

    async def get_user_input(self) -> bool:
        """Get and validate target input from user with improved UI"""
        try:
            if self.args.target:
                target = self.args.target
                if self._is_valid_url(target):
                    self.target_url = target
                    self.is_url = True
                elif self._is_valid_ip(target):
                    self.target_ip = target
                    self.is_url = False
                else:
                    self.console.print("[bold red]잘못된 대상 형식입니다.[/bold red]")
                    return False
                return True

            while True:
                self.console.print(Panel(
                    "[bold blue]스캔 대상 선택[/bold blue]\n\n"
                    "1. URL 입력 (예: https://example.com)\n"
                    "2. IP 주소 입력 (예: 192.168.1.1)\n"
                    "3. 종료",
                    title="P-ALL Scanner"
                ))
                
                choice = await self._get_valid_input("선택 (1-3): ", ['1', '2', '3'])
                
                if choice == '3':
                    return False
                
                target = await self._get_valid_input(
                    "대상을 입력하세요: ",
                    validator=self._validate_url if choice == '1' else self._validate_ip
                )
                
                if target:
                    if choice == '1':
                        self.target_url = target
                        self.is_url = True
                    else:
                        self.target_ip = target
                        self.is_url = False
                    return True
                
        except Exception as e:
            logger.error(f"사용자 입력 처리 중 오류 발생: {e}")
            return False

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed = urlparse(url)
            return bool(parsed.netloc)
        except:
            return False

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    async def _get_valid_input(self, prompt: str, valid_values: List[str] = None, validator = None) -> Optional[str]:
        """Get and validate user input with improved error handling"""
        while True:
            try:
                value = input(prompt).strip()
                
                if valid_values and value not in valid_values:
                    self.console.print(f"[bold red]잘못된 입력입니다. 유효한 값: {', '.join(valid_values)}[/bold red]")
                    continue
                    
                if validator and not await validator(value):
                    continue
                    
                return value
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]스캔이 취소되었습니다.[/yellow]")
                return None
            except Exception as e:
                logger.error(f"입력 처리 중 오류 발생: {e}")
                return None

    async def _validate_url(self, url: str) -> bool:
        """Validate URL format with improved checks"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            if not parsed.netloc:
                self.console.print("[bold red]올바른 URL 형식이 아닙니다.[/bold red]")
                return False
            
            domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
            if not re.match(domain_pattern, parsed.netloc):
                self.console.print("[bold red]올바른 도메인 형식이 아닙니다.[/bold red]")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"URL 검증 실패: {e}")
            return False

    async def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format with improved checks"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private:
                self.console.print("[yellow]경고: 프라이빗 IP 주소입니다.[/yellow]")
            elif ip_obj.is_loopback:
                self.console.print("[yellow]경고: 로컬호스트 주소입니다.[/yellow]")
            
            return True
            
        except ValueError:
            self.console.print("[bold red]올바른 IP 주소 형식이 아닙니다.[/bold red]")
            return False
        except Exception as e:
            logger.error(f"IP 검증 실패: {e}")
            return False

    async def _select_individual_modules(self) -> bool:
        """개별 모듈 선택 메뉴를 표시합니다."""
        try:
            while True:
                # 모듈 선택 메뉴 표시
                self.console.print("\n[bold blue]실행할 모듈을 선택하세요:[/bold blue]")
                
                # 모듈 목록을 2열로 표시
                table = Table(show_header=False, box=None)
                table.add_column("모듈", style="cyan", width=40)
                table.add_column("상태", style="green", width=10)
                table.add_column("모듈", style="cyan", width=40)
                table.add_column("상태", style="green", width=10)
                
                # 모듈 목록을 2열로 구성
                modules_list = list(MODULES.items())
                half = (len(modules_list) + 1) // 2
                
                for i in range(half):
                    row = []
                    # 첫 번째 열
                    module_id1, module_info1 = modules_list[i]
                    status1 = "[green]✓[/green]" if module_id1 in self.selected_modules else "[red]✗[/red]"
                    row.extend([f"{i+1}. {module_info1['name']}", status1])
                    
                    # 두 번째 열 (있는 경우)
                    if i + half < len(modules_list):
                        module_id2, module_info2 = modules_list[i + half]
                        status2 = "[green]✓[/green]" if module_id2 in self.selected_modules else "[red]✗[/red]"
                        row.extend([f"{i+half+1}. {module_info2['name']}", status2])
                    else:
                        row.extend(["", ""])
                    
                    table.add_row(*row)
                
                self.console.print(table)
                
                # 기능 버튼 표시
                self.console.print("\n[bold blue]기능 선택:[/bold blue]")
                self.console.print("1. 선택 완료")
                self.console.print("2. 모듈 순서 설정")
                self.console.print("3. 개별 모듈 실행")
                self.console.print("4. 취소")
                
                choice = await self._get_valid_input(
                    "선택: ",
                    [str(i) for i in range(1, 5)]
                )
                
                if choice == "4":  # 취소
                    return False
                elif choice == "3":  # 개별 모듈 실행
                    if not await self._run_single_module():
                        continue
                elif choice == "2":  # 모듈 순서 설정
                    if not await self._set_module_order():
                        continue
                elif choice == "1":  # 선택 완료
                    if not self.selected_modules:
                        self.console.print("[bold red]하나 이상의 모듈을 선택해야 합니다.[/bold red]")
                        continue
                    return True
                else:
                    module_id = list(MODULES.keys())[int(choice) - 1]
                    if module_id in self.selected_modules:
                        self.selected_modules.remove(module_id)
                        self.console.print(f"[yellow]{MODULES[module_id]['name']} 모듈 선택이 취소되었습니다.[/yellow]")
                    else:
                        if MODULES[module_id]['requires_url'] and not self.is_url:
                            self.console.print(f"[bold red]{MODULES[module_id]['name']} 모듈은 URL 대상에만 사용할 수 있습니다.[/bold red]")
                            continue
                        self.selected_modules.append(module_id)
                        self.console.print(f"[green]{MODULES[module_id]['name']} 모듈이 선택되었습니다.[/green]")
                        
        except Exception as e:
            logger.error(f"개별 모듈 선택 중 오류 발생: {e}")
            return False

    async def _run_single_module(self) -> bool:
        """개별 모듈을 실행합니다."""
        try:
            self.console.print("\n[bold blue]실행할 모듈을 선택하세요:[/bold blue]")
            
            # 모듈 목록 표시
            for i, (module_id, module_info) in enumerate(MODULES.items(), 1):
                self.console.print(f"{i}. {module_info['name']} - {module_info['description']}")
            
            self.console.print(f"{len(MODULES) + 1}. 취소")
            
            choice = await self._get_valid_input(
                "선택: ",
                [str(i) for i in range(1, len(MODULES) + 2)]
            )
            
            if choice == str(len(MODULES) + 1):  # 취소
                return True
            
            module_id = list(MODULES.keys())[int(choice) - 1]
            module_info = MODULES[module_id]
            
            if module_info['requires_url'] and not self.is_url:
                self.console.print(f"[bold red]{module_info['name']} 모듈은 URL 대상에만 사용할 수 있습니다.[/bold red]")
                return False
            
            # 의존성 모듈 체크
            for dep in module_info['dependencies']:
                if dep not in self.selected_modules:
                    self.console.print(f"[yellow]의존성 모듈 {MODULES[dep]['name']}이(가) 필요합니다.[/yellow]")
                    return False
            
            # 개별 모듈 실행
            target = self.target_url if self.is_url else self.target_ip
            self.console.print(Panel(
                f"[bold blue]모듈 실행: {module_info['name']}[/bold blue]\n"
                f"대상: {target}\n"
                f"설명: {module_info['description']}",
                title="P-ALL Scanner"
            ))
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                task_id = progress.add_task(
                    f"[cyan]{module_info['name']} 실행 중...[/cyan]", 
                    total=100
                )
                
                try:
                    # 모듈별 실행 함수 호출
                    if module_id == 'port':
                        await self._scan_ports(target, progress, task_id)
                    elif module_id == 'web' and self.is_url:
                        await self._scan_web(target, progress, task_id)
                    elif module_id == 'ssh' and not self.is_url:
                        await self._scan_ssh(target, progress, task_id)
                    elif module_id == 'nmap':
                        await self._scan_nmap(target, progress, task_id)
                    elif module_id == 'js' and self.is_url:
                        await self._scan_js(target, progress, task_id)
                except Exception as e:
                    # 에러 발생 시 자동 수정 시도
                    error_handler = ErrorHandler()
                    correction = error_handler.handle_error(e)
                    
                    if correction:
                        self.console.print(f"[yellow]에러 발생: {str(e)}[/yellow]")
                        self.console.print(f"[green]자동 수정 시도: {correction}[/green]")
                        
                        # 수정 후 재시도
                        progress.update(task_id, description="[cyan]수정 후 재시도 중...[/cyan]")
                        if module_id == 'port':
                            await self._scan_ports(target, progress, task_id)
                        elif module_id == 'web' and self.is_url:
                            await self._scan_web(target, progress, task_id)
                        elif module_id == 'ssh' and not self.is_url:
                            await self._scan_ssh(target, progress, task_id)
                        elif module_id == 'nmap':
                            await self._scan_nmap(target, progress, task_id)
                        elif module_id == 'js' and self.is_url:
                            await self._scan_js(target, progress, task_id)
                    else:
                        progress.update(task_id, completed=100, description="[red]실행 실패[/red]")
                        self.console.print(f"[bold red]에러 발생: {str(e)}[/bold red]")
                        self.console.print("[yellow]자동 수정이 불가능한 에러입니다. 수동으로 확인해주세요.[/yellow]")
                        return False
            
            # 결과 표시
            self.console.print("\n[bold green]모듈 실행 완료[/bold green]")
            if module_id in self.results:
                self.console.print(Panel(
                    str(self.results[module_id]),
                    title=f"{module_info['name']} 결과"
                ))
            
            # 추가 실행 여부 확인
            self.console.print("\n[bold blue]추가 작업 선택:[/bold blue]")
            self.console.print("1. 다른 모듈 실행")
            self.console.print("2. 메인 메뉴로 돌아가기")
            
            choice = await self._get_valid_input(
                "선택: ",
                ['1', '2']
            )
            
            if choice == '1':
                return await self._run_single_module()
            else:
                return True
            
        except Exception as e:
            logger.error(f"개별 모듈 실행 중 오류 발생: {e}")
            self.console.print(f"[bold red]오류 발생: {e}[/bold red]")
            return False

    async def _set_module_order(self) -> bool:
        """선택된 모듈의 실행 순서를 설정합니다."""
        try:
            if not self.selected_modules:
                self.console.print("[bold red]먼저 모듈을 선택해야 합니다.[/bold red]")
                return False

            self.console.print("\n[bold blue]모듈 실행 순서 설정[/bold blue]")
            self.console.print("각 모듈에 대해 실행 순서를 입력하세요 (1부터 시작)")
            
            # 의존성 체크 및 기본 순서 설정
            self.module_order = {}
            for module_id in self.selected_modules:
                module_info = MODULES[module_id]
                # 의존성 모듈이 선택되지 않은 경우 추가
                for dep in module_info['dependencies']:
                    if dep not in self.selected_modules:
                        self.selected_modules.append(dep)
                        self.console.print(f"[yellow]의존성 모듈 {MODULES[dep]['name']}이(가) 자동으로 추가되었습니다.[/yellow]")
                
                # 기본 순서 설정
                self.module_order[module_id] = module_info['default_order']

            # 순서 입력 받기
            for module_id in self.selected_modules:
                while True:
                    try:
                        order = int(await self._get_valid_input(
                            f"{MODULES[module_id]['name']}의 실행 순서 (현재: {self.module_order[module_id]}): ",
                            [str(i) for i in range(1, len(self.selected_modules) + 1)]
                        ))
                        self.module_order[module_id] = order
                        break
                    except ValueError:
                        self.console.print("[bold red]잘못된 입력입니다. 숫자를 입력하세요.[/bold red]")

            # 순서대로 정렬
            self.selected_modules.sort(key=lambda x: self.module_order[x])
            
            # 순서 확인
            self.console.print("\n[bold blue]설정된 모듈 실행 순서:[/bold blue]")
            for i, module_id in enumerate(self.selected_modules, 1):
                self.console.print(f"{i}. {MODULES[module_id]['name']}")
            
            return True
            
        except Exception as e:
            logger.error(f"모듈 순서 설정 중 오류 발생: {e}")
            return False

    async def scan(self, scan_type: str = "all") -> Dict:
        """선택된 모듈에 따라 스캔을 수행합니다."""
        try:
            target = self.target_url if self.is_url else self.target_ip
            self.scan_start_time = datetime.now()
            
            self.console.print(Panel(
                f"[bold blue]스캔 시작: {target}[/bold blue]\n"
                f"시작 시간: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"실행 순서:\n" + "\n".join([
                    f"{i+1}. {MODULES[m]['name']}" 
                    for i, m in enumerate(self.selected_modules)
                ]),
                title="P-ALL Scanner"
            ))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # 선택된 모듈을 순서대로 실행
                for module_id in self.selected_modules:
                    task_id = progress.add_task(
                        f"[cyan]{MODULES[module_id]['name']} 실행 중...[/cyan]", 
                        total=100
                    )
                    
                    if module_id == 'port':
                        await self._scan_ports(target, progress, task_id)
                    elif module_id == 'web' and self.is_url:
                        await self._scan_web(target, progress, task_id)
                    elif module_id == 'ssh' and not self.is_url:
                        await self._scan_ssh(target, progress, task_id)
                    elif module_id == 'nmap':
                        await self._scan_nmap(target, progress, task_id)
                    elif module_id == 'js' and self.is_url:
                        await self._scan_js(target, progress, task_id)

            self.scan_end_time = datetime.now()
            return {
                'status': 'success',
                'results': self.results,
                'vulnerabilities': self.vulnerabilities,
                'scan_duration': (self.scan_end_time - self.scan_start_time).total_seconds(),
                'modules': self.selected_modules,
                'module_order': self.module_order
            }
            
        except Exception as e:
            logger.error(f"스캔 실패: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def _scan_ports(self, target: str, progress: Progress, task_id: int) -> None:
        """포트 스캔을 수행합니다."""
        try:
            scanner = PortScanner(target)
            results = await scanner.scan()
            self.results['ports'] = results
            if 'vulnerabilities' in results:
                self.vulnerabilities.extend(results['vulnerabilities'])
            progress.update(task_id, completed=100)
        except Exception as e:
            error_handler = ErrorHandler()
            correction = error_handler.handle_error(e)
            if correction:
                self.console.print(f"[yellow]에러 발생: {str(e)}[/yellow]")
                self.console.print(f"[green]자동 수정 시도: {correction}[/green]")
                # 수정 후 재시도
                scanner = PortScanner(target)
                results = await scanner.scan()
                self.results['ports'] = results
                if 'vulnerabilities' in results:
                    self.vulnerabilities.extend(results['vulnerabilities'])
                progress.update(task_id, completed=100)
            else:
                raise e

    async def _scan_web(self, target: str, progress: Progress, task_id: int) -> None:
        """웹 취약점 스캔을 수행합니다."""
        try:
            progress.update(task_id, completed=0, description="[cyan]XSS 취약점 스캔 중...[/cyan]")
            xss_scanner = XSSScanner(target)
            xss_results = await xss_scanner.scan()
            self.results['xss'] = xss_results
            if 'vulnerabilities' in xss_results:
                self.vulnerabilities.extend(xss_results['vulnerabilities'])
            progress.update(task_id, completed=50)

            progress.update(task_id, description="[cyan]SQL Injection 취약점 스캔 중...[/cyan]")
            sql_scanner = SQLInjectionScanner(target)
            sql_results = await sql_scanner.scan()
            self.results['sql_injection'] = sql_results
            if 'vulnerabilities' in sql_results:
                self.vulnerabilities.extend(sql_results['vulnerabilities'])
            progress.update(task_id, completed=100)
            
        except Exception as e:
            error_handler = ErrorHandler()
            correction = error_handler.handle_error(e)
            if correction:
                self.console.print(f"[yellow]에러 발생: {str(e)}[/yellow]")
                self.console.print(f"[green]자동 수정 시도: {correction}[/green]")
                # 수정 후 재시도
                scanner = SQLInjectionScanner(target)
                results = await scanner.scan()
                self.results['sql_injection'] = results
                if 'vulnerabilities' in results:
                    self.vulnerabilities.extend(results['vulnerabilities'])
                progress.update(task_id, completed=100)
            else:
                raise e

    async def _scan_ssh(self, target: str, progress: Progress, task_id: int) -> None:
        """Perform SSH security scanning with progress updates"""
        try:
            scanner = SSHScanner(target)
            results = await scanner.scan()
            self.results['ssh'] = results
            if 'vulnerabilities' in results:
                self.vulnerabilities.extend(results['vulnerabilities'])
            progress.update(task_id, completed=100)
        except Exception as e:
            error_handler = ErrorHandler()
            correction = error_handler.handle_error(e)
            if correction:
                self.console.print(f"[yellow]에러 발생: {str(e)}[/yellow]")
                self.console.print(f"[green]자동 수정 시도: {correction}[/green]")
                # 수정 후 재시도
                scanner = SSHScanner(target)
                results = await scanner.scan()
                self.results['ssh'] = results
                if 'vulnerabilities' in results:
                    self.vulnerabilities.extend(results['vulnerabilities'])
                progress.update(task_id, completed=100)
            else:
                raise e

    async def _scan_nmap(self, target: str, progress: Progress, task_id: int) -> None:
        """Perform Nmap scanning with progress updates"""
        try:
            scanner = NmapScanner(target)
            results = await scanner.scan()
            self.results['nmap'] = results
            if 'vulnerabilities' in results:
                self.vulnerabilities.extend(results['vulnerabilities'])
            progress.update(task_id, completed=100)
        except Exception as e:
            error_handler = ErrorHandler()
            correction = error_handler.handle_error(e)
            if correction:
                self.console.print(f"[yellow]에러 발생: {str(e)}[/yellow]")
                self.console.print(f"[green]자동 수정 시도: {correction}[/green]")
                # 수정 후 재시도
                scanner = NmapScanner(target)
                results = await scanner.scan()
                self.results['nmap'] = results
                if 'vulnerabilities' in results:
                    self.vulnerabilities.extend(results['vulnerabilities'])
                progress.update(task_id, completed=100)
            else:
                raise e

    async def _scan_js(self, target: str, progress: Progress, task_id: int) -> None:
        """Perform JavaScript analysis with progress updates"""
        try:
            analyzer = JSAnalyzer(target)
            results = await analyzer.analyze()
            self.results['javascript'] = results
            if 'vulnerabilities' in results:
                self.vulnerabilities.extend(results['vulnerabilities'])
            progress.update(task_id, completed=100)
        except Exception as e:
            error_handler = ErrorHandler()
            correction = error_handler.handle_error(e)
            if correction:
                self.console.print(f"[yellow]에러 발생: {str(e)}[/yellow]")
                self.console.print(f"[green]자동 수정 시도: {correction}[/green]")
                # 수정 후 재시도
                analyzer = JSAnalyzer(target)
                results = await analyzer.analyze()
                self.results['javascript'] = results
                if 'vulnerabilities' in results:
                    self.vulnerabilities.extend(results['vulnerabilities'])
                progress.update(task_id, completed=100)
            else:
                raise e

    def generate_report(self) -> None:
        """보고서 생성 시 모듈 실행 순서 정보를 포함합니다."""
        if not self.scan_end_time:
            return
            
        # 스캔 요약 정보
        self.console.print(Panel(
            f"[bold blue]스캔 요약[/bold blue]\n"
            f"대상: {self.target_url if self.is_url else self.target_ip}\n"
            f"실행 순서:\n" + "\n".join([
                f"{i+1}. {MODULES[m]['name']}" 
                for i, m in enumerate(self.selected_modules)
            ]) + "\n"
            f"시작 시간: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"종료 시간: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"소요 시간: {(self.scan_end_time - self.scan_start_time).total_seconds():.2f}초",
            title="P-ALL Scanner Report"
        ))

        # 모듈별 실행 결과
        table = Table(title="모듈별 실행 결과")
        table.add_column("모듈", style="cyan")
        table.add_column("상태", style="green")
        table.add_column("취약점 수", style="red")
        table.add_column("상세 정보", style="yellow")

        for module, results in self.results.items():
            vuln_count = len([v for v in self.vulnerabilities if v.get('type', '').startswith(module)])
            status = "✓ 완료" if results.get('status') == 'success' else "✗ 실패"
            details = results.get('details', '-')
            table.add_row(module, status, str(vuln_count), str(details))

        self.console.print(table)

        # 취약점 상세 정보
        if self.vulnerabilities:
            self.console.print("\n[bold red]발견된 취약점:[/bold red]")
            for vuln in self.vulnerabilities:
                self.console.print(Panel(
                    f"[bold red]{vuln['type']}[/bold red]\n"
                    f"심각도: {vuln['severity']}\n"
                    f"설명: {vuln['description']}\n"
                    f"권장 조치: {vuln['recommendation']}",
                    title=f"취약점 상세 - {vuln.get('id', 'N/A')}",
                    border_style="red"
                ))

        # 보고서 저장
        report_path = Path('reports') / f'p-all_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        Path('reports').mkdir(exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# P-ALL 보안 스캔 보고서\n\n")
            f.write(f"## 스캔 정보\n")
            f.write(f"- 대상: {self.target_url if self.is_url else self.target_ip}\n")
            f.write(f"- 실행 순서:\n" + "\n".join([
                f"{i+1}. {MODULES[m]['name']}" 
                for i, m in enumerate(self.selected_modules)
            ]) + "\n")
            f.write(f"- 시작 시간: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- 종료 시간: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- 소요 시간: {(self.scan_end_time - self.scan_start_time).total_seconds():.2f}초\n\n")
            
            # 나머지 보고서 내용 작성...

        self.console.print(f"\n[green]보고서가 저장되었습니다: {report_path}[/green]")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='P-ALL: 통합 보안 스캐너')
    parser.add_argument('--target', help='스캔 대상 (URL 또는 IP)')
    parser.add_argument('--module', choices=['all', 'port', 'web', 'ssh', 'nmap', 'js'], 
                      default='all', help='실행할 모듈')
    parser.add_argument('--output', choices=['html', 'pdf', 'json'], 
                      default='html', help='보고서 출력 형식')
    parser.add_argument('--timeout', type=int, default=30, 
                      help='스캔 타임아웃 (초)')
    parser.add_argument('--threads', type=int, default=5, 
                      help='동시 스캔 스레드 수')
    return parser.parse_args()

async def main():
    """Main function with improved error handling"""
    try:
        args = parse_args()
        console.print(BANNER)
        
        # Initialize scanner
        scanner = PAllScanner(args)
        
        # Get target input
        if not await scanner.get_user_input():
            console.print("[yellow]프로그램을 종료합니다.[/yellow]")
            return
        
        # Perform scan
        results = await scanner.scan()
        
        if results['status'] == 'success':
            # Generate report
            scanner.generate_report()
        else:
            console.print(f"[bold red]스캔 실패: {results.get('error', '알 수 없는 오류')}[/bold red]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]사용자에 의해 프로그램이 중단되었습니다.[/yellow]")
    except Exception as e:
        logger.error(f"프로그램 실행 중 오류 발생: {e}")
        console.print(f"[bold red]오류 발생: {e}[/bold red]")
    finally:
        console.print("[bold blue]프로그램을 종료합니다.[/bold blue]")

if __name__ == "__main__":
    asyncio.run(main()) 