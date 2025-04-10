"""
Advanced Nmap Scanner Module
This module provides comprehensive network scanning, service detection, and vulnerability assessment capabilities.
"""

import asyncio
import nmap
import nmap3
from typing import Dict, List, Optional, Tuple, Union, Any
import logging
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.style import Style
from rich.box import ROUNDED, DOUBLE, HEAVY
import os
import requests
import stem
from stem.control import Controller
from stem import Signal
import socks
import socket
import time
import json
from datetime import datetime, timedelta
import re
import webbrowser
import subprocess
import shutil
from pathlib import Path
import concurrent.futures
import base64
import random
import string
import ipaddress
import threading
import queue
import signal
import sys
import tempfile
import hashlib
import ssl
import OpenSSL
import paramiko
import ftplib
import pymysql
import smb.SMBConnection
import rdp
import telnetlib
import dns.resolver
import whois
import geoip2.database
from scapy.all import *
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.align import Align
from rich.console import Group
from rich.syntax import Syntax
from rich.tree import Tree
from rich import print as rprint
import aiohttp
import async_timeout
import aioredis
import motor.motor_asyncio
from bson import ObjectId
import yaml
import toml
import xml.etree.ElementTree as ET
import csv
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
import torch
import torch.nn as nn
import torch.optim as optim
from transformers import AutoTokenizer, AutoModel
import spacy
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import gensim
from gensim.models import Word2Vec
import networkx as nx
import community
import igraph
import plotly.graph_objects as go
import plotly.express as px
import dash
from dash import dcc, html
import streamlit as st
import gradio as gr
import fastapi
from fastapi import FastAPI, HTTPException
import uvicorn
import pydantic
from pydantic import BaseModel, Field
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import alembic
from alembic import command
import pytest
import hypothesis
from hypothesis import given, strategies as st
import mypy
import black
import isort
import flake8
import pylint
import bandit
import safety
import snyk
import sonarqube
import zap
import burp
import metasploit
import sqlmap
import nikto
import wpscan
import joomscan
import droopescan
import w3af
import arachni
import skipfish
import wapiti
import dirb
import gobuster
import ffuf
import amass
import subfinder
import assetfinder
import findomain
import massdns
import masscan
import rustscan
import naabu
import httpx
import nuclei
import gau
import waybackurls
import meg
import sublist3r
import theharvester
import recon_ng
import maltego
import spiderfoot
import osintframework
import sherlock
import social_analyzer
import twint
import instagram_scraper
import facebook_scraper
import linkedin_scraper
import twitter_scraper
import youtube_dl
import tiktok_scraper
import reddit_scraper
import pinterest_scraper
import tumblr_scraper
import flickr_scraper
import vk_scraper
import weibo_scraper
import douyin_scraper
import bilibili_scraper

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nmap_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
console = Console()

class AdvancedNmapScanner:
    def __init__(self, target: str):
        """
        Initialize the advanced Nmap scanner
        
        Args:
            target: Target IP address or hostname
        """
        self.target = target
        self.target_ip = self._resolve_target(target)
        self.nm = nmap.PortScanner()
        self.nmap3 = nmap3.Nmap()
        self.open_ports: List[int] = []
        self.vulnerabilities: List[Dict] = []
        self.scan_results: Dict = {}
        self.payloads: Dict = {}
        self.credentials: Dict = {}
        self.banner_grab_results: Dict = {}
        self.ssl_info: Dict = {}
        self.geo_info: Dict = {}
        self.whois_info: Dict = {}
        self.scan_history: List[Dict] = []
        self.network_graph = nx.Graph()
        self.ml_model = None
        self.redis_client = None
        self.mongo_client = None
        self.sql_engine = None
        self.scan_options = {
            '1': {'name': '기본 스캔', 'description': '일반적인 포트 스캔 (1-1024)', 'timeout': 300},
            '2': {'name': '전체 포트 스캔', 'description': '모든 포트 스캔 (1-65535)', 'timeout': 1800},
            '3': {'name': '빠른 스캔', 'description': '일반적인 서비스 포트만 스캔', 'timeout': 60},
            '4': {'name': '서비스 감지', 'description': '포트 스캔 및 서비스 버전 감지', 'timeout': 600},
            '5': {'name': 'OS 감지', 'description': '포트 스캔 및 운영체제 감지', 'timeout': 900},
            '6': {'name': '취약점 스캔', 'description': '포트 스캔 및 취약점 검사', 'timeout': 1200},
            '7': {'name': '페이로드 생성', 'description': '발견된 서비스에 대한 페이로드 생성', 'timeout': 300},
            '8': {'name': '배너 그랩', 'description': '서비스 배너 정보 수집', 'timeout': 300},
            '9': {'name': 'SSL/TLS 분석', 'description': 'SSL/TLS 설정 및 취약점 분석', 'timeout': 300},
            '10': {'name': '지리적 정보', 'description': 'IP 지리적 위치 정보', 'timeout': 60},
            '11': {'name': 'WHOIS 조회', 'description': '도메인 WHOIS 정보 조회', 'timeout': 60},
            '12': {'name': '스캔 기록', 'description': '이전 스캔 결과 보기', 'timeout': 60},
            '13': {'name': '네트워크 분석', 'description': '네트워크 토폴로지 분석', 'timeout': 300},
            '14': {'name': '머신러닝 분석', 'description': '스캔 결과 머신러닝 분석', 'timeout': 600},
            '15': {'name': '실시간 모니터링', 'description': '포트 변경 실시간 모니터링', 'timeout': 0},
            '16': {'name': '분산 스캔', 'description': '분산 포트 스캔 실행', 'timeout': 1800},
            '17': {'name': 'API 엔드포인트', 'description': 'REST API 서버 시작', 'timeout': 0},
            '18': {'name': '웹 인터페이스', 'description': '웹 기반 인터페이스 시작', 'timeout': 0},
            '19': {'name': 'TOR 스캔', 'description': 'TOR 네트워크를 통한 스캔', 'timeout': 1800},
            '20': {'name': '취약점 데이터베이스', 'description': 'NVD 및 Exploit-DB 연동', 'timeout': 300},
            '0': {'name': '종료', 'description': '프로그램 종료', 'timeout': 0}
        }
        
        # 초기화
        self._initialize_scanner()
        self._load_credentials()
        self._setup_geoip()
        self._setup_databases()
        self._setup_ml_model()
        self._setup_tor()
        self._setup_vuln_db()
        
    def _initialize_scanner(self) -> None:
        """
        Initialize scanner settings and configurations
        """
        # Nmap 설정
        self.nm.scaninfo = {
            'tcp': {'method': 'syn', 'services': '1-65535'},
            'udp': {'method': 'udp', 'services': '1-65535'}
        }
        
        # 스캔 제한 설정
        self.max_threads = 100
        self.timeout = 5
        self.retries = 3
        
        # 결과 저장 디렉토리 생성
        self.results_dir = Path('scan_results')
        self.results_dir.mkdir(exist_ok=True)
        
        # 암호화 키 생성
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # 웹 인터페이스 설정
        self.web_app = FastAPI(title="P-ALL Nmap Scanner API")
        self._setup_api_routes()
        
    def _setup_tor(self) -> None:
        """
        Setup TOR configuration
        """
        self.tor_controller = None
        self.tor_socks_port = 9050
        self.tor_control_port = 9051
        
        try:
            from stem.control import Controller
            from stem import Signal
            
            self.tor_controller = Controller.from_port(port=self.tor_control_port)
            self.tor_controller.authenticate()
            
            # TOR SOCKS 프록시 설정
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_socks_port)
            socket.socket = socks.socksocket
            
            console.print(Panel(
                "[bold green]TOR 연결 성공[/bold green]",
                border_style="bright_green",
                box=ROUNDED
            ))
        except Exception as e:
            logger.error(f"TOR setup failed: {e}")
            console.print(Panel(
                f"[bold red]TOR 설정 중 오류가 발생했습니다: {e}[/bold red]",
                border_style="bright_red",
                box=ROUNDED
            ))
            
    def _setup_vuln_db(self) -> None:
        """
        Setup vulnerability database connections
        """
        self.nvd_api_key = None
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.exploit_db_path = Path('exploit_db')
        
        # Exploit-DB 로컬 미러 설정
        if not self.exploit_db_path.exists():
            self.exploit_db_path.mkdir()
            subprocess.run(['git', 'clone', 'https://github.com/offensive-security/exploitdb.git', str(self.exploit_db_path)])
            
    async def register_nvd_api_key(self) -> None:
        """
        Register NVD API key
        """
        try:
            console.print(Panel(
                "[bold blue]NVD API 키 등록[/bold blue]",
                border_style="bright_blue",
                box=ROUNDED
            ))
            
            # NVD API 키 등록 페이지 열기
            webbrowser.open("https://nvd.nist.gov/developers/request-an-api-key")
            
            # 사용자로부터 API 키 입력 받기
            api_key = Prompt.ask("NVD API 키를 입력하세요")
            
            if api_key:
                self.nvd_api_key = api_key
                console.print(Panel(
                    "[bold green]NVD API 키가 성공적으로 등록되었습니다.[/bold green]",
                    border_style="bright_green",
                    box=ROUNDED
                ))
            else:
                raise ValueError("API 키가 입력되지 않았습니다.")
                
        except Exception as e:
            logger.error(f"NVD API key registration failed: {e}")
            console.print(Panel(
                f"[bold red]NVD API 키 등록 중 오류가 발생했습니다: {e}[/bold red]",
                border_style="bright_red",
                box=ROUNDED
            ))
            
    async def search_nvd(self, query: str) -> List[Dict]:
        """
        Search NVD for vulnerabilities
        """
        try:
            if not self.nvd_api_key:
                await self.register_nvd_api_key()
                
            headers = {
                'apiKey': self.nvd_api_key,
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.nvd_base_url}?keyword={query}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('result', {}).get('CVE_Items', [])
                    else:
                        raise ValueError(f"NVD API request failed: {response.status}")
                        
        except Exception as e:
            logger.error(f"NVD search failed: {e}")
            return []
            
    async def search_exploit_db(self, query: str) -> List[Dict]:
        """
        Search Exploit-DB for exploits
        """
        try:
            # 로컬 Exploit-DB 검색
            if self.exploit_db_path.exists():
                result = subprocess.run(
                    ['searchsploit', query],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    exploits = []
                    for line in result.stdout.split('\n'):
                        if '|' in line:
                            parts = line.split('|')
                            if len(parts) >= 3:
                                exploits.append({
                                    'id': parts[0].strip(),
                                    'title': parts[1].strip(),
                                    'path': parts[2].strip()
                                })
                    return exploits
                    
            # 온라인 Exploit-DB 검색
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.exploit-db.com/search?q={query}"
                ) as response:
                    if response.status == 200:
                        # HTML 파싱 및 결과 추출
                        # (실제 구현에서는 BeautifulSoup 등을 사용)
                        return []
                    else:
                        raise ValueError(f"Exploit-DB search failed: {response.status}")
                        
        except Exception as e:
            logger.error(f"Exploit-DB search failed: {e}")
            return []
            
    async def get_exploit_code(self, exploit_id: str) -> str:
        """
        Get exploit code from Exploit-DB
        """
        try:
            # 로컬 Exploit-DB에서 코드 가져오기
            if self.exploit_db_path.exists():
                exploit_path = self.exploit_db_path / 'exploits' / exploit_id
                if exploit_path.exists():
                    with open(exploit_path, 'r') as f:
                        return f.read()
                        
            # 온라인 Exploit-DB에서 코드 가져오기
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.exploit-db.com/download/{exploit_id}"
                ) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        raise ValueError(f"Exploit code download failed: {response.status}")
                        
        except Exception as e:
            logger.error(f"Exploit code retrieval failed: {e}")
            return ""
            
    async def renew_tor_identity(self) -> None:
        """
        Renew TOR circuit for new identity
        """
        try:
            if self.tor_controller:
                self.tor_controller.signal(Signal.NEWNYM)
                console.print(Panel(
                    "[bold green]TOR 신원이 갱신되었습니다.[/bold green]",
                    border_style="bright_green",
                    box=ROUNDED
                ))
            else:
                raise ValueError("TOR controller not initialized")
                
        except Exception as e:
            logger.error(f"TOR identity renewal failed: {e}")
            console.print(Panel(
                f"[bold red]TOR 신원 갱신 중 오류가 발생했습니다: {e}[/bold red]",
                border_style="bright_red",
                box=ROUNDED
            ))
            
    async def scan_with_tor(self, ports: str, scan_type: str) -> None:
        """
        Perform scan through TOR network
        """
        try:
            if not self.tor_controller:
                raise ValueError("TOR not initialized")
                
            # TOR를 통한 스캔
            arguments = f"-p {ports} --proxies socks4://127.0.0.1:{self.tor_socks_port}"
            self.nm.scan(self.target_ip, arguments=arguments)
            
            # 결과 처리
            self._process_scan_results(scan_type)
            
            console.print(Panel(
                "[bold green]TOR 스캔 완료[/bold green]",
                border_style="bright_green",
                box=ROUNDED
            ))
            
        except Exception as e:
            logger.error(f"TOR scan failed: {e}")
            console.print(Panel(
                f"[bold red]TOR 스캔 중 오류가 발생했습니다: {e}[/bold red]",
                border_style="bright_red",
                box=ROUNDED
            ))

    # ... (나머지 메서드들은 이전과 동일하게 유지)

    def _create_banner(self) -> Panel:
        """
        Create a fancy banner for the scanner
        """
        banner = """
███╗   ██╗███╗   ███╗ █████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
████╗  ██║████╗ ████║██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██╔██╗ ██║██╔████╔██║███████║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║ ╚████║██║ ╚═╝ ██║██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""
        return Panel(
            banner,
            title="[bold red]P-ALL Security Scanner[/bold red]",
            border_style="bright_blue",
            box=DOUBLE
        )

    def _create_status_table(self) -> Table:
        """
        Create a status table for scan information
        """
        table = Table(
            title="[bold yellow]스캔 상태[/bold yellow]",
            box=ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("항목", style="cyan")
        table.add_column("값", style="green")
        return table

    def _create_vulnerability_table(self) -> Table:
        """
        Create a table for vulnerability information
        """
        table = Table(
            title="[bold red]취약점 정보[/bold red]",
            box=ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("CVE ID", style="cyan")
        table.add_column("심각도", style="red")
        table.add_column("설명", style="green", width=50)
        table.add_column("발견일", style="yellow")
        return table

    async def analyze_vulnerabilities(self) -> None:
        """
        Analyze vulnerabilities with enhanced display
        """
        try:
            if not self.scan_results:
                console.print(Panel(
                    "[bold red]분석할 스캔 결과가 없습니다.[/bold red]",
                    border_style="bright_red",
                    box=ROUNDED
                ))
                return

            layout = Layout()
            layout.split_column(
                Layout(name="header"),
                Layout(name="body")
            )
            
            layout["header"].update(Panel(
                "[bold blue]NVD 취약점 분석[/bold blue]",
                border_style="bright_blue",
                box=ROUNDED
            ))

            for host, data in self.scan_results.items():
                for port_info in data.get('ports', []):
                    if port_info['state'] == 'open':
                        query = f"{port_info['service']} {port_info.get('version', '')}"
                        vulnerabilities = await self.search_nvd(query)
                        
                        if vulnerabilities:
                            table = self._create_vulnerability_table()
                            
                            for vuln in vulnerabilities:
                                severity_color = {
                                    'CRITICAL': 'bright_red',
                                    'HIGH': 'red',
                                    'MEDIUM': 'yellow',
                                    'LOW': 'green'
                                }.get(vuln['severity'], 'white')
                                
                                table.add_row(
                                    vuln['id'],
                                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                                    vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description'],
                                    vuln['published']
                                )
                            
                            layout["body"].update(table)
                            console.print(layout)
                            
                            # Display attack code for high severity vulnerabilities
                            for vuln in vulnerabilities:
                                if vuln['severity'] in ['HIGH', 'CRITICAL']:
                                    attack_code = await self.generate_attack_code(vuln['id'])
                                    if attack_code:
                                        console.print(Panel.fit(
                                            f"[bold red]Exploit Code for {vuln['id']}[/bold red]\n" +
                                            f"Python:\n{attack_code['python']}\n" +
                                            f"Bash:\n{attack_code['bash']}",
                                            title="Attack Code",
                                            border_style="bright_red",
                                            box=ROUNDED
                                        ))
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            console.print(Panel(
                f"[bold red]취약점 분석 중 오류가 발생했습니다: {e}[/bold red]",
                border_style="bright_red",
                box=ROUNDED
            ))

    async def handle_choice(self, choice: str) -> None:
        """
        Handle user's menu choice
        """
        try:
            if choice == '1':
                await self.scan(scan_type="default", use_tor=False)
            elif choice == '2':
                await self.scan(scan_type="aggressive", use_tor=False)
            elif choice == '3':
                await self.scan(scan_type="vulnerability", use_tor=False)
            elif choice == '4':
                await self.scan(scan_type="default", use_tor=True)
            elif choice == '5':
                await self.scan(scan_type="aggressive", use_tor=True)
            elif choice == '6':
                await self.scan(scan_type="vulnerability", use_tor=True)
            elif choice == '7':
                await self.renew_tor_identity()
            elif choice == '8':
                await self.analyze_vulnerabilities()
            else:
                console.print("[bold red]잘못된 선택입니다.[/bold red]")
        except Exception as e:
            logger.error(f"Error handling choice: {e}")
            console.print(f"[bold red]오류가 발생했습니다: {e}[/bold red]")

    async def initialize_tor(self) -> bool:
        """
        Initialize TOR connection
        """
        try:
            # Check if TOR is running
            if not self._is_tor_running():
                console.print("[bold red]TOR 서비스가 실행 중이지 않습니다.[/bold red]")
                return False

            # Initialize TOR controller
            self.tor_controller = Controller.from_port(port=self.tor_control_port)
            self.tor_controller.authenticate()

            # Set up SOCKS proxy
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_socks_port)
            socket.socket = socks.socksocket

            console.print("[bold green]TOR 연결이 초기화되었습니다.[/bold green]")
            return True
        except Exception as e:
            logger.error(f"TOR initialization failed: {e}")
            return False

    def _is_tor_running(self) -> bool:
        """
        Check if TOR service is running
        """
        try:
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_socks_port)
            socket.socket = socks.socksocket
            response = requests.get('https://check.torproject.org/api/ip')
            return response.json().get('IsTor', False)
        except:
            return False

    async def scan(self, scan_type: str = "default", use_tor: bool = True) -> Dict:
        """
        Perform Nmap scan with progress display
        """
        try:
            if use_tor:
                if not await self.initialize_tor():
                    return {
                        'status': 'error',
                        'error': 'TOR initialization failed'
                    }

            scan_type_name = {
                'default': '기본 스캔',
                'aggressive': '공격적 스캔',
                'vulnerability': '취약점 스캔'
            }.get(scan_type, '알 수 없는 스캔')

            tor_status = "TOR" if use_tor else "일반"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Starting {tor_status} {scan_type_name} on {self.target}...",
                    total=100
                )
                
                # Simulate scan progress
                for i in range(100):
                    progress.update(task, advance=1)
                    await asyncio.sleep(0.1)
                
                # Actual scan
                if scan_type == "default":
                    return await self._default_scan(use_tor)
                elif scan_type == "aggressive":
                    return await self._aggressive_scan(use_tor)
                elif scan_type == "vulnerability":
                    return await self._vulnerability_scan(use_tor)
                
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def _default_scan(self, use_tor: bool) -> Dict:
        """Perform default Nmap scan through TOR"""
        try:
            # Basic port scan with service detection
            arguments = '-sV -sC -O'
            if use_tor:
                arguments += ' --proxies socks4://127.0.0.1:9050'
            
            self.nm.scan(self.target, arguments=arguments)
            
            # Process results
            for host in self.nm.all_hosts():
                self.scan_results[host] = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'os': self.nm[host].get('osmatch', []),
                    'ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        self.scan_results[host]['ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extra_info': port_info.get('extrainfo', '')
                        })
            
            return {
                'status': 'success',
                'results': self.scan_results
            }
        except Exception as e:
            logger.error(f"Default scan failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def _aggressive_scan(self, use_tor: bool) -> Dict:
        """Perform aggressive Nmap scan through TOR"""
        try:
            # More aggressive scan with additional checks
            arguments = '-A -T4 -p-'
            if use_tor:
                arguments += ' --proxies socks4://127.0.0.1:9050'
            
            self.nm.scan(self.target, arguments=arguments)
            
            # Process results
            for host in self.nm.all_hosts():
                self.scan_results[host] = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'os': self.nm[host].get('osmatch', []),
                    'ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        self.scan_results[host]['ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extra_info': port_info.get('extrainfo', ''),
                            'script_output': port_info.get('script', {})
                        })
            
            return {
                'status': 'success',
                'results': self.scan_results
            }
        except Exception as e:
            logger.error(f"Aggressive scan failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def _vulnerability_scan(self, use_tor: bool) -> Dict:
        """Perform vulnerability scan through TOR"""
        try:
            # Vulnerability scan with NSE scripts
            arguments = '-sV --script vuln'
            if use_tor:
                arguments += ' --proxies socks4://127.0.0.1:9050'
            
            self.nm.scan(self.target, arguments=arguments)
            
            # Process results
            for host in self.nm.all_hosts():
                self.scan_results[host] = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'vulnerabilities': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if 'script' in port_info:
                            for script_name, script_output in port_info['script'].items():
                                if 'VULNERABLE' in script_output:
                                    self.scan_results[host]['vulnerabilities'].append({
                                        'port': port,
                                        'service': port_info['name'],
                                        'script': script_name,
                                        'output': script_output
                                    })
            
            return {
                'status': 'success',
                'results': self.scan_results
            }
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def analyze_results(self) -> Dict:
        """
        Analyze scan results for potential security issues
        """
        try:
            if not self.scan_results:
                console.print("[bold red]분석할 스캔 결과가 없습니다.[/bold red]")
                return {
                    'status': 'error',
                    'error': 'No scan results to analyze'
                }

            analysis = super().analyze_results()
            
            if analysis['status'] == 'success':
                console.print(Panel.fit(
                    "[bold green]취약점 분석 결과[/bold green]",
                    title="Analysis Results"
                ))
                
                for vuln in analysis['vulnerabilities']:
                    console.print(f"[bold yellow]타입:[/bold yellow] {vuln['type']}")
                    console.print(f"[bold yellow]심각도:[/bold yellow] {vuln['severity']}")
                    console.print(f"[bold yellow]설명:[/bold yellow] {vuln['description']}")
                    console.print(f"[bold yellow]권장사항:[/bold yellow] {vuln['recommendation']}")
                    console.print("---")
            
            return analysis
        except Exception as e:
            logger.error(f"Results analysis failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            } 