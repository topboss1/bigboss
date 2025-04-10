"""
SQL Injection Scanner Module
This module provides functionality for detecting SQL injection vulnerabilities.
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional
import logging
from bs4 import BeautifulSoup
from rich.console import Console
import re

logger = logging.getLogger(__name__)
console = Console()

class SQLInjectionScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities: List[Dict] = []
        self.session = None

    async def initialize(self):
        """Initialize the scanner"""
        self.session = aiohttp.ClientSession()

    async def close(self):
        """Close the scanner session"""
        if self.session:
            await self.session.close()

    async def scan(self) -> Dict:
        """
        Scan for SQL injection vulnerabilities
        """
        try:
            await self.initialize()
            console.print(f"[bold blue]Scanning for SQL injection vulnerabilities on {self.target_url}...[/bold blue]")
            
            # Get the page content
            async with self.session.get(self.target_url) as response:
                if response.status != 200:
                    return {
                        'status': 'error',
                        'error': f'Failed to fetch page: {response.status}'
                    }
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find all forms
                forms = soup.find_all('form')
                for form in forms:
                    await self._check_form_sql_injection(form)
                
                # Find all input fields
                inputs = soup.find_all('input')
                for input_field in inputs:
                    await self._check_input_sql_injection(input_field)
            
            return {
                'status': 'success',
                'vulnerabilities': self.vulnerabilities
            }
        except Exception as e:
            logger.error(f"SQL injection scan failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
        finally:
            await self.close()

    async def _check_form_sql_injection(self, form):
        """Check form for SQL injection vulnerabilities"""
        try:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            # Test SQL injection payloads
            payloads = [
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
            
            for payload in payloads:
                form_data = {}
                for input_field in form.find_all('input'):
                    name = input_field.get('name', '')
                    if name:
                        form_data[name] = payload
                
                if form_method == 'get':
                    async with self.session.get(form_action, params=form_data) as response:
                        if await self._check_response_for_sql_injection(await response.text()):
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'location': 'form',
                                'form_action': form_action,
                                'payload': payload
                            })
                else:
                    async with self.session.post(form_action, data=form_data) as response:
                        if await self._check_response_for_sql_injection(await response.text()):
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'location': 'form',
                                'form_action': form_action,
                                'payload': payload
                            })
        except Exception as e:
            logger.error(f"Form SQL injection check failed: {e}")

    async def _check_input_sql_injection(self, input_field):
        """Check input field for SQL injection vulnerabilities"""
        try:
            input_name = input_field.get('name', '')
            if not input_name:
                return
            
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' OR '1'='1'/*"
            ]
            
            for payload in payloads:
                params = {input_name: payload}
                async with self.session.get(self.target_url, params=params) as response:
                    if await self._check_response_for_sql_injection(await response.text()):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'location': 'input',
                            'input_name': input_name,
                            'payload': payload
                        })
        except Exception as e:
            logger.error(f"Input SQL injection check failed: {e}")

    async def _check_response_for_sql_injection(self, response_text: str) -> bool:
        """Check if SQL injection payload caused an error or unexpected behavior"""
        error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'syntax error',
            r'unterminated quoted string',
            r'quoted string not properly terminated'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False 