import os
import sys
from typing import Dict, List
import logging

# 현재 파일의 절대 경로를 기준으로 프로젝트 루트 디렉토리 경로 계산
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))

# 프로젝트 루트 디렉토리를 Python 경로에 추가
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from web_security_tool.core.scanner import SecurityScanner

class XSSScanner(SecurityScanner):
    """Scanner for detecting Cross-Site Scripting (XSS) vulnerabilities."""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[str]:
        """Load XSS test payloads from file."""
        try:
            # payloads 디렉토리의 절대 경로 계산
            payloads_dir = os.path.join(project_root, 'web_security_tool', 'payloads')
            payloads_file = os.path.join(payloads_dir, 'xss_payloads.txt')
            
            with open(payloads_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.warning("XSS payloads file not found, using default payloads")
            return [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>'
            ]
            
    def scan(self) -> Dict:
        """
        Scan for XSS vulnerabilities.
        
        Returns:
            Dict: Results containing found vulnerabilities
        """
        results = {
            'vulnerabilities': [],
            'tested_urls': [],
            'status': 'completed'
        }
        
        if not self._validate_target():
            results['status'] = 'failed'
            results['error'] = 'Invalid target URL'
            return results
            
        # Test for reflected XSS
        self._test_reflected_xss(results)
        
        # Test for stored XSS (if applicable)
        if self.config.get('test_stored_xss', False):
            self._test_stored_xss(results)
            
        return results
        
    def _test_reflected_xss(self, results: Dict):
        """Test for reflected XSS vulnerabilities."""
        # Get all forms on the page
        response = self._make_request(self.target)
        soup = self._parse_html(response.text)
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {}
            for input_field in form.find_all('input'):
                if input_field.get('name'):
                    form_data[input_field['name']] = self.payloads[0]
                    
            # Submit form with XSS payload
            try:
                form_action = form.get('action', self.target)
                if not form_action.startswith(('http://', 'https://')):
                    form_action = self.target + form_action
                    
                response = self._make_request(
                    form_action,
                    method=form.get('method', 'GET'),
                    data=form_data
                )
                
                # Check if payload is reflected in response
                for payload in self.payloads:
                    if payload in response.text:
                        results['vulnerabilities'].append({
                            'type': 'reflected_xss',
                            'url': form_action,
                            'payload': payload,
                            'severity': 'high'
                        })
                        
            except Exception as e:
                self.logger.error(f"Error testing form: {e}")
                
    def _test_stored_xss(self, results: Dict):
        """Test for stored XSS vulnerabilities."""
        # Implementation for stored XSS testing
        # This would typically involve submitting data through forms
        # and then checking if the payload appears on other pages
        pass 