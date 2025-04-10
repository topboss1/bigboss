from typing import Dict, List
from ..core.scanner import SecurityScanner
import logging

class SQLInjectionScanner(SecurityScanner):
    """Scanner for detecting SQL Injection vulnerabilities."""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[str]:
        """Load SQL injection test payloads from file."""
        try:
            with open('payloads/sql_injection_payloads.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.warning("SQL injection payloads file not found, using default payloads")
            return [
                "' OR '1'='1",
                "' OR 1=1 --",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--"
            ]
            
    def scan(self) -> Dict:
        """
        Scan for SQL injection vulnerabilities.
        
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
            
        # Test for SQL injection in forms
        self._test_forms(results)
        
        # Test for SQL injection in URL parameters
        self._test_url_parameters(results)
        
        return results
        
    def _test_forms(self, results: Dict):
        """Test forms for SQL injection vulnerabilities."""
        response = self._make_request(self.target)
        soup = self._parse_html(response.text)
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {}
            for input_field in form.find_all('input'):
                if input_field.get('name'):
                    form_data[input_field['name']] = self.payloads[0]
                    
            try:
                form_action = form.get('action', self.target)
                if not form_action.startswith(('http://', 'https://')):
                    form_action = self.target + form_action
                    
                # Test each payload
                for payload in self.payloads:
                    test_data = {k: payload for k in form_data.keys()}
                    response = self._make_request(
                        form_action,
                        method=form.get('method', 'GET'),
                        data=test_data
                    )
                    
                    # Check for common SQL error messages
                    error_indicators = [
                        'SQL syntax',
                        'mysql_fetch',
                        'ORA-',
                        'error in your SQL',
                        'SQL Server',
                        'PostgreSQL',
                        'SQLite'
                    ]
                    
                    if any(indicator in response.text for indicator in error_indicators):
                        results['vulnerabilities'].append({
                            'type': 'sql_injection',
                            'url': form_action,
                            'payload': payload,
                            'severity': 'critical'
                        })
                        
            except Exception as e:
                self.logger.error(f"Error testing form: {e}")
                
    def _test_url_parameters(self, results: Dict):
        """Test URL parameters for SQL injection vulnerabilities."""
        # Implementation for testing URL parameters
        # This would involve modifying query parameters with SQL injection payloads
        pass 