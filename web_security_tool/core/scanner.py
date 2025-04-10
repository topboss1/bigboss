from typing import Dict, List, Optional
import requests
from bs4 import BeautifulSoup
import logging

class SecurityScanner:
    """Base class for security scanning functionality."""
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize the security scanner.
        
        Args:
            target (str): The target URL or IP address to scan
            config (Dict, optional): Configuration options for the scanner
        """
        self.target = target
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
    def scan(self) -> Dict:
        """
        Perform the security scan.
        
        Returns:
            Dict: Scan results including vulnerabilities found
        """
        raise NotImplementedError("Subclasses must implement scan()")
        
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """
        Make an HTTP request to the target.
        
        Args:
            url (str): URL to request
            method (str): HTTP method to use
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            requests.Response: The response object
        """
        try:
            response = requests.request(method, url, **kwargs)
            return response
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise
            
    def _parse_html(self, html: str) -> BeautifulSoup:
        """
        Parse HTML content.
        
        Args:
            html (str): HTML content to parse
            
        Returns:
            BeautifulSoup: Parsed HTML object
        """
        return BeautifulSoup(html, 'html.parser')
        
    def _validate_target(self) -> bool:
        """
        Validate the target URL or IP address.
        
        Returns:
            bool: True if target is valid, False otherwise
        """
        # Basic URL validation
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
            
        try:
            response = self._make_request(self.target)
            return response.status_code < 400
        except:
            return False 