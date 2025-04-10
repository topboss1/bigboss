"""
Error handling module for the reverse shell system.
"""

import logging
import datetime
from typing import Dict, Optional, List, Any
from .config import CONFIG
from .shell_utils import ShellUtils

logger = logging.getLogger(__name__)

class ErrorHandler:
    """Handles errors and provides automatic correction functionality"""
    
    def __init__(self):
        self.error_log: List[Dict] = []
        self.correction_history: List[Dict] = []
        
    def handle_error(self, error_type: str, error_message: str, context: Optional[Dict] = None) -> Optional[Dict]:
        """
        Handle errors and attempt automatic correction
        
        Args:
            error_type: Type of error
            error_message: Error message
            context: Additional context for error handling
            
        Returns:
            Dictionary containing correction information if successful, None otherwise
        """
        error_info = {
            'type': error_type,
            'message': error_message,
            'context': context or {},
            'timestamp': datetime.datetime.now().isoformat()
        }
        self.error_log.append(error_info)
        logger.error(f"Error occurred: {error_type} - {error_message}")
        
        correction = self._attempt_correction(error_type, error_message, context)
        if correction:
            self.correction_history.append({
                'error': error_info,
                'correction': correction,
                'success': True
            })
            logger.info(f"Applied correction for {error_type}: {correction}")
            return correction
        
        logger.warning(f"No correction available for {error_type}")
        return None
    
    def _attempt_correction(self, error_type: str, error_message: str, context: Optional[Dict]) -> Optional[Dict]:
        """Attempt to automatically correct common errors"""
        correction_methods = {
            'connection_error': self._fix_connection_error,
            'shell_error': self._fix_shell_error,
            'payload_error': self._fix_payload_error,
            'execution_error': self._fix_execution_error,
            'permission_error': self._fix_permission_error,
            'encryption_error': self._fix_encryption_error
        }
        
        method = correction_methods.get(error_type)
        if method:
            return method(error_message, context)
        return None
    
    def _fix_connection_error(self, error_message: str, context: Optional[Dict]) -> Optional[Dict]:
        """Fix common connection errors"""
        if not context:
            return None
            
        if "Connection refused" in error_message:
            port = context.get('port')
            host = context.get('host')
            if port and host:
                new_port = ShellUtils.find_available_port(host)
                if new_port:
                    return {
                        'action': 'retry_connection',
                        'parameters': {
                            'port': new_port,
                            'retry_count': CONFIG['retries']['connection'],
                            'delay': 5
                        }
                    }
        
        elif "Timeout" in error_message:
            current_timeout = context.get('timeout', CONFIG['timeouts']['connection'])
            return {
                'action': 'increase_timeout',
                'parameters': {
                    'timeout': min(current_timeout * 2, 120)
                }
            }
            
        return None
    
    def _fix_shell_error(self, error_message: str, context: Optional[Dict]) -> Optional[Dict]:
        """Fix common shell errors"""
        if not context:
            return None
            
        if "command not found" in error_message:
            command = context.get('command')
            if command:
                alternatives = {
                    'netcat': ['nc', 'ncat', 'socat'],
                    'python': ['python3', 'python2', 'perl'],
                    'bash': ['sh', 'zsh', 'ksh']
                }
                
                for cmd, alts in alternatives.items():
                    if cmd in command:
                        return {
                            'action': 'use_alternative_command',
                            'parameters': {
                                'command': command.replace(cmd, alts[0])
                            }
                        }
        
        return None
    
    def _fix_payload_error(self, error_message: str, context: Optional[Dict]) -> Optional[Dict]:
        """Fix common payload errors"""
        if not context:
            return None
            
        if "invalid syntax" in error_message:
            payload_type = context.get('payload_type')
            if payload_type:
                return {
                    'action': 'regenerate_payload',
                    'parameters': {
                        'type': payload_type,
                        'encryption': True
                    }
                }
                
        elif "payload too large" in error_message:
            return {
                'action': 'compress_payload',
                'parameters': {
                    'compression': 'zlib'
                }
            }
            
        return None
    
    def _fix_execution_error(self, error_message: str, context: Optional[Dict]) -> Optional[Dict]:
        """Fix common execution errors"""
        if not context:
            return None
            
        if "permission denied" in error_message:
            command = context.get('command')
            if command:
                return {
                    'action': 'elevate_privileges',
                    'parameters': {
                        'method': 'sudo',
                        'command': command
                    }
                }
                
        elif "process terminated" in error_message:
            return {
                'action': 'restart_process',
                'parameters': {
                    'retry_count': CONFIG['retries']['execution']
                }
            }
            
        return None
    
    def _fix_permission_error(self, error_message: str, context: Optional[Dict]) -> Optional[Dict]:
        """Fix permission-related errors"""
        if not context:
            return None
            
        if "access denied" in error_message:
            return {
                'action': 'request_elevation',
                'parameters': {
                    'method': 'uac_bypass' if 'windows' in error_message.lower() else 'sudo'
                }
            }
            
        return None
    
    def _fix_encryption_error(self, error_message: str, context: Optional[Dict]) -> Optional[Dict]:
        """Fix encryption-related errors"""
        if not context:
            return None
            
        if "invalid key" in error_message:
            return {
                'action': 'regenerate_key',
                'parameters': {
                    'algorithm': CONFIG['security']['encryption_algorithm'],
                    'key_length': CONFIG['security']['min_key_length']
                }
            }
            
        return None
    
    def get_error_log(self) -> List[Dict]:
        """Get the error log"""
        return self.error_log
    
    def get_correction_history(self) -> List[Dict]:
        """Get the correction history"""
        return self.correction_history
    
    def clear_logs(self) -> None:
        """Clear error and correction logs"""
        self.error_log.clear()
        self.correction_history.clear()
        logger.info("Cleared error and correction logs") 