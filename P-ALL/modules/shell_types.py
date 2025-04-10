"""
Shell types and configuration classes for the reverse shell system.
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional
from .config import CONFIG

class ShellType(Enum):
    """Enum for different shell types"""
    PYTHON = auto()
    BASH = auto()
    POWERSHELL = auto()
    CMD = auto()
    PERL = auto()
    RUBY = auto()
    PHP = auto()
    JAVA = auto()
    NODEJS = auto()
    GO = auto()
    RUST = auto()

    @classmethod
    def get_default_shell(cls) -> 'ShellType':
        """Get the default shell type based on the operating system"""
        import platform
        system = platform.system().lower()
        if system == 'windows':
            return cls.POWERSHELL
        elif system in ('linux', 'darwin'):
            return cls.BASH
        else:
            return cls.PYTHON

@dataclass
class ShellConfig:
    """Configuration for shell operations"""
    host: str
    port: int
    protocol: str = CONFIG['network']['default_protocol']
    encryption: Optional[str] = None
    timeout: int = CONFIG['timeouts']['shell']
    retry_count: int = CONFIG['retries']['shell']
    retry_delay: int = 5
    shell_type: ShellType = ShellType.get_default_shell()

    def __post_init__(self):
        """Validate configuration after initialization"""
        self._validate_port()
        self._validate_protocol()
        self._validate_timeout()
        self._validate_retry_count()
        self._validate_retry_delay()

    def _validate_port(self):
        """Validate port number"""
        if not (0 < self.port < 65536):
            raise ValueError(f"Invalid port number: {self.port}")
        if self.port in CONFIG['network']['banned_ports']:
            raise ValueError(f"Port {self.port} is in the banned ports list")

    def _validate_protocol(self):
        """Validate protocol"""
        if self.protocol.lower() not in ('tcp', 'udp'):
            raise ValueError(f"Invalid protocol: {self.protocol}")

    def _validate_timeout(self):
        """Validate timeout"""
        if self.timeout <= 0:
            raise ValueError(f"Invalid timeout: {self.timeout}")

    def _validate_retry_count(self):
        """Validate retry count"""
        if self.retry_count < 0:
            raise ValueError(f"Invalid retry count: {self.retry_count}")

    def _validate_retry_delay(self):
        """Validate retry delay"""
        if self.retry_delay < 0:
            raise ValueError(f"Invalid retry delay: {self.retry_delay}")

    def to_dict(self) -> dict:
        """Convert configuration to dictionary"""
        return {
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'encryption': self.encryption,
            'timeout': self.timeout,
            'retry_count': self.retry_count,
            'retry_delay': self.retry_delay,
            'shell_type': self.shell_type.name
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ShellConfig':
        """Create configuration from dictionary"""
        shell_type = ShellType[data.pop('shell_type')]
        return cls(**data, shell_type=shell_type) 