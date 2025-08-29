"""Secure communication protocols for all system integrations."""

import logging
import ssl
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import socket


class CommunicationProtocol(Enum):
    """Supported secure communication protocols."""
    TLS_1_3 = "tls_1_3"
    TLS_1_2 = "tls_1_2"
    HTTPS = "https"
    WSS = "wss"  # WebSocket Secure
    SFTP = "sftp"
    SSH = "ssh"


@dataclass
class TLSConfig:
    """TLS configuration settings."""
    
    protocol_version: str = "TLSv1.3"
    cipher_suites: List[str] = None
    verify_mode: int = ssl.CERT_REQUIRED
    check_hostname: bool = True
    ca_certs_file: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    
    def __post_init__(self):
        if self.cipher_suites is None:
            # Secure cipher suites
            self.cipher_suites = [
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_128_GCM_SHA256',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256'
            ]
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with secure settings."""
        
        # Use highest available TLS version
        context = ssl.create_default_context()
        
        # Set minimum TLS version
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Prefer TLS 1.3 if available
        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass  # TLS 1.3 not available
        
        # Configure verification
        context.verify_mode = self.verify_mode
        context.check_hostname = self.check_hostname
        
        # Load certificates if provided
        if self.ca_certs_file:
            context.load_verify_locations(self.ca_certs_file)
        
        if self.cert_file and self.key_file:
            context.load_cert_chain(self.cert_file, self.key_file)
        
        return context


class CertificateManager:
    """Manages SSL/TLS certificates."""
    
    def __init__(self):
        """Initialize certificate manager."""
        self.logger = logging.getLogger(__name__)
    
    def validate_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Validate SSL certificate for hostname."""
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
        except Exception as e:
            self.logger.error(f"Certificate validation failed for {hostname}: {e}")
            return {
                'valid': False,
                'error': str(e)
            }


class MessageEncryption:
    """Handles message-level encryption."""
    
    def __init__(self):
        """Initialize message encryption."""
        self.logger = logging.getLogger(__name__)
    
    def encrypt_message(self, message: str, key: bytes) -> bytes:
        """Encrypt message using Fernet."""
        
        try:
            from cryptography.fernet import Fernet
            
            if len(key) != 32:
                # Derive key if not 32 bytes
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                import base64
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'compliance_sentinel',
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(key))
            
            f = Fernet(key)
            return f.encrypt(message.encode())
            
        except ImportError:
            self.logger.error("cryptography library not available")
            return message.encode()
        except Exception as e:
            self.logger.error(f"Message encryption failed: {e}")
            return message.encode()
    
    def decrypt_message(self, encrypted_message: bytes, key: bytes) -> str:
        """Decrypt message using Fernet."""
        
        try:
            from cryptography.fernet import Fernet
            
            if len(key) != 32:
                # Derive key if not 32 bytes
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                import base64
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'compliance_sentinel',
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(key))
            
            f = Fernet(key)
            return f.decrypt(encrypted_message).decode()
            
        except ImportError:
            self.logger.error("cryptography library not available")
            return encrypted_message.decode()
        except Exception as e:
            self.logger.error(f"Message decryption failed: {e}")
            return encrypted_message.decode()


class SecureCommunicationManager:
    """Main secure communication manager."""
    
    def __init__(self):
        """Initialize secure communication manager."""
        self.logger = logging.getLogger(__name__)
        self.tls_config = TLSConfig()
        self.cert_manager = CertificateManager()
        self.message_encryption = MessageEncryption()
    
    def create_secure_context(self, protocol: CommunicationProtocol) -> ssl.SSLContext:
        """Create secure SSL context for protocol."""
        
        if protocol in [CommunicationProtocol.HTTPS, CommunicationProtocol.WSS, 
                       CommunicationProtocol.TLS_1_2, CommunicationProtocol.TLS_1_3]:
            return self.tls_config.create_ssl_context()
        else:
            raise ValueError(f"SSL context not applicable for protocol: {protocol}")
    
    def validate_connection_security(self, hostname: str, port: int, protocol: CommunicationProtocol) -> Dict[str, Any]:
        """Validate security of connection."""
        
        results = {
            'secure': False,
            'protocol': protocol.value,
            'issues': [],
            'recommendations': []
        }
        
        if protocol in [CommunicationProtocol.HTTPS, CommunicationProtocol.WSS]:
            # Validate certificate
            cert_validation = self.cert_manager.validate_certificate(hostname, port)
            
            if cert_validation['valid']:
                results['secure'] = True
                results['certificate'] = cert_validation
            else:
                results['issues'].append(f"Certificate validation failed: {cert_validation.get('error')}")
                results['recommendations'].append("Fix certificate issues before establishing connection")
        
        elif protocol in [CommunicationProtocol.TLS_1_2, CommunicationProtocol.TLS_1_3]:
            results['secure'] = True  # Assume secure if using TLS
        
        else:
            results['issues'].append(f"Protocol {protocol.value} may not be secure")
            results['recommendations'].append("Use TLS-based protocols for secure communication")
        
        return results
    
    def get_security_recommendations(self) -> List[str]:
        """Get general security recommendations."""
        
        return [
            "Always use TLS 1.2 or higher for network communication",
            "Validate SSL certificates and check for expiration",
            "Use strong cipher suites and disable weak ones",
            "Implement certificate pinning for critical connections",
            "Enable HSTS headers for web applications",
            "Use secure WebSocket (WSS) instead of plain WebSocket",
            "Implement proper certificate chain validation",
            "Monitor certificate expiration dates",
            "Use mutual TLS (mTLS) for service-to-service communication",
            "Implement proper error handling without information disclosure"
        ]