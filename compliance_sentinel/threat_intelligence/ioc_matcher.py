"""IOC (Indicator of Compromise) matching and extraction engine."""

import re
import ipaddress
from typing import List, Tuple, Set, Dict, Any
from dataclasses import dataclass
from enum import Enum
import hashlib
import logging

from compliance_sentinel.core.interfaces import SecurityIssue
from compliance_sentinel.monitoring.monitoring_manager import SecurityEvent
from .threat_intel_manager import IOCType


logger = logging.getLogger(__name__)


@dataclass
class IOCMatch:
    """Represents an IOC match result."""
    ioc_type: IOCType
    value: str
    confidence: float
    context: str
    line_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary."""
        return {
            'ioc_type': self.ioc_type.value,
            'value': self.value,
            'confidence': self.confidence,
            'context': self.context,
            'line_number': self.line_number
        }


class IOCMatcher:
    """IOC matching and extraction engine."""
    
    def __init__(self):
        """Initialize IOC matcher with patterns."""
        self.logger = logging.getLogger(__name__)
        
        # Compile regex patterns for different IOC types
        self._compile_patterns()
        
        # Known file extensions for executables
        self.executable_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.pif',
            '.msi', '.jar', '.app', '.dmg', '.pkg', '.deb', '.rpm'
        }
        
        # Common hash lengths
        self.hash_lengths = {
            32: 'MD5',
            40: 'SHA1', 
            56: 'SHA224',
            64: 'SHA256',
            96: 'SHA384',
            128: 'SHA512'
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for IOC detection."""
        
        # IP Address patterns
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # Domain patterns
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'  # Subdomains
            r'[a-zA-Z]{2,}\b'  # TLD
        )
        
        # URL patterns
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            re.IGNORECASE
        )
        
        # Email patterns
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        # File hash patterns (MD5, SHA1, SHA256, etc.)
        self.hash_pattern = re.compile(
            r'\b[a-fA-F0-9]{32}\b|'     # MD5
            r'\b[a-fA-F0-9]{40}\b|'     # SHA1
            r'\b[a-fA-F0-9]{56}\b|'     # SHA224
            r'\b[a-fA-F0-9]{64}\b|'     # SHA256
            r'\b[a-fA-F0-9]{96}\b|'     # SHA384
            r'\b[a-fA-F0-9]{128}\b'     # SHA512
        )
        
        # User-Agent patterns (suspicious)
        self.user_agent_pattern = re.compile(
            r'User-Agent:\s*([^\r\n]+)',
            re.IGNORECASE
        )
        
        # Registry key patterns (Windows)
        self.registry_pattern = re.compile(
            r'\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"]+',
            re.IGNORECASE
        )
        
        # File path patterns
        self.file_path_pattern = re.compile(
            r'(?:[a-zA-Z]:\\|/)[^\s"<>|*?]+(?:\.[a-zA-Z0-9]+)?'
        )
        
        # Process name patterns
        self.process_pattern = re.compile(
            r'\b[a-zA-Z0-9_.-]+\.(?:exe|dll|bat|cmd|com|scr|pif|msi)\b',
            re.IGNORECASE
        )
        
        # Mutex patterns
        self.mutex_pattern = re.compile(
            r'\\BaseNamedObjects\\[a-zA-Z0-9_.-]+|'
            r'Global\\[a-zA-Z0-9_.-]+|'
            r'Local\\[a-zA-Z0-9_.-]+',
            re.IGNORECASE
        )
        
        # Certificate patterns (SHA1 thumbprints)
        self.certificate_pattern = re.compile(
            r'\b[a-fA-F0-9]{40}\b'  # Certificate thumbprints are typically SHA1
        )
    
    def extract_iocs_from_issue(self, issue: SecurityIssue) -> List[Tuple[IOCType, str]]:
        """Extract IOCs from a security issue."""
        iocs = []
        
        # Combine all text content for analysis
        text_content = f"{issue.description} {issue.file_path}"
        if hasattr(issue, 'code_snippet') and issue.code_snippet:
            text_content += f" {issue.code_snippet}"
        
        # Extract different types of IOCs
        iocs.extend(self._extract_ip_addresses(text_content))
        iocs.extend(self._extract_domains(text_content))
        iocs.extend(self._extract_urls(text_content))
        iocs.extend(self._extract_emails(text_content))
        iocs.extend(self._extract_file_hashes(text_content))
        iocs.extend(self._extract_file_paths(text_content))
        iocs.extend(self._extract_registry_keys(text_content))
        iocs.extend(self._extract_process_names(text_content))
        
        return self._deduplicate_iocs(iocs)
    
    def extract_iocs_from_event(self, event: SecurityEvent) -> List[Tuple[IOCType, str]]:
        """Extract IOCs from a security event."""
        iocs = []
        
        # Extract from event description and details
        text_content = event.description
        if hasattr(event, 'details') and event.details:
            text_content += f" {event.details}"
        
        # Add specific event fields
        if event.source_ip:
            iocs.append((IOCType.IP_ADDRESS, event.source_ip))
        
        if hasattr(event, 'user_agent') and event.user_agent:
            iocs.append((IOCType.USER_AGENT, event.user_agent))
        
        # Extract from text content
        iocs.extend(self._extract_ip_addresses(text_content))
        iocs.extend(self._extract_domains(text_content))
        iocs.extend(self._extract_urls(text_content))
        iocs.extend(self._extract_emails(text_content))
        iocs.extend(self._extract_file_hashes(text_content))
        iocs.extend(self._extract_file_paths(text_content))
        iocs.extend(self._extract_process_names(text_content))
        
        return self._deduplicate_iocs(iocs)
    
    def extract_iocs_from_text(self, text: str) -> List[IOCMatch]:
        """Extract IOCs from arbitrary text with confidence scoring."""
        matches = []
        
        # Extract different types of IOCs with context
        matches.extend(self._extract_ip_matches(text))
        matches.extend(self._extract_domain_matches(text))
        matches.extend(self._extract_url_matches(text))
        matches.extend(self._extract_email_matches(text))
        matches.extend(self._extract_hash_matches(text))
        matches.extend(self._extract_file_path_matches(text))
        matches.extend(self._extract_registry_matches(text))
        matches.extend(self._extract_process_matches(text))
        matches.extend(self._extract_user_agent_matches(text))
        matches.extend(self._extract_mutex_matches(text))
        
        return matches
    
    def _extract_ip_addresses(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract IP addresses from text."""
        iocs = []
        matches = self.ip_pattern.findall(text)
        
        for match in matches:
            if self._is_valid_ip(match):
                iocs.append((IOCType.IP_ADDRESS, match))
        
        return iocs
    
    def _extract_domains(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract domain names from text."""
        iocs = []
        matches = self.domain_pattern.findall(text)
        
        for match in matches:
            if self._is_valid_domain(match):
                iocs.append((IOCType.DOMAIN, match.lower()))
        
        return iocs
    
    def _extract_urls(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract URLs from text."""
        iocs = []
        matches = self.url_pattern.findall(text)
        
        for match in matches:
            iocs.append((IOCType.URL, match))
        
        return iocs
    
    def _extract_emails(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract email addresses from text."""
        iocs = []
        matches = self.email_pattern.findall(text)
        
        for match in matches:
            iocs.append((IOCType.EMAIL, match.lower()))
        
        return iocs
    
    def _extract_file_hashes(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract file hashes from text."""
        iocs = []
        matches = self.hash_pattern.findall(text)
        
        for match in matches:
            if self._is_valid_hash(match):
                iocs.append((IOCType.FILE_HASH, match.lower()))
        
        return iocs
    
    def _extract_file_paths(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract file paths from text."""
        iocs = []
        matches = self.file_path_pattern.findall(text)
        
        for match in matches:
            if self._is_suspicious_file_path(match):
                iocs.append((IOCType.FILE_PATH, match))
        
        return iocs
    
    def _extract_registry_keys(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract Windows registry keys from text."""
        iocs = []
        matches = self.registry_pattern.findall(text)
        
        for match in matches:
            iocs.append((IOCType.REGISTRY_KEY, match))
        
        return iocs
    
    def _extract_process_names(self, text: str) -> List[Tuple[IOCType, str]]:
        """Extract process names from text."""
        iocs = []
        matches = self.process_pattern.findall(text)
        
        for match in matches:
            if self._is_suspicious_process(match):
                iocs.append((IOCType.PROCESS_NAME, match.lower()))
        
        return iocs
    
    def _extract_ip_matches(self, text: str) -> List[IOCMatch]:
        """Extract IP address matches with context."""
        matches = []
        
        for match in self.ip_pattern.finditer(text):
            ip = match.group()
            if self._is_valid_ip(ip):
                context = self._get_context(text, match.start(), match.end())
                confidence = self._calculate_ip_confidence(ip, context)
                
                matches.append(IOCMatch(
                    ioc_type=IOCType.IP_ADDRESS,
                    value=ip,
                    confidence=confidence,
                    context=context
                ))
        
        return matches
    
    def _extract_domain_matches(self, text: str) -> List[IOCMatch]:
        """Extract domain matches with context."""
        matches = []
        
        for match in self.domain_pattern.finditer(text):
            domain = match.group().lower()
            if self._is_valid_domain(domain):
                context = self._get_context(text, match.start(), match.end())
                confidence = self._calculate_domain_confidence(domain, context)
                
                matches.append(IOCMatch(
                    ioc_type=IOCType.DOMAIN,
                    value=domain,
                    confidence=confidence,
                    context=context
                ))
        
        return matches
    
    def _extract_url_matches(self, text: str) -> List[IOCMatch]:
        """Extract URL matches with context."""
        matches = []
        
        for match in self.url_pattern.finditer(text):
            url = match.group()
            context = self._get_context(text, match.start(), match.end())
            confidence = self._calculate_url_confidence(url, context)
            
            matches.append(IOCMatch(
                ioc_type=IOCType.URL,
                value=url,
                confidence=confidence,
                context=context
            ))
        
        return matches
    
    def _extract_email_matches(self, text: str) -> List[IOCMatch]:
        """Extract email matches with context."""
        matches = []
        
        for match in self.email_pattern.finditer(text):
            email = match.group().lower()
            context = self._get_context(text, match.start(), match.end())
            confidence = self._calculate_email_confidence(email, context)
            
            matches.append(IOCMatch(
                ioc_type=IOCType.EMAIL,
                value=email,
                confidence=confidence,
                context=context
            ))
        
        return matches
    
    def _extract_hash_matches(self, text: str) -> List[IOCMatch]:
        """Extract hash matches with context."""
        matches = []
        
        for match in self.hash_pattern.finditer(text):
            hash_value = match.group().lower()
            if self._is_valid_hash(hash_value):
                context = self._get_context(text, match.start(), match.end())
                confidence = self._calculate_hash_confidence(hash_value, context)
                
                matches.append(IOCMatch(
                    ioc_type=IOCType.FILE_HASH,
                    value=hash_value,
                    confidence=confidence,
                    context=context
                ))
        
        return matches
    
    def _extract_file_path_matches(self, text: str) -> List[IOCMatch]:
        """Extract file path matches with context."""
        matches = []
        
        for match in self.file_path_pattern.finditer(text):
            file_path = match.group()
            if self._is_suspicious_file_path(file_path):
                context = self._get_context(text, match.start(), match.end())
                confidence = self._calculate_file_path_confidence(file_path, context)
                
                matches.append(IOCMatch(
                    ioc_type=IOCType.FILE_PATH,
                    value=file_path,
                    confidence=confidence,
                    context=context
                ))
        
        return matches
    
    def _extract_registry_matches(self, text: str) -> List[IOCMatch]:
        """Extract registry key matches with context."""
        matches = []
        
        for match in self.registry_pattern.finditer(text):
            registry_key = match.group()
            context = self._get_context(text, match.start(), match.end())
            confidence = self._calculate_registry_confidence(registry_key, context)
            
            matches.append(IOCMatch(
                ioc_type=IOCType.REGISTRY_KEY,
                value=registry_key,
                confidence=confidence,
                context=context
            ))
        
        return matches
    
    def _extract_process_matches(self, text: str) -> List[IOCMatch]:
        """Extract process name matches with context."""
        matches = []
        
        for match in self.process_pattern.finditer(text):
            process_name = match.group().lower()
            if self._is_suspicious_process(process_name):
                context = self._get_context(text, match.start(), match.end())
                confidence = self._calculate_process_confidence(process_name, context)
                
                matches.append(IOCMatch(
                    ioc_type=IOCType.PROCESS_NAME,
                    value=process_name,
                    confidence=confidence,
                    context=context
                ))
        
        return matches
    
    def _extract_user_agent_matches(self, text: str) -> List[IOCMatch]:
        """Extract user agent matches with context."""
        matches = []
        
        for match in self.user_agent_pattern.finditer(text):
            user_agent = match.group(1)
            context = self._get_context(text, match.start(), match.end())
            confidence = self._calculate_user_agent_confidence(user_agent, context)
            
            matches.append(IOCMatch(
                ioc_type=IOCType.USER_AGENT,
                value=user_agent,
                confidence=confidence,
                context=context
            ))
        
        return matches
    
    def _extract_mutex_matches(self, text: str) -> List[IOCMatch]:
        """Extract mutex matches with context."""
        matches = []
        
        for match in self.mutex_pattern.finditer(text):
            mutex = match.group()
            context = self._get_context(text, match.start(), match.end())
            confidence = self._calculate_mutex_confidence(mutex, context)
            
            matches.append(IOCMatch(
                ioc_type=IOCType.MUTEX,
                value=mutex,
                confidence=confidence,
                context=context
            ))
        
        return matches
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        try:
            addr = ipaddress.ip_address(ip)
            # Filter out private/local addresses for threat intelligence
            return not (addr.is_private or addr.is_loopback or addr.is_multicast)
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name."""
        # Basic domain validation
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        # Must have at least one dot
        if '.' not in domain:
            return False
        
        # Filter out common false positives
        false_positives = {
            'localhost', 'example.com', 'test.com', 'sample.com',
            'domain.com', 'site.com', 'website.com'
        }
        
        return domain.lower() not in false_positives
    
    def _is_valid_hash(self, hash_value: str) -> bool:
        """Validate hash value."""
        # Check if it's a known hash length
        return len(hash_value) in self.hash_lengths
    
    def _is_suspicious_file_path(self, file_path: str) -> bool:
        """Check if file path is suspicious."""
        suspicious_paths = {
            '/tmp/', '/var/tmp/', 'C:\\Temp\\', 'C:\\Windows\\Temp\\',
            '%TEMP%', '%APPDATA%', '/dev/shm/', 'C:\\Users\\Public\\'
        }
        
        # Check for suspicious directories
        for suspicious in suspicious_paths:
            if suspicious.lower() in file_path.lower():
                return True
        
        # Check for executable extensions
        for ext in self.executable_extensions:
            if file_path.lower().endswith(ext):
                return True
        
        return False
    
    def _is_suspicious_process(self, process_name: str) -> bool:
        """Check if process name is suspicious."""
        # Common legitimate processes to filter out
        legitimate_processes = {
            'explorer.exe', 'svchost.exe', 'winlogon.exe', 'csrss.exe',
            'lsass.exe', 'services.exe', 'chrome.exe', 'firefox.exe'
        }
        
        return process_name.lower() not in legitimate_processes
    
    def _get_context(self, text: str, start: int, end: int, window: int = 50) -> str:
        """Get context around a match."""
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        return text[context_start:context_end].strip()
    
    def _calculate_ip_confidence(self, ip: str, context: str) -> float:
        """Calculate confidence score for IP address."""
        confidence = 0.7  # Base confidence
        
        # Increase confidence for certain contexts
        threat_keywords = ['malware', 'attack', 'suspicious', 'blocked', 'threat']
        for keyword in threat_keywords:
            if keyword.lower() in context.lower():
                confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_domain_confidence(self, domain: str, context: str) -> float:
        """Calculate confidence score for domain."""
        confidence = 0.6  # Base confidence
        
        # Increase confidence for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                confidence += 0.2
                break
        
        # Increase confidence for threat context
        threat_keywords = ['malware', 'phishing', 'suspicious', 'blocked']
        for keyword in threat_keywords:
            if keyword.lower() in context.lower():
                confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_url_confidence(self, url: str, context: str) -> float:
        """Calculate confidence score for URL."""
        confidence = 0.7  # Base confidence
        
        # Increase confidence for suspicious patterns
        if any(pattern in url.lower() for pattern in ['download', 'payload', 'exploit']):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_email_confidence(self, email: str, context: str) -> float:
        """Calculate confidence score for email."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence for suspicious domains
        domain = email.split('@')[1] if '@' in email else ''
        if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
            confidence += 0.3
        
        return min(confidence, 1.0)
    
    def _calculate_hash_confidence(self, hash_value: str, context: str) -> float:
        """Calculate confidence score for hash."""
        confidence = 0.8  # Base confidence (hashes are usually reliable)
        
        # Increase confidence for malware context
        if any(keyword in context.lower() for keyword in ['malware', 'virus', 'trojan']):
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_file_path_confidence(self, file_path: str, context: str) -> float:
        """Calculate confidence score for file path."""
        confidence = 0.6  # Base confidence
        
        # Increase confidence for suspicious locations
        if any(path in file_path.lower() for path in ['/tmp/', 'temp', 'appdata']):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_registry_confidence(self, registry_key: str, context: str) -> float:
        """Calculate confidence score for registry key."""
        confidence = 0.7  # Base confidence
        
        # Increase confidence for persistence locations
        persistence_keys = ['run', 'runonce', 'startup', 'service']
        if any(key in registry_key.lower() for key in persistence_keys):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_process_confidence(self, process_name: str, context: str) -> float:
        """Calculate confidence score for process name."""
        confidence = 0.6  # Base confidence
        
        # Increase confidence for suspicious names
        suspicious_patterns = ['temp', 'tmp', 'random', 'update']
        if any(pattern in process_name.lower() for pattern in suspicious_patterns):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_user_agent_confidence(self, user_agent: str, context: str) -> float:
        """Calculate confidence score for user agent."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence for suspicious patterns
        if len(user_agent) < 10 or 'bot' in user_agent.lower():
            confidence += 0.3
        
        return min(confidence, 1.0)
    
    def _calculate_mutex_confidence(self, mutex: str, context: str) -> float:
        """Calculate confidence score for mutex."""
        confidence = 0.8  # Base confidence (mutexes are usually reliable IOCs)
        
        return min(confidence, 1.0)
    
    def _deduplicate_iocs(self, iocs: List[Tuple[IOCType, str]]) -> List[Tuple[IOCType, str]]:
        """Remove duplicate IOCs."""
        seen = set()
        deduplicated = []
        
        for ioc_type, value in iocs:
            key = (ioc_type, value.lower())
            if key not in seen:
                seen.add(key)
                deduplicated.append((ioc_type, value))
        
        return deduplicated