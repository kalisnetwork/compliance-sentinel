"""Threat intelligence feed integrations."""

import asyncio
import aiohttp
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from abc import ABC, abstractmethod

from .threat_intel_manager import (
    ThreatIndicator, ThreatIntelConfig, IOCType, 
    ThreatType, ThreatLevel
)


logger = logging.getLogger(__name__)


class ThreatFeedIntegration(ABC):
    """Base class for threat intelligence feed integrations."""
    
    def __init__(self, config: ThreatIntelConfig):
        """Initialize feed integration."""
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.feed_name}")
        self.session = None
        self.rate_limiter = asyncio.Semaphore(config.requests_per_minute)
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def get_latest_indicators(self) -> List[ThreatIndicator]:
        """Get latest threat indicators from feed."""
        pass
    
    async def _make_request(self, url: str, headers: Dict[str, str] = None, 
                          params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make rate-limited HTTP request."""
        async with self.rate_limiter:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            try:
                async with self.session.get(url, headers=headers, params=params) as response:
                    response.raise_for_status()
                    return await response.json()
            except Exception as e:
                self.logger.error(f"Request failed for {url}: {e}")
                raise
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime."""
        # Common timestamp formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Fallback to current time
        self.logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return datetime.now()
    
    async def close(self):
        """Close the integration."""
        if self.session:
            await self.session.close()


class VirusTotalIntegration(ThreatFeedIntegration):
    """VirusTotal threat intelligence integration."""
    
    def __init__(self, config: ThreatIntelConfig):
        """Initialize VirusTotal integration."""
        super().__init__(config)
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.api_key = config.api_key
    
    async def get_latest_indicators(self) -> List[ThreatIndicator]:
        """Get latest indicators from VirusTotal."""
        indicators = []
        
        try:
            # Get recent malware samples
            url = f"{self.base_url}/file/search"
            headers = {"apikey": self.api_key}
            params = {
                "query": "type:peexe",
                "limit": self.config.batch_size
            }
            
            response = await self._make_request(url, headers, params)
            
            if "hashes" in response:
                for hash_info in response["hashes"]:
                    indicator = await self._create_hash_indicator(hash_info)
                    if indicator:
                        indicators.append(indicator)
            
            # Get malicious URLs
            url = f"{self.base_url}/url/search"
            params = {
                "query": "positives:>5",
                "limit": self.config.batch_size // 2
            }
            
            response = await self._make_request(url, headers, params)
            
            if "urls" in response:
                for url_info in response["urls"]:
                    indicator = await self._create_url_indicator(url_info)
                    if indicator:
                        indicators.append(indicator)
        
        except Exception as e:
            self.logger.error(f"Failed to get VirusTotal indicators: {e}")
        
        return indicators
    
    async def _create_hash_indicator(self, hash_info: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Create indicator from hash information."""
        try:
            hash_value = hash_info.get("sha256", hash_info.get("md5", ""))
            if not hash_value:
                return None
            
            positives = hash_info.get("positives", 0)
            total = hash_info.get("total", 1)
            confidence = min(positives / total, 1.0) if total > 0 else 0.0
            
            # Determine threat level based on detection ratio
            if confidence >= 0.8:
                threat_level = ThreatLevel.CRITICAL
            elif confidence >= 0.6:
                threat_level = ThreatLevel.HIGH
            elif confidence >= 0.4:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            return ThreatIndicator(
                indicator_id=f"vt_hash_{hash_value}",
                ioc_type=IOCType.FILE_HASH,
                value=hash_value,
                threat_type=ThreatType.MALWARE,
                threat_level=threat_level,
                confidence=confidence,
                source=self.config.feed_name,
                description=f"Malicious file detected by {positives}/{total} engines",
                tags=["malware", "virustotal"],
                raw_data=hash_info
            )
        
        except Exception as e:
            self.logger.error(f"Failed to create hash indicator: {e}")
            return None
    
    async def _create_url_indicator(self, url_info: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Create indicator from URL information."""
        try:
            url = url_info.get("url", "")
            if not url:
                return None
            
            positives = url_info.get("positives", 0)
            total = url_info.get("total", 1)
            confidence = min(positives / total, 1.0) if total > 0 else 0.0
            
            # Determine threat level
            if confidence >= 0.7:
                threat_level = ThreatLevel.HIGH
            elif confidence >= 0.5:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            return ThreatIndicator(
                indicator_id=f"vt_url_{hash(url)}",
                ioc_type=IOCType.URL,
                value=url,
                threat_type=ThreatType.PHISHING,
                threat_level=threat_level,
                confidence=confidence,
                source=self.config.feed_name,
                description=f"Malicious URL detected by {positives}/{total} engines",
                tags=["phishing", "malicious-url", "virustotal"],
                raw_data=url_info
            )
        
        except Exception as e:
            self.logger.error(f"Failed to create URL indicator: {e}")
            return None


class AlienVaultOTXIntegration(ThreatFeedIntegration):
    """AlienVault OTX threat intelligence integration."""
    
    def __init__(self, config: ThreatIntelConfig):
        """Initialize AlienVault OTX integration."""
        super().__init__(config)
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.api_key = config.api_key
    
    async def get_latest_indicators(self) -> List[ThreatIndicator]:
        """Get latest indicators from AlienVault OTX."""
        indicators = []
        
        try:
            # Get recent pulses
            url = f"{self.base_url}/pulses/subscribed"
            headers = {"X-OTX-API-KEY": self.api_key}
            params = {
                "limit": 50,
                "modified_since": (datetime.now() - timedelta(days=7)).isoformat()
            }
            
            response = await self._make_request(url, headers, params)
            
            if "results" in response:
                for pulse in response["results"]:
                    pulse_indicators = await self._process_pulse(pulse)
                    indicators.extend(pulse_indicators)
        
        except Exception as e:
            self.logger.error(f"Failed to get OTX indicators: {e}")
        
        return indicators[:self.config.batch_size]
    
    async def _process_pulse(self, pulse: Dict[str, Any]) -> List[ThreatIndicator]:
        """Process OTX pulse and extract indicators."""
        indicators = []
        
        try:
            pulse_id = pulse.get("id", "")
            pulse_name = pulse.get("name", "")
            pulse_tags = pulse.get("tags", [])
            
            for ioc in pulse.get("indicators", []):
                indicator = await self._create_otx_indicator(ioc, pulse_id, pulse_name, pulse_tags)
                if indicator:
                    indicators.append(indicator)
        
        except Exception as e:
            self.logger.error(f"Failed to process pulse: {e}")
        
        return indicators
    
    async def _create_otx_indicator(self, ioc: Dict[str, Any], pulse_id: str, 
                                  pulse_name: str, pulse_tags: List[str]) -> Optional[ThreatIndicator]:
        """Create indicator from OTX IOC."""
        try:
            ioc_type_map = {
                "IPv4": IOCType.IP_ADDRESS,
                "domain": IOCType.DOMAIN,
                "hostname": IOCType.DOMAIN,
                "URL": IOCType.URL,
                "FileHash-MD5": IOCType.FILE_HASH,
                "FileHash-SHA1": IOCType.FILE_HASH,
                "FileHash-SHA256": IOCType.FILE_HASH,
                "email": IOCType.EMAIL
            }
            
            otx_type = ioc.get("type", "")
            ioc_type = ioc_type_map.get(otx_type)
            
            if not ioc_type:
                return None
            
            value = ioc.get("indicator", "")
            if not value:
                return None
            
            # Determine threat type from tags
            threat_type = ThreatType.UNKNOWN
            if any(tag in pulse_tags for tag in ["malware", "trojan", "virus"]):
                threat_type = ThreatType.MALWARE
            elif any(tag in pulse_tags for tag in ["phishing", "scam"]):
                threat_type = ThreatType.PHISHING
            elif any(tag in pulse_tags for tag in ["botnet", "c2"]):
                threat_type = ThreatType.BOTNET
            
            # Base confidence from OTX
            confidence = 0.8
            
            return ThreatIndicator(
                indicator_id=f"otx_{pulse_id}_{hash(value)}",
                ioc_type=ioc_type,
                value=value,
                threat_type=threat_type,
                threat_level=ThreatLevel.MEDIUM,
                confidence=confidence,
                source=self.config.feed_name,
                description=f"IOC from OTX pulse: {pulse_name}",
                tags=["otx"] + pulse_tags,
                raw_data=ioc
            )
        
        except Exception as e:
            self.logger.error(f"Failed to create OTX indicator: {e}")
            return None


class MISPIntegration(ThreatFeedIntegration):
    """MISP threat intelligence integration."""
    
    def __init__(self, config: ThreatIntelConfig):
        """Initialize MISP integration."""
        super().__init__(config)
        self.base_url = config.api_url.rstrip('/')
        self.api_key = config.api_key
    
    async def get_latest_indicators(self) -> List[ThreatIndicator]:
        """Get latest indicators from MISP."""
        indicators = []
        
        try:
            # Get recent events
            url = f"{self.base_url}/events/restSearch"
            headers = {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            # Search for events from last 7 days
            search_data = {
                "returnFormat": "json",
                "last": "7d",
                "limit": self.config.batch_size,
                "includeEventTags": True,
                "includeContext": True
            }
            
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.post(url, headers=headers, json=search_data) as response:
                response.raise_for_status()
                data = await response.json()
            
            if "response" in data:
                for event in data["response"]:
                    event_indicators = await self._process_misp_event(event)
                    indicators.extend(event_indicators)
        
        except Exception as e:
            self.logger.error(f"Failed to get MISP indicators: {e}")
        
        return indicators
    
    async def _process_misp_event(self, event: Dict[str, Any]) -> List[ThreatIndicator]:
        """Process MISP event and extract indicators."""
        indicators = []
        
        try:
            event_info = event.get("Event", {})
            event_id = event_info.get("id", "")
            event_info_text = event_info.get("info", "")
            event_tags = [tag.get("name", "") for tag in event_info.get("Tag", [])]
            
            for attribute in event_info.get("Attribute", []):
                indicator = await self._create_misp_indicator(attribute, event_id, event_info_text, event_tags)
                if indicator:
                    indicators.append(indicator)
        
        except Exception as e:
            self.logger.error(f"Failed to process MISP event: {e}")
        
        return indicators
    
    async def _create_misp_indicator(self, attribute: Dict[str, Any], event_id: str,
                                   event_info: str, event_tags: List[str]) -> Optional[ThreatIndicator]:
        """Create indicator from MISP attribute."""
        try:
            misp_type_map = {
                "ip-dst": IOCType.IP_ADDRESS,
                "ip-src": IOCType.IP_ADDRESS,
                "domain": IOCType.DOMAIN,
                "hostname": IOCType.DOMAIN,
                "url": IOCType.URL,
                "md5": IOCType.FILE_HASH,
                "sha1": IOCType.FILE_HASH,
                "sha256": IOCType.FILE_HASH,
                "email-src": IOCType.EMAIL,
                "email-dst": IOCType.EMAIL,
                "filename": IOCType.FILE_PATH,
                "regkey": IOCType.REGISTRY_KEY
            }
            
            misp_type = attribute.get("type", "")
            ioc_type = misp_type_map.get(misp_type)
            
            if not ioc_type:
                return None
            
            value = attribute.get("value", "")
            if not value:
                return None
            
            # Determine threat type from category and tags
            category = attribute.get("category", "")
            threat_type = ThreatType.UNKNOWN
            
            if "malware" in category.lower() or any("malware" in tag.lower() for tag in event_tags):
                threat_type = ThreatType.MALWARE
            elif "network" in category.lower():
                threat_type = ThreatType.SUSPICIOUS
            
            # Confidence based on to_ids flag
            to_ids = attribute.get("to_ids", False)
            confidence = 0.9 if to_ids else 0.7
            
            return ThreatIndicator(
                indicator_id=f"misp_{event_id}_{attribute.get('id', hash(value))}",
                ioc_type=ioc_type,
                value=value,
                threat_type=threat_type,
                threat_level=ThreatLevel.MEDIUM,
                confidence=confidence,
                source=self.config.feed_name,
                description=f"MISP attribute from event: {event_info}",
                tags=["misp"] + event_tags,
                raw_data=attribute
            )
        
        except Exception as e:
            self.logger.error(f"Failed to create MISP indicator: {e}")
            return None


class CustomFeedIntegration(ThreatFeedIntegration):
    """Custom threat intelligence feed integration."""
    
    def __init__(self, config: ThreatIntelConfig):
        """Initialize custom feed integration."""
        super().__init__(config)
        self.base_url = config.api_url
        self.headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json"
        }
    
    async def get_latest_indicators(self) -> List[ThreatIndicator]:
        """Get latest indicators from custom feed."""
        indicators = []
        
        try:
            # Assume custom feed has a standard endpoint
            url = f"{self.base_url}/indicators"
            params = {
                "limit": self.config.batch_size,
                "since": (datetime.now() - timedelta(days=1)).isoformat()
            }
            
            response = await self._make_request(url, self.headers, params)
            
            if "indicators" in response:
                for indicator_data in response["indicators"]:
                    indicator = await self._create_custom_indicator(indicator_data)
                    if indicator:
                        indicators.append(indicator)
        
        except Exception as e:
            self.logger.error(f"Failed to get custom feed indicators: {e}")
        
        return indicators
    
    async def _create_custom_indicator(self, data: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Create indicator from custom feed data."""
        try:
            # Assume standard format
            ioc_type_str = data.get("type", "")
            ioc_type = IOCType(ioc_type_str) if ioc_type_str in [t.value for t in IOCType] else None
            
            if not ioc_type:
                return None
            
            value = data.get("value", "")
            if not value:
                return None
            
            threat_type_str = data.get("threat_type", "unknown")
            threat_type = ThreatType(threat_type_str) if threat_type_str in [t.value for t in ThreatType] else ThreatType.UNKNOWN
            
            threat_level_str = data.get("threat_level", "medium")
            threat_level = ThreatLevel(threat_level_str) if threat_level_str in [t.value for t in ThreatLevel] else ThreatLevel.MEDIUM
            
            confidence = float(data.get("confidence", 0.7))
            
            return ThreatIndicator(
                indicator_id=f"custom_{data.get('id', hash(value))}",
                ioc_type=ioc_type,
                value=value,
                threat_type=threat_type,
                threat_level=threat_level,
                confidence=confidence,
                source=self.config.feed_name,
                description=data.get("description", ""),
                tags=data.get("tags", []),
                first_seen=self._parse_timestamp(data.get("first_seen", "")),
                last_seen=self._parse_timestamp(data.get("last_seen", "")),
                raw_data=data
            )
        
        except Exception as e:
            self.logger.error(f"Failed to create custom indicator: {e}")
            return None