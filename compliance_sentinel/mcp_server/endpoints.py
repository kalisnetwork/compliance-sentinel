"""MCP server endpoint implementations for vulnerability and compliance data."""

import asyncio
import json
import os
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import logging
import httpx
from urllib.parse import quote

from compliance_sentinel.utils.cache import VulnerabilityCacheManager, CacheManager
from compliance_sentinel.utils.error_handler import (
    async_retry_with_backoff,
    RetryStrategy,
    get_global_error_handler
)
from compliance_sentinel.core.validation import InputSanitizer
from compliance_sentinel.config.dynamic_config import get_dynamic_config_manager


logger = logging.getLogger(__name__)


class VulnerabilityEndpoints:
    """Handles vulnerability-related API endpoints with dynamic configuration."""
    
    def __init__(self, http_client: httpx.AsyncClient, vuln_cache: VulnerabilityCacheManager):
        self.http_client = http_client
        self.vuln_cache = vuln_cache
        self.error_handler = get_global_error_handler()
        self.config_manager = get_dynamic_config_manager()
        
        # Load configuration with environment variable support
        self._load_configuration()
        
        # Rate limiting state
        self.last_nvd_request = datetime.min
        self.last_cve_request = datetime.min
    
    def _load_configuration(self) -> None:
        """Load configuration from environment variables and config manager."""
        # API endpoints with environment variable overrides
        self.nvd_base_url = os.getenv(
            "MCP_NVD_BASE_URL", 
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.cve_base_url = os.getenv(
            "MCP_CVE_BASE_URL", 
            "https://cve.circl.lu/api"
        )
        self.osv_base_url = os.getenv(
            "MCP_OSV_BASE_URL", 
            "https://api.osv.dev/v1"
        )
        
        # Rate limiting configuration
        self.nvd_delay = float(os.getenv("MCP_NVD_DELAY_SECONDS", "6.0"))
        self.cve_delay = float(os.getenv("MCP_CVE_DELAY_SECONDS", "1.0"))
        
        # Request timeout configuration
        self.request_timeout = float(os.getenv("MCP_REQUEST_TIMEOUT_SECONDS", "30.0"))
        
        # Default limits
        self.default_search_limit = int(os.getenv("MCP_DEFAULT_SEARCH_LIMIT", "10"))
        self.default_latest_limit = int(os.getenv("MCP_DEFAULT_LATEST_LIMIT", "20"))
        
        # Retry configuration
        self.max_retry_attempts = int(os.getenv("MCP_MAX_RETRY_ATTEMPTS", "3"))
        self.retry_base_delay = float(os.getenv("MCP_RETRY_BASE_DELAY", "2.0"))
        
        logger.info(f"MCP endpoints configured with NVD: {self.nvd_base_url}, CVE: {self.cve_base_url}")
    
    def reload_configuration(self) -> None:
        """Reload configuration from environment variables."""
        logger.info("Reloading MCP endpoint configuration")
        self._load_configuration()
    
    async def search_vulnerabilities(
        self, 
        query: str, 
        limit: Optional[int] = None, 
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Search for vulnerabilities using multiple sources with dynamic configuration."""
        # Use configured default limit if not provided
        if limit is None:
            limit = self.default_search_limit
        
        # Sanitize input
        query = InputSanitizer.sanitize_user_input(query, max_length=100)
        
        # Check cache first with configurable TTL
        cache_ttl = int(os.getenv("MCP_CACHE_TTL_SECONDS", "1800"))  # 30 minutes default
        cache_key = f"vuln_search:{query}:{limit}:{offset}"
        cached_result = self.vuln_cache.cache.get(cache_key)
        if cached_result:
            logger.debug(f"Using cached vulnerability search results for: {query}")
            return cached_result
        
        try:
            # Search in parallel from multiple sources with retry logic
            retry_strategy = RetryStrategy(
                max_attempts=self.max_retry_attempts, 
                base_delay=self.retry_base_delay
            )
            
            async def search_with_retry(search_func, *args):
                return await async_retry_with_backoff(
                    strategy=retry_strategy,
                    exceptions=(httpx.TimeoutException, httpx.ConnectError)
                )(search_func)(*args)
            
            tasks = [
                search_with_retry(self._search_nvd, query, limit),
                search_with_retry(self._search_cve_circl, query, limit),
                search_with_retry(self._search_osv, query, limit)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine and deduplicate results
            combined_results = []
            for result in results:
                if isinstance(result, list):
                    combined_results.extend(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Vulnerability search source failed: {result}")
            
            # Deduplicate by CVE ID
            seen_cves = set()
            deduplicated = []
            for vuln in combined_results:
                cve_id = vuln.get('cve_id') or vuln.get('id')
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    deduplicated.append(vuln)
            
            # Apply pagination
            paginated_results = deduplicated[offset:offset + limit]
            
            # Cache results with configurable TTL
            self.vuln_cache.cache.set(cache_key, paginated_results, ttl=cache_ttl)
            
            logger.info(f"Vulnerability search for '{query}' returned {len(paginated_results)} results")
            return paginated_results
            
        except Exception as e:
            logger.error(f"Vulnerability search failed for query '{query}': {e}")
            self.error_handler.handle_external_service_error("vulnerability_search", e)
            return []
    
    async def _search_nvd(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Search NVD database with dynamic configuration."""
        await self._respect_nvd_rate_limit()
        
        try:
            params = {
                "keywordSearch": query,
                "resultsPerPage": min(limit, 20),  # NVD max is 2000, but we limit for performance
                "startIndex": 0
            }
            
            response = await self.http_client.get(
                self.nvd_base_url,
                params=params,
                timeout=self.request_timeout
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Transform NVD format to our standard format
            results = []
            for vuln_data in vulnerabilities:
                cve = vuln_data.get("cve", {})
                cve_id = cve.get("id")
                
                if not cve_id:
                    continue
                
                # Extract description
                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity = "UNKNOWN"
                
                for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_type in metrics and metrics[metric_type]:
                        metric = metrics[metric_type][0]  # Take first metric
                        cvss_data = metric.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        break
                
                # Extract published date
                published = cve.get("published", "")
                
                results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published_date": published,
                    "source": "NVD"
                })
            
            return results
            
        except Exception as e:
            logger.warning(f"NVD search failed: {e}")
            return []
    
    async def _search_cve_circl(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Search CVE CIRCL database."""
        await self._respect_cve_rate_limit()
        
        try:
            # CVE CIRCL has a search endpoint
            url = f"{self.cve_base_url}/search/{quote(query)}"
            
            response = await self.http_client.get(url, timeout=self.request_timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Transform CVE CIRCL format
            results = []
            if isinstance(data, list):
                for cve_data in data[:limit]:
                    cve_id = cve_data.get("id")
                    if not cve_id:
                        continue
                    
                    results.append({
                        "cve_id": cve_id,
                        "description": cve_data.get("summary", ""),
                        "cvss_score": cve_data.get("cvss"),
                        "severity": self._cvss_to_severity(cve_data.get("cvss")),
                        "published_date": cve_data.get("Published", ""),
                        "source": "CVE CIRCL"
                    })
            
            return results
            
        except Exception as e:
            logger.warning(f"CVE CIRCL search failed: {e}")
            return []
    
    async def _search_osv(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Search OSV database."""
        try:
            # OSV query format
            query_data = {
                "query": query,
                "page_token": ""
            }
            
            response = await self.http_client.post(
                f"{self.osv_base_url}/query",
                json=query_data,
                timeout=self.request_timeout
            )
            response.raise_for_status()
            
            data = response.json()
            vulns = data.get("vulns", [])
            
            # Transform OSV format
            results = []
            for vuln_data in vulns[:limit]:
                vuln_id = vuln_data.get("id")
                if not vuln_id:
                    continue
                
                # Extract severity
                severity_data = vuln_data.get("database_specific", {}).get("severity")
                cvss_score = None
                severity = "UNKNOWN"
                
                if severity_data:
                    if isinstance(severity_data, list) and severity_data:
                        severity_info = severity_data[0]
                        cvss_score = severity_info.get("score")
                        severity = severity_info.get("type", "UNKNOWN")
                
                results.append({
                    "cve_id": vuln_id,
                    "description": vuln_data.get("summary", ""),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published_date": vuln_data.get("published", ""),
                    "source": "OSV"
                })
            
            return results
            
        except Exception as e:
            logger.warning(f"OSV search failed: {e}")
            return []
    
    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific CVE."""
        # Check cache first
        cached_cve = self.vuln_cache.get_cve_data(cve_id)
        if cached_cve:
            logger.debug(f"Using cached CVE data for: {cve_id}")
            return cached_cve
        
        try:
            # Try NVD first (most comprehensive)
            cve_details = await self._get_cve_from_nvd(cve_id)
            
            if not cve_details:
                # Fallback to CVE CIRCL
                cve_details = await self._get_cve_from_circl(cve_id)
            
            if cve_details:
                # Cache the result
                self.vuln_cache.cache_cve_data(cve_id, cve_details)
                logger.info(f"Retrieved CVE details for: {cve_id}")
            
            return cve_details
            
        except Exception as e:
            logger.error(f"Failed to get CVE details for {cve_id}: {e}")
            self.error_handler.handle_external_service_error("cve_lookup", e)
            return None
    
    async def _get_cve_from_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE details from NVD."""
        await self._respect_nvd_rate_limit()
        
        try:
            params = {"cveId": cve_id}
            
            response = await self.http_client.get(
                self.nvd_base_url,
                params=params,
                timeout=self.request_timeout
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                return None
            
            vuln_data = vulnerabilities[0]
            cve = vuln_data.get("cve", {})
            
            # Extract comprehensive details
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CVSS metrics
            metrics = cve.get("metrics", {})
            cvss_details = {}
            
            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in metrics and metrics[metric_type]:
                    metric = metrics[metric_type][0]
                    cvss_data = metric.get("cvssData", {})
                    cvss_details[metric_type] = {
                        "baseScore": cvss_data.get("baseScore"),
                        "baseSeverity": cvss_data.get("baseSeverity"),
                        "vectorString": cvss_data.get("vectorString"),
                        "exploitabilityScore": cvss_data.get("exploitabilityScore"),
                        "impactScore": cvss_data.get("impactScore")
                    }
            
            # Extract references
            references = []
            for ref in cve.get("references", []):
                references.append({
                    "url": ref.get("url"),
                    "source": ref.get("source"),
                    "tags": ref.get("tags", [])
                })
            
            # Extract weaknesses (CWE)
            weaknesses = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append({
                            "cwe_id": desc.get("value"),
                            "description": desc.get("value")
                        })
            
            # Extract configurations (affected products)
            configurations = []
            config_data = cve.get("configurations", [])
            for config in config_data:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            configurations.append({
                                "cpe23Uri": cpe_match.get("criteria"),
                                "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                                "versionEndExcluding": cpe_match.get("versionEndExcluding")
                            })
            
            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_metrics": cvss_details,
                "published_date": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "references": references,
                "weaknesses": weaknesses,
                "configurations": configurations,
                "source": "NVD"
            }
            
        except Exception as e:
            logger.warning(f"NVD CVE lookup failed for {cve_id}: {e}")
            return None
    
    async def _get_cve_from_circl(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE details from CVE CIRCL."""
        await self._respect_cve_rate_limit()
        
        try:
            url = f"{self.cve_base_url}/cve/{cve_id}"
            
            response = await self.http_client.get(url, timeout=self.request_timeout)
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "cve_id": cve_id,
                "description": data.get("summary", ""),
                "cvss_score": data.get("cvss"),
                "severity": self._cvss_to_severity(data.get("cvss")),
                "published_date": data.get("Published"),
                "last_modified": data.get("Modified"),
                "references": [{"url": ref} for ref in data.get("references", [])],
                "source": "CVE CIRCL"
            }
            
        except Exception as e:
            logger.warning(f"CVE CIRCL lookup failed for {cve_id}: {e}")
            return None
    
    async def check_package_vulnerabilities(
        self, 
        package_name: str, 
        package_version: str, 
        ecosystem: str = "pypi"
    ) -> List[Dict[str, Any]]:
        """Check vulnerabilities for a specific package."""
        # Check cache first
        cached_vulns = self.vuln_cache.get_vulnerability_scan(package_name, package_version)
        if cached_vulns:
            logger.debug(f"Using cached vulnerability data for {package_name}:{package_version}")
            return cached_vulns
        
        try:
            # Use OSV API for package-specific queries
            query_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem.upper()
                },
                "version": package_version
            }
            
            response = await self.http_client.post(
                f"{self.osv_base_url}/query",
                json=query_data,
                timeout=self.request_timeout
            )
            response.raise_for_status()
            
            data = response.json()
            vulns = data.get("vulns", [])
            
            # Transform to our format
            vulnerabilities = []
            for vuln in vulns:
                vuln_id = vuln.get("id")
                if not vuln_id:
                    continue
                
                # Extract affected ranges
                affected_ranges = []
                for affected in vuln.get("affected", []):
                    package_info = affected.get("package", {})
                    if package_info.get("name") == package_name:
                        for range_info in affected.get("ranges", []):
                            affected_ranges.append({
                                "type": range_info.get("type"),
                                "events": range_info.get("events", [])
                            })
                
                vulnerabilities.append({
                    "id": vuln_id,
                    "summary": vuln.get("summary", ""),
                    "details": vuln.get("details", ""),
                    "severity": vuln.get("database_specific", {}).get("severity"),
                    "published": vuln.get("published"),
                    "modified": vuln.get("modified"),
                    "affected_ranges": affected_ranges,
                    "references": [ref.get("url") for ref in vuln.get("references", [])],
                    "source": "OSV"
                })
            
            # Cache results
            self.vuln_cache.cache_vulnerability_scan(package_name, package_version, vulnerabilities)
            
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {package_name}:{package_version}")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Package vulnerability check failed for {package_name}:{package_version}: {e}")
            self.error_handler.handle_external_service_error("package_vuln_check", e)
            return []
    
    async def get_latest_vulnerabilities(
        self, 
        limit: Optional[int] = None, 
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get latest vulnerabilities with dynamic configuration."""
        # Use configured default limit if not provided
        if limit is None:
            limit = self.default_latest_limit
        
        # Check cache first with configurable TTL
        cache_ttl = int(os.getenv("MCP_CACHE_TTL_SECONDS", "1800"))  # 30 minutes default
        cache_key = f"latest_vulns:{limit}:{severity or 'all'}"
        cached_result = self.vuln_cache.cache.get(cache_key)
        if cached_result:
            logger.debug("Using cached latest vulnerabilities")
            return cached_result
        
        try:
            # Get latest from CVE CIRCL (has a convenient endpoint)
            await self._respect_cve_rate_limit()
            
            url = f"{self.cve_base_url}/last/{limit}"
            
            response = await self.http_client.get(url, timeout=self.request_timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Transform and filter by severity if specified
            vulnerabilities = []
            for cve_data in data:
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                
                cvss_score = cve_data.get("cvss")
                vuln_severity = self._cvss_to_severity(cvss_score)
                
                # Filter by severity if specified
                if severity and vuln_severity.lower() != severity.lower():
                    continue
                
                vulnerabilities.append({
                    "cve_id": cve_id,
                    "description": cve_data.get("summary", ""),
                    "cvss_score": cvss_score,
                    "severity": vuln_severity,
                    "published_date": cve_data.get("Published"),
                    "source": "CVE CIRCL"
                })
            
            # Cache results with configurable TTL
            self.vuln_cache.cache.set(cache_key, vulnerabilities, ttl=cache_ttl)
            
            logger.info(f"Retrieved {len(vulnerabilities)} latest vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Failed to get latest vulnerabilities: {e}")
            self.error_handler.handle_external_service_error("latest_vulns", e)
            return []
    
    async def _respect_nvd_rate_limit(self) -> None:
        """Respect NVD API rate limiting."""
        now = datetime.utcnow()
        time_since_last = (now - self.last_nvd_request).total_seconds()
        
        if time_since_last < self.nvd_delay:
            sleep_time = self.nvd_delay - time_since_last
            logger.debug(f"Rate limiting NVD request, sleeping for {sleep_time:.2f} seconds")
            await asyncio.sleep(sleep_time)
        
        self.last_nvd_request = datetime.utcnow()
    
    async def _respect_cve_rate_limit(self) -> None:
        """Respect CVE CIRCL API rate limiting."""
        now = datetime.utcnow()
        time_since_last = (now - self.last_cve_request).total_seconds()
        
        if time_since_last < self.cve_delay:
            sleep_time = self.cve_delay - time_since_last
            logger.debug(f"Rate limiting CVE request, sleeping for {sleep_time:.2f} seconds")
            await asyncio.sleep(sleep_time)
        
        self.last_cve_request = datetime.utcnow()
    
    def _cvss_to_severity(self, cvss_score: Optional[float]) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score is None:
            return "UNKNOWN"
        
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"


class ComplianceEndpoints:
    """Handles compliance-related API endpoints with dynamic configuration."""
    
    def __init__(self, http_client: httpx.AsyncClient, cache: CacheManager):
        self.http_client = http_client
        self.cache = cache
        self.error_handler = get_global_error_handler()
        self.config_manager = get_dynamic_config_manager()
        
        # Load configuration
        self._load_configuration()
    
    def _load_configuration(self) -> None:
        """Load configuration from environment variables."""
        # Cache TTL configuration
        self.compliance_cache_ttl = int(os.getenv("MCP_COMPLIANCE_CACHE_TTL_SECONDS", "3600"))  # 1 hour default
        self.requirements_cache_ttl = int(os.getenv("MCP_REQUIREMENTS_CACHE_TTL_SECONDS", "86400"))  # 24 hours default
        
        # Request timeout configuration
        self.request_timeout = float(os.getenv("MCP_REQUEST_TIMEOUT_SECONDS", "30.0"))
        
        logger.info("Compliance endpoints configured with dynamic settings")
    
    def reload_configuration(self) -> None:
        """Reload configuration from environment variables."""
        logger.info("Reloading compliance endpoint configuration")
        self._load_configuration()
        
        # Compliance frameworks data
        self.frameworks = {
            "owasp-top-10": {
                "name": "OWASP Top 10",
                "version": "2021",
                "description": "The OWASP Top 10 is a standard awareness document for developers and web application security."
            },
            "cwe-top-25": {
                "name": "CWE Top 25",
                "version": "2023",
                "description": "The CWE Top 25 Most Dangerous Software Weaknesses."
            },
            "nist-csf": {
                "name": "NIST Cybersecurity Framework",
                "version": "1.1",
                "description": "The NIST Cybersecurity Framework provides a policy framework of computer security guidance."
            },
            "iso-27001": {
                "name": "ISO/IEC 27001",
                "version": "2013",
                "description": "Information security management systems — Requirements."
            },
            "soc2": {
                "name": "SOC 2",
                "version": "2017",
                "description": "Service Organization Control 2 - Security, Availability, Processing Integrity, Confidentiality, Privacy."
            }
        }
    
    async def check_compliance(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check compliance against regulatory requirements."""
        framework = compliance_data.get("framework", "owasp-top-10")
        code_patterns = compliance_data.get("code_patterns", [])
        vulnerabilities = compliance_data.get("vulnerabilities", [])
        
        # Check cache first
        cache_key = f"compliance_check:{framework}:{len(code_patterns)}:{len(vulnerabilities)}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            logger.debug(f"Using cached compliance check for framework: {framework}")
            return cached_result
        
        try:
            # Get framework requirements
            requirements = await self.get_compliance_requirements(framework)
            
            # Analyze compliance
            compliance_results = {
                "framework": framework,
                "overall_score": 0.0,
                "requirements_checked": len(requirements),
                "requirements_passed": 0,
                "requirements_failed": 0,
                "detailed_results": []
            }
            
            for requirement in requirements:
                req_id = requirement.get("id")
                req_name = requirement.get("name")
                req_patterns = requirement.get("patterns", [])
                
                # Check if any code patterns match this requirement
                violations = []
                for pattern in code_patterns:
                    for req_pattern in req_patterns:
                        if req_pattern.lower() in pattern.get("description", "").lower():
                            violations.append(pattern)
                
                # Check if any vulnerabilities relate to this requirement
                related_vulns = []
                for vuln in vulnerabilities:
                    vuln_categories = vuln.get("categories", [])
                    req_categories = requirement.get("categories", [])
                    
                    if any(cat in vuln_categories for cat in req_categories):
                        related_vulns.append(vuln)
                
                # Determine compliance status
                passed = len(violations) == 0 and len(related_vulns) == 0
                
                if passed:
                    compliance_results["requirements_passed"] += 1
                else:
                    compliance_results["requirements_failed"] += 1
                
                compliance_results["detailed_results"].append({
                    "requirement_id": req_id,
                    "requirement_name": req_name,
                    "passed": passed,
                    "violations": violations,
                    "related_vulnerabilities": related_vulns,
                    "recommendations": requirement.get("recommendations", [])
                })
            
            # Calculate overall score
            total_requirements = compliance_results["requirements_checked"]
            if total_requirements > 0:
                compliance_results["overall_score"] = (
                    compliance_results["requirements_passed"] / total_requirements
                ) * 100
            
            # Cache results with configurable TTL
            self.cache.set(cache_key, compliance_results, ttl=self.compliance_cache_ttl)
            
            logger.info(f"Compliance check completed for {framework}: {compliance_results['overall_score']:.1f}% compliant")
            return compliance_results
            
        except Exception as e:
            logger.error(f"Compliance check failed for framework {framework}: {e}")
            self.error_handler.handle_analysis_error(e, f"compliance_check:{framework}")
            return {"error": "Compliance check failed", "framework": framework}
    
    async def get_compliance_frameworks(self) -> List[Dict[str, Any]]:
        """Get available compliance frameworks."""
        return list(self.frameworks.values())
    
    async def get_compliance_requirements(self, framework: str) -> List[Dict[str, Any]]:
        """Get requirements for a specific compliance framework."""
        # Check cache first
        cache_key = f"compliance_requirements:{framework}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            logger.debug(f"Using cached requirements for framework: {framework}")
            return cached_result
        
        try:
            requirements = []
            
            if framework == "owasp-top-10":
                requirements = self._get_owasp_top_10_requirements()
            elif framework == "cwe-top-25":
                requirements = self._get_cwe_top_25_requirements()
            elif framework == "nist-csf":
                requirements = self._get_nist_csf_requirements()
            elif framework == "iso-27001":
                requirements = self._get_iso_27001_requirements()
            elif framework == "soc2":
                requirements = self._get_soc2_requirements()
            else:
                raise ValueError(f"Unknown compliance framework: {framework}")
            
            # Cache requirements with configurable TTL
            self.cache.set(cache_key, requirements, ttl=self.requirements_cache_ttl)
            
            logger.info(f"Retrieved {len(requirements)} requirements for framework: {framework}")
            return requirements
            
        except Exception as e:
            logger.error(f"Failed to get requirements for framework {framework}: {e}")
            return []
    
    def _get_owasp_top_10_requirements(self) -> List[Dict[str, Any]]:
        """Get OWASP Top 10 2021 requirements."""
        return [
            {
                "id": "A01:2021",
                "name": "Broken Access Control",
                "patterns": ["access control", "authorization", "privilege escalation"],
                "categories": ["authentication", "authorization"],
                "recommendations": [
                    "Implement proper access control mechanisms",
                    "Use principle of least privilege",
                    "Validate permissions on server-side"
                ]
            },
            {
                "id": "A02:2021",
                "name": "Cryptographic Failures",
                "patterns": ["weak crypto", "insecure hash", "ssl", "tls"],
                "categories": ["insecure_crypto"],
                "recommendations": [
                    "Use strong encryption algorithms",
                    "Implement proper key management",
                    "Enable SSL/TLS verification"
                ]
            },
            {
                "id": "A03:2021",
                "name": "Injection",
                "patterns": ["sql injection", "command injection", "xss"],
                "categories": ["sql_injection", "xss", "input_validation"],
                "recommendations": [
                    "Use parameterized queries",
                    "Validate and sanitize all inputs",
                    "Use safe APIs and frameworks"
                ]
            },
            {
                "id": "A04:2021",
                "name": "Insecure Design",
                "patterns": ["insecure design", "threat modeling"],
                "categories": ["input_validation"],
                "recommendations": [
                    "Implement secure design patterns",
                    "Perform threat modeling",
                    "Use security by design principles"
                ]
            },
            {
                "id": "A05:2021",
                "name": "Security Misconfiguration",
                "patterns": ["misconfiguration", "default credentials"],
                "categories": ["hardcoded_secrets"],
                "recommendations": [
                    "Remove default credentials",
                    "Implement secure configuration management",
                    "Regular security configuration reviews"
                ]
            }
        ]
    
    def _get_cwe_top_25_requirements(self) -> List[Dict[str, Any]]:
        """Get CWE Top 25 requirements."""
        return [
            {
                "id": "CWE-79",
                "name": "Cross-site Scripting",
                "patterns": ["xss", "cross-site scripting"],
                "categories": ["xss"],
                "recommendations": [
                    "Sanitize all user inputs",
                    "Use Content Security Policy",
                    "Encode output data"
                ]
            },
            {
                "id": "CWE-89",
                "name": "SQL Injection",
                "patterns": ["sql injection", "sqli"],
                "categories": ["sql_injection"],
                "recommendations": [
                    "Use parameterized queries",
                    "Validate input data",
                    "Use stored procedures"
                ]
            },
            {
                "id": "CWE-20",
                "name": "Improper Input Validation",
                "patterns": ["input validation", "unvalidated input"],
                "categories": ["input_validation"],
                "recommendations": [
                    "Validate all inputs",
                    "Use whitelist validation",
                    "Implement proper error handling"
                ]
            }
        ]
    
    def _get_nist_csf_requirements(self) -> List[Dict[str, Any]]:
        """Get NIST Cybersecurity Framework requirements."""
        return [
            {
                "id": "PR.AC-1",
                "name": "Access Control Policy",
                "patterns": ["access control", "authentication"],
                "categories": ["authentication", "authorization"],
                "recommendations": [
                    "Implement identity and access management",
                    "Use multi-factor authentication",
                    "Regular access reviews"
                ]
            },
            {
                "id": "PR.DS-1",
                "name": "Data Protection",
                "patterns": ["data protection", "encryption"],
                "categories": ["insecure_crypto"],
                "recommendations": [
                    "Encrypt sensitive data",
                    "Implement data classification",
                    "Use secure data transmission"
                ]
            }
        ]
    
    def _get_iso_27001_requirements(self) -> List[Dict[str, Any]]:
        """Get ISO 27001 requirements."""
        return [
            {
                "id": "A.9.1.1",
                "name": "Access Control Policy",
                "patterns": ["access control", "authorization"],
                "categories": ["authentication", "authorization"],
                "recommendations": [
                    "Establish access control policy",
                    "Implement user access management",
                    "Regular access reviews"
                ]
            },
            {
                "id": "A.10.1.1",
                "name": "Cryptographic Controls",
                "patterns": ["cryptography", "encryption"],
                "categories": ["insecure_crypto"],
                "recommendations": [
                    "Use approved cryptographic algorithms",
                    "Implement key management",
                    "Regular cryptographic reviews"
                ]
            }
        ]
    
    def _get_soc2_requirements(self) -> List[Dict[str, Any]]:
        """Get SOC 2 requirements."""
        return [
            {
                "id": "CC6.1",
                "name": "Logical Access Controls",
                "patterns": ["access control", "authentication"],
                "categories": ["authentication", "authorization"],
                "recommendations": [
                    "Implement logical access controls",
                    "Use strong authentication",
                    "Monitor access activities"
                ]
            },
            {
                "id": "CC6.7",
                "name": "Data Transmission",
                "patterns": ["data transmission", "encryption"],
                "categories": ["insecure_crypto"],
                "recommendations": [
                    "Encrypt data in transmission",
                    "Use secure communication protocols",
                    "Implement network security controls"
                ]
            }
        ]