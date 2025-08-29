"""Dependency vulnerability scanner using free APIs."""

import asyncio
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from compliance_sentinel.core.interfaces import Severity

logger = logging.getLogger(__name__)


@dataclass
class DependencyVulnerability:
    """Represents a vulnerability in a dependency."""
    package_name: str
    current_version: str
    vulnerability_id: str
    cve_id: Optional[str] = None
    description: str = ""
    severity: Severity = Severity.MEDIUM
    fixed_version: Optional[str] = None
    advisory_url: Optional[str] = None
    cwe_id: Optional[str] = None
    file_path: str = ""
    
    def __post_init__(self):
        """Validate vulnerability data."""
        if not self.package_name:
            raise ValueError("package_name is required")
        if not self.current_version:
            raise ValueError("current_version is required")
        if not self.vulnerability_id:
            raise ValueError("vulnerability_id is required")


class DependencyScanner:
    """Scanner for dependency vulnerabilities using free APIs."""
    
    def __init__(self):
        """Initialize dependency scanner."""
        self.supported_files = {
            'requirements.txt': self._parse_requirements_txt,
            'pyproject.toml': self._parse_pyproject_toml,
            'package.json': self._parse_package_json,
            'Gemfile': self._parse_gemfile,
            'go.mod': self._parse_go_mod,
            'Cargo.toml': self._parse_cargo_toml
        }
        logger.info("Dependency scanner initialized")
    
    async def scan_dependencies(self, file_paths: List[str]) -> List[DependencyVulnerability]:
        """Scan dependency files for vulnerabilities."""
        all_vulnerabilities = []
        
        for file_path in file_paths:
            try:
                vulnerabilities = await self._scan_file(file_path)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
        
        return all_vulnerabilities
    
    async def _scan_file(self, file_path: str) -> List[DependencyVulnerability]:
        """Scan a single dependency file."""
        path = Path(file_path)
        file_name = path.name
        
        if file_name not in self.supported_files:
            logger.debug(f"Unsupported dependency file: {file_name}")
            return []
        
        try:
            # Parse dependencies from file
            dependencies = await self.supported_files[file_name](file_path)
            
            # Check each dependency for vulnerabilities
            vulnerabilities = []
            for dep in dependencies:
                dep_vulns = await self._check_dependency_vulnerabilities(dep, file_path)
                vulnerabilities.extend(dep_vulns)
            
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {file_path}")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scanning dependency file {file_path}: {e}")
            return []
    
    async def _check_dependency_vulnerabilities(
        self, 
        dependency: Dict[str, str], 
        file_path: str
    ) -> List[DependencyVulnerability]:
        """Check a single dependency for vulnerabilities using OSV API."""
        package_name = dependency.get('name', '')
        version = dependency.get('version', '')
        ecosystem = dependency.get('ecosystem', 'PyPI')
        
        if not package_name or not version:
            return []
        
        try:
            # Use OSV API (free) to check for vulnerabilities
            import httpx
            
            query_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                },
                "version": version
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.osv.dev/v1/query",
                    json=query_data,
                    timeout=10.0
                )
                
                if response.status_code != 200:
                    logger.warning(f"OSV API error for {package_name}: {response.status_code}")
                    return []
                
                data = response.json()
                vulnerabilities = []
                
                for vuln in data.get('vulns', []):
                    vulnerability = DependencyVulnerability(
                        package_name=package_name,
                        current_version=version,
                        vulnerability_id=vuln.get('id', ''),
                        cve_id=self._extract_cve_id(vuln),
                        description=vuln.get('summary', ''),
                        severity=self._map_severity(vuln),
                        fixed_version=self._extract_fixed_version(vuln),
                        advisory_url=self._extract_advisory_url(vuln),
                        file_path=file_path
                    )
                    vulnerabilities.append(vulnerability)
                
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Error checking vulnerabilities for {package_name}: {e}")
            return []
    
    def _extract_cve_id(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from vulnerability data."""
        aliases = vuln_data.get('aliases', [])
        for alias in aliases:
            if alias.startswith('CVE-'):
                return alias
        return None
    
    def _map_severity(self, vuln_data: Dict[str, Any]) -> Severity:
        """Map OSV severity to our severity enum."""
        # OSV doesn't always provide severity, so we'll use a heuristic
        severity_info = vuln_data.get('severity', [])
        
        if not severity_info:
            return Severity.MEDIUM
        
        # Look for CVSS score
        for sev in severity_info:
            if sev.get('type') == 'CVSS_V3':
                score = sev.get('score', 0)
                if score >= 9.0:
                    return Severity.CRITICAL
                elif score >= 7.0:
                    return Severity.HIGH
                elif score >= 4.0:
                    return Severity.MEDIUM
                else:
                    return Severity.LOW
        
        return Severity.MEDIUM
    
    def _extract_fixed_version(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract fixed version from vulnerability data."""
        affected = vuln_data.get('affected', [])
        for affect in affected:
            ranges = affect.get('ranges', [])
            for range_info in ranges:
                events = range_info.get('events', [])
                for event in events:
                    if 'fixed' in event:
                        return event['fixed']
        return None
    
    def _extract_advisory_url(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract advisory URL from vulnerability data."""
        references = vuln_data.get('references', [])
        for ref in references:
            if ref.get('type') == 'ADVISORY':
                return ref.get('url')
        
        # Fallback to OSV URL
        vuln_id = vuln_data.get('id', '')
        if vuln_id:
            return f"https://osv.dev/vulnerability/{vuln_id}"
        
        return None
    
    async def _parse_requirements_txt(self, file_path: str) -> List[Dict[str, str]]:
        """Parse requirements.txt file."""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple parsing - handle package==version
                        if '==' in line:
                            name, version = line.split('==', 1)
                            dependencies.append({
                                'name': name.strip(),
                                'version': version.strip(),
                                'ecosystem': 'PyPI'
                            })
                        elif '>=' in line:
                            name = line.split('>=')[0].strip()
                            dependencies.append({
                                'name': name,
                                'version': 'latest',
                                'ecosystem': 'PyPI'
                            })
        except Exception as e:
            logger.error(f"Error parsing requirements.txt: {e}")
        
        return dependencies
    
    async def _parse_pyproject_toml(self, file_path: str) -> List[Dict[str, str]]:
        """Parse pyproject.toml file."""
        dependencies = []
        
        try:
            import tomli
            with open(file_path, 'rb') as f:
                data = tomli.load(f)
            
            # Check different sections for dependencies
            deps = data.get('project', {}).get('dependencies', [])
            for dep in deps:
                if isinstance(dep, str):
                    # Parse dependency string
                    if '==' in dep:
                        name, version = dep.split('==', 1)
                        dependencies.append({
                            'name': name.strip(),
                            'version': version.strip(),
                            'ecosystem': 'PyPI'
                        })
        except ImportError:
            logger.warning("tomli not available, skipping pyproject.toml parsing")
        except Exception as e:
            logger.error(f"Error parsing pyproject.toml: {e}")
        
        return dependencies
    
    async def _parse_package_json(self, file_path: str) -> List[Dict[str, str]]:
        """Parse package.json file."""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Parse dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                deps = data.get(dep_type, {})
                for name, version in deps.items():
                    dependencies.append({
                        'name': name,
                        'version': version.lstrip('^~'),  # Remove version prefixes
                        'ecosystem': 'npm'
                    })
        except Exception as e:
            logger.error(f"Error parsing package.json: {e}")
        
        return dependencies
    
    async def _parse_gemfile(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Gemfile (Ruby)."""
        # Simplified parsing - would need proper Ruby parser for production
        return []
    
    async def _parse_go_mod(self, file_path: str) -> List[Dict[str, str]]:
        """Parse go.mod file."""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('require '):
                        # Simple parsing: require github.com/package v1.2.3
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[1]
                            version = parts[2]
                            dependencies.append({
                                'name': name,
                                'version': version,
                                'ecosystem': 'Go'
                            })
        except Exception as e:
            logger.error(f"Error parsing go.mod: {e}")
        
        return dependencies
    
    async def _parse_cargo_toml(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Cargo.toml file."""
        dependencies = []
        
        try:
            import tomli
            with open(file_path, 'rb') as f:
                data = tomli.load(f)
            
            deps = data.get('dependencies', {})
            for name, version_info in deps.items():
                if isinstance(version_info, str):
                    version = version_info
                elif isinstance(version_info, dict):
                    version = version_info.get('version', 'latest')
                else:
                    version = 'latest'
                
                dependencies.append({
                    'name': name,
                    'version': version,
                    'ecosystem': 'crates.io'
                })
        except ImportError:
            logger.warning("tomli not available, skipping Cargo.toml parsing")
        except Exception as e:
            logger.error(f"Error parsing Cargo.toml: {e}")
        
        return dependencies