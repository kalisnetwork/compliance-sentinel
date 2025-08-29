"""Custom MCP server for external vulnerability intelligence integration."""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel, Field

from compliance_sentinel.models.config import MCPServerConfig
from compliance_sentinel.utils.cache import get_global_cache, VulnerabilityCacheManager
from compliance_sentinel.utils.error_handler import (
    get_global_error_handler,
    async_retry_with_backoff,
    RetryStrategy
)
from compliance_sentinel.core.validation import InputSanitizer
from compliance_sentinel.mcp_server.endpoints import VulnerabilityEndpoints, ComplianceEndpoints
from compliance_sentinel.mcp_server.rate_limiter import RateLimiter
from compliance_sentinel.mcp_server.auth import AuthManager


logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer(auto_error=False)


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = "healthy"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str = "0.1.0"
    uptime_seconds: float
    cache_stats: Dict[str, Any]
    external_services: Dict[str, str]


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Compliance Sentinel MCP Server")
    
    # Initialize external service connections
    app.state.start_time = datetime.utcnow()
    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0),
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=100)
    )
    
    # Initialize cache and rate limiter
    app.state.cache = get_global_cache()
    app.state.vuln_cache = VulnerabilityCacheManager(app.state.cache)
    app.state.rate_limiter = RateLimiter()
    app.state.auth_manager = AuthManager()
    
    # Initialize endpoints
    app.state.vulnerability_endpoints = VulnerabilityEndpoints(
        app.state.http_client,
        app.state.vuln_cache
    )
    app.state.compliance_endpoints = ComplianceEndpoints(
        app.state.http_client,
        app.state.cache
    )
    
    # Test external service connectivity
    await _test_external_services(app)
    
    logger.info("MCP Server startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down MCP Server")
    await app.state.http_client.aclose()
    logger.info("MCP Server shutdown complete")


async def _test_external_services(app: FastAPI) -> None:
    """Test connectivity to external services."""
    services_status = {}
    
    # Test NVD API
    try:
        response = await app.state.http_client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"resultsPerPage": 1}
        )
        services_status["nvd"] = "healthy" if response.status_code == 200 else "degraded"
    except Exception as e:
        logger.warning(f"NVD API test failed: {e}")
        services_status["nvd"] = "unhealthy"
    
    # Test CVE API
    try:
        response = await app.state.http_client.get("https://cve.circl.lu/api/last")
        services_status["cve"] = "healthy" if response.status_code == 200 else "degraded"
    except Exception as e:
        logger.warning(f"CVE API test failed: {e}")
        services_status["cve"] = "unhealthy"
    
    app.state.external_services = services_status
    logger.info(f"External services status: {services_status}")


def create_app(config: Optional[MCPServerConfig] = None) -> FastAPI:
    """Create and configure FastAPI application."""
    if config is None:
        config = MCPServerConfig()
    
    app = FastAPI(
        title="Compliance Sentinel MCP Server",
        description="Model Context Protocol server for external vulnerability intelligence",
        version="0.1.0",
        docs_url="/docs" if not config.api_key_required else None,
        redoc_url="/redoc" if not config.api_key_required else None,
        lifespan=lifespan
    )
    
    # Store config in app state
    app.state.config = config
    
    # Add middleware
    _add_middleware(app, config)
    
    # Add routes
    _add_routes(app)
    
    # Add exception handlers
    _add_exception_handlers(app)
    
    return app


def _add_middleware(app: FastAPI, config: MCPServerConfig) -> None:
    """Add middleware to the FastAPI application."""
    # CORS middleware
    if config.enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["*"],
        )
    
    # Trusted host middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", config.host]
    )


def _add_routes(app: FastAPI) -> None:
    """Add routes to the FastAPI application."""
    
    @app.get("/health", response_model=HealthResponse)
    async def health_check(request: Request) -> HealthResponse:
        """Health check endpoint."""
        uptime = (datetime.utcnow() - request.app.state.start_time).total_seconds()
        
        return HealthResponse(
            uptime_seconds=uptime,
            cache_stats=request.app.state.cache.get_stats(),
            external_services=getattr(request.app.state, 'external_services', {})
        )
    
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "service": "Compliance Sentinel MCP Server",
            "version": "0.1.0",
            "status": "operational",
            "endpoints": {
                "health": "/health",
                "vulnerabilities": "/vulnerabilities/*",
                "compliance": "/compliance/*",
                "docs": "/docs"
            }
        }
    
    # Vulnerability endpoints
    @app.get("/vulnerabilities/search")
    async def search_vulnerabilities(
        query: str,
        limit: int = 10,
        offset: int = 0,
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Search for vulnerabilities."""
        await _check_auth_and_rate_limit(request, credentials)
        
        try:
            results = await request.app.state.vulnerability_endpoints.search_vulnerabilities(
                query, limit, offset
            )
            return {"results": results, "query": query, "limit": limit, "offset": offset}
        except Exception as e:
            logger.error(f"Vulnerability search failed: {e}")
            raise HTTPException(status_code=500, detail="Vulnerability search failed")
    
    @app.get("/vulnerabilities/cve/{cve_id}")
    async def get_cve_details(
        cve_id: str,
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Get detailed information about a specific CVE."""
        await _check_auth_and_rate_limit(request, credentials)
        
        # Validate CVE ID format
        if not cve_id.startswith("CVE-"):
            raise HTTPException(status_code=400, detail="Invalid CVE ID format")
        
        try:
            cve_details = await request.app.state.vulnerability_endpoints.get_cve_details(cve_id)
            if not cve_details:
                raise HTTPException(status_code=404, detail="CVE not found")
            return cve_details
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"CVE lookup failed for {cve_id}: {e}")
            raise HTTPException(status_code=500, detail="CVE lookup failed")
    
    @app.post("/vulnerabilities/package/check")
    async def check_package_vulnerabilities(
        package_data: Dict[str, Any],
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Check vulnerabilities for a specific package."""
        await _check_auth_and_rate_limit(request, credentials)
        
        # Validate input
        if "name" not in package_data or "version" not in package_data:
            raise HTTPException(
                status_code=400, 
                detail="Package name and version are required"
            )
        
        package_name = InputSanitizer.sanitize_user_input(package_data["name"])
        package_version = InputSanitizer.sanitize_user_input(package_data["version"])
        ecosystem = package_data.get("ecosystem", "pypi")
        
        try:
            vulnerabilities = await request.app.state.vulnerability_endpoints.check_package_vulnerabilities(
                package_name, package_version, ecosystem
            )
            return {
                "package": package_name,
                "version": package_version,
                "ecosystem": ecosystem,
                "vulnerabilities": vulnerabilities
            }
        except Exception as e:
            logger.error(f"Package vulnerability check failed: {e}")
            raise HTTPException(status_code=500, detail="Package vulnerability check failed")
    
    @app.get("/vulnerabilities/latest")
    async def get_latest_vulnerabilities(
        limit: int = 20,
        severity: Optional[str] = None,
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Get latest vulnerabilities."""
        await _check_auth_and_rate_limit(request, credentials)
        
        try:
            vulnerabilities = await request.app.state.vulnerability_endpoints.get_latest_vulnerabilities(
                limit, severity
            )
            return {"vulnerabilities": vulnerabilities, "limit": limit, "severity": severity}
        except Exception as e:
            logger.error(f"Latest vulnerabilities fetch failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to fetch latest vulnerabilities")
    
    # Compliance endpoints
    @app.post("/compliance/check")
    async def check_compliance(
        compliance_data: Dict[str, Any],
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Check compliance against regulatory requirements."""
        await _check_auth_and_rate_limit(request, credentials)
        
        try:
            results = await request.app.state.compliance_endpoints.check_compliance(compliance_data)
            return results
        except Exception as e:
            logger.error(f"Compliance check failed: {e}")
            raise HTTPException(status_code=500, detail="Compliance check failed")
    
    @app.get("/compliance/frameworks")
    async def get_compliance_frameworks(
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Get available compliance frameworks."""
        await _check_auth_and_rate_limit(request, credentials)
        
        try:
            frameworks = await request.app.state.compliance_endpoints.get_compliance_frameworks()
            return {"frameworks": frameworks}
        except Exception as e:
            logger.error(f"Compliance frameworks fetch failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to fetch compliance frameworks")
    
    @app.get("/compliance/requirements/{framework}")
    async def get_compliance_requirements(
        framework: str,
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Get requirements for a specific compliance framework."""
        await _check_auth_and_rate_limit(request, credentials)
        
        framework = InputSanitizer.sanitize_user_input(framework)
        
        try:
            requirements = await request.app.state.compliance_endpoints.get_compliance_requirements(framework)
            return {"framework": framework, "requirements": requirements}
        except Exception as e:
            logger.error(f"Compliance requirements fetch failed for {framework}: {e}")
            raise HTTPException(status_code=500, detail="Failed to fetch compliance requirements")
    
    # Cache management endpoints
    @app.post("/cache/invalidate")
    async def invalidate_cache(
        cache_data: Dict[str, Any],
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Invalidate cache entries."""
        await _check_auth_and_rate_limit(request, credentials)
        
        pattern = cache_data.get("pattern", "*")
        pattern = InputSanitizer.sanitize_user_input(pattern)
        
        try:
            request.app.state.cache.invalidate(pattern)
            return {"message": f"Cache invalidated for pattern: {pattern}"}
        except Exception as e:
            logger.error(f"Cache invalidation failed: {e}")
            raise HTTPException(status_code=500, detail="Cache invalidation failed")
    
    @app.get("/cache/stats")
    async def get_cache_stats(
        request: Request = None,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Get cache statistics."""
        await _check_auth_and_rate_limit(request, credentials)
        
        try:
            stats = request.app.state.cache.get_stats()
            return {"cache_stats": stats}
        except Exception as e:
            logger.error(f"Cache stats fetch failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to fetch cache stats")


async def _check_auth_and_rate_limit(
    request: Request, 
    credentials: Optional[HTTPAuthorizationCredentials]
) -> None:
    """Check authentication and rate limiting."""
    config = request.app.state.config
    
    # Check authentication if required
    if config.api_key_required:
        if not credentials:
            raise HTTPException(status_code=401, detail="API key required")
        
        if not request.app.state.auth_manager.validate_api_key(credentials.credentials):
            raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Check rate limiting
    client_ip = request.client.host
    if not request.app.state.rate_limiter.check_rate_limit(
        client_ip, 
        config.rate_limit_requests, 
        config.rate_limit_window
    ):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _add_exception_handlers(app: FastAPI) -> None:
    """Add custom exception handlers."""
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=f"HTTP {exc.status_code}",
                message=exc.detail,
                request_id=getattr(request.state, 'request_id', None)
            ).dict()
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle general exceptions."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal Server Error",
                message="An unexpected error occurred",
                request_id=getattr(request.state, 'request_id', None)
            ).dict()
        )


async def main():
    """Main entry point for running the MCP server."""
    config = MCPServerConfig()
    app = create_app(config)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run server
    server_config = uvicorn.Config(
        app,
        host=config.host,
        port=config.port,
        workers=1,  # Use 1 worker for development
        log_level="info",
        access_log=True
    )
    
    server = uvicorn.Server(server_config)
    
    logger.info(f"Starting MCP server on {config.host}:{config.port}")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())