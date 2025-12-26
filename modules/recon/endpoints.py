"""
WPHunter - Advanced Endpoint Mapping
====================================
Discover and map WordPress endpoints for vulnerability testing.

Enhanced with:
- GraphQL detection and introspection
- Admin endpoint exposure detection
- Debug/backup file discovery
- WebSocket/SSE endpoint detection
- AJAX action bruteforce
- Rewrite rules analysis
- Comprehensive vulnerability assessment
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from bs4 import BeautifulSoup

from core.http_client import WPHttpClient
from core.logger import logger
from core.utils import extract_forms, extract_ajax_actions


@dataclass
class RESTEndpoint:
    """REST API endpoint information."""
    namespace: str
    route: str
    methods: List[str] = field(default_factory=list)
    requires_auth: bool = False
    parameters: List[str] = field(default_factory=list)


@dataclass
class AJAXAction:
    """AJAX action information."""
    action: str
    requires_nonce: bool = False
    requires_auth: bool = False
    found_in: str = ""
    vulnerable: bool = False


@dataclass
class FormEndpoint:
    """HTML form endpoint."""
    action: str
    method: str
    inputs: List[Dict[str, str]] = field(default_factory=list)
    has_nonce: bool = False
    found_on: str = ""


@dataclass
class GraphQLEndpoint:
    """GraphQL endpoint information."""
    endpoint: str
    introspection_enabled: bool = False
    mutations: List[str] = field(default_factory=list)
    queries: List[str] = field(default_factory=list)


@dataclass
class DebugEndpoint:
    """Debug/sensitive file endpoint."""
    endpoint: str
    endpoint_type: str  # SECRET_EXPOSURE, DEBUG_ENDPOINT, BACKUP_FILE
    secrets_found: List[str] = field(default_factory=list)


@dataclass
class EndpointMap:
    """Complete endpoint mapping result."""
    rest_endpoints: List[RESTEndpoint] = field(default_factory=list)
    ajax_actions: List[AJAXAction] = field(default_factory=list)
    forms: List[FormEndpoint] = field(default_factory=list)
    xmlrpc_enabled: bool = False
    xmlrpc_methods: List[str] = field(default_factory=list)
    graphql_endpoints: List[GraphQLEndpoint] = field(default_factory=list)
    debug_endpoints: List[DebugEndpoint] = field(default_factory=list)
    admin_exposed: List[str] = field(default_factory=list)
    realtime_endpoints: List[str] = field(default_factory=list)
    rewrite_rules: List[Tuple[str, str]] = field(default_factory=list)


class EndpointMapper:
    """
    Map all exploitable WordPress endpoints.
    
    Creates a comprehensive map of attack surface for the scanner modules.
    """
    
    # Common AJAX actions to check
    KNOWN_AJAX_ACTIONS = [
        "heartbeat", "wp_ajax_parse-embed", "query-attachments",
        "upload-attachment", "save-attachment", "delete-post",
        "trash-post", "inline-save", "wp-remove-post-lock",
        "closed-postboxes", "meta-box-order", "get-comments",
        "replyto-comment", "edit-comment", "delete-comment",
    ]
    
    # AJAX actions to bruteforce
    BRUTEFORCE_AJAX_ACTIONS = [
        # User actions
        "get_user_data", "update_profile", "change_password", "delete_account",
        # Post actions  
        "create_post", "edit_post", "delete_post", "publish_post",
        # Media actions
        "upload_media", "delete_media", "get_media",
        # Plugin/theme actions
        "install_plugin", "activate_plugin", "deactivate_plugin",
        "delete_plugin", "install_theme", "activate_theme",
        # Settings actions
        "update_options", "reset_options", "save_settings",
        # E-commerce actions
        "update_cart", "checkout", "update_order", "add_to_cart",
        # Export/Import
        "export_data", "import_data", "download_backup",
    ]
    
    # Debug and sensitive file patterns
    DEBUG_PATTERNS = [
        "/wp-admin/debug.log", "/debug.log", "/error_log",
        "/wp-content/debug.log", "/?debug=true", "/?debug=1",
        "/?XDEBUG_SESSION_START", "/?XDEBUG_PROFILE",
        "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php.save",
        "/wp-config.php~", "/wp-config.php.swp", "/wp-config.txt",
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/backup.sql", "/backup.zip", "/database.sql", "/db.sql",
        "/wp-backup/", "/.git/config", "/.svn/entries",
        "/phpinfo.php", "/info.php", "/test.php",
    ]
    
    # Admin endpoints to check
    ADMIN_PATTERNS = [
        "/wp-admin/admin.php", "/wp-admin/admin-ajax.php",
        "/wp-admin/admin-post.php", "/wp-admin/update.php",
        "/wp-admin/plugin-install.php", "/wp-admin/theme-install.php",
        "/wp-admin/user-new.php", "/wp-admin/media-new.php",
        "/wp-admin/upgrade.php", "/wp-admin/install.php",
        "/wp-admin/setup-config.php", "/wp-admin/options.php",
    ]
    
    # GraphQL paths to check
    GRAPHQL_PATHS = [
        "/graphql", "/api/graphql", "/wp-json/graphql",
        "/wp/graphql", "/index.php?graphql", "/graphiql",
    ]
    
    # Sensitive keywords in responses
    SENSITIVE_KEYWORDS = [
        "DB_PASSWORD", "DB_USER", "AUTH_KEY", "SECURE_AUTH_KEY",
        "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT",
        "LOGGED_IN_SALT", "NONCE_SALT", "password", "secret",
        "api_key", "access_token", "private_key", "AWS_SECRET",
    ]
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.endpoints = EndpointMap()
    
    async def map_all(self) -> EndpointMap:
        """Map all WordPress endpoints."""
        logger.section("Endpoint Mapping")
        
        await asyncio.gather(
            self._map_rest_api(),
            self._map_ajax_actions(),
            self._map_xmlrpc(),
            self._map_forms(),
        )
        
        logger.success(f"REST endpoints: {len(self.endpoints.rest_endpoints)}")
        logger.success(f"AJAX actions: {len(self.endpoints.ajax_actions)}")
        logger.success(f"Forms: {len(self.endpoints.forms)}")
        logger.success(f"XML-RPC: {'enabled' if self.endpoints.xmlrpc_enabled else 'disabled'}")
        
        return self.endpoints
    
    async def comprehensive_mapping(self) -> EndpointMap:
        """Perform comprehensive endpoint mapping with all advanced features."""
        logger.section("Advanced Endpoint Mapping")
        
        # Run all mapping tasks
        await asyncio.gather(
            self._map_rest_api(),
            self._map_ajax_actions(),
            self._map_xmlrpc(),
            self._map_forms(),
            self._map_graphql(),
            self._map_admin_endpoints(),
            self._map_debug_endpoints(),
            self._map_realtime_endpoints(),
            self._map_v2_endpoints_detail(),
        )
        
        # AJAX bruteforce (slower, run separately)
        await self._bruteforce_ajax_actions()
        
        # Summary
        self._log_comprehensive_summary()
        
        return self.endpoints
    
    def _log_comprehensive_summary(self):
        """Log comprehensive mapping summary."""
        logger.success(f"REST endpoints: {len(self.endpoints.rest_endpoints)}")
        logger.success(f"AJAX actions: {len(self.endpoints.ajax_actions)}")
        logger.success(f"Forms: {len(self.endpoints.forms)}")
        logger.success(f"XML-RPC: {'enabled' if self.endpoints.xmlrpc_enabled else 'disabled'}")
        
        if self.endpoints.graphql_endpoints:
            for gql in self.endpoints.graphql_endpoints:
                if gql.introspection_enabled:
                    logger.warning(f"GraphQL introspection enabled: {gql.endpoint}")
        
        if self.endpoints.debug_endpoints:
            for debug in self.endpoints.debug_endpoints:
                if debug.endpoint_type == "SECRET_EXPOSURE":
                    logger.vuln("critical", f"Secrets exposed: {debug.endpoint}")
                else:
                    logger.warning(f"Debug endpoint: {debug.endpoint}")
        
        if self.endpoints.admin_exposed:
            logger.warning(f"Admin endpoints exposed: {len(self.endpoints.admin_exposed)}")
        
        if self.endpoints.realtime_endpoints:
            logger.info(f"Realtime endpoints: {len(self.endpoints.realtime_endpoints)}")
    
    async def _map_rest_api(self):
        """Map REST API endpoints."""
        try:
            response = await self.http.get("/wp-json/")
            
            if not response.ok or not response.is_json:
                logger.debug("REST API not accessible")
                return
            
            data = response.json()
            namespaces = data.get("namespaces", [])
            routes = data.get("routes", {})
            
            for route_path, route_info in routes.items():
                namespace = "wp/v2"
                for ns in namespaces:
                    if route_path.startswith(f"/{ns}"):
                        namespace = ns
                        break
                
                methods = []
                requires_auth = False
                parameters = []
                
                endpoints_info = route_info.get("endpoints", [])
                for ep in endpoints_info:
                    methods.extend(ep.get("methods", []))
                    args = ep.get("args", {})
                    parameters.extend(args.keys())
                    
                    if any(arg.get("required") and arg.get("name") == "X-WP-Nonce"
                           for arg in args.values()):
                        requires_auth = True
                
                self.endpoints.rest_endpoints.append(RESTEndpoint(
                    namespace=namespace,
                    route=route_path,
                    methods=list(set(methods)),
                    requires_auth=requires_auth,
                    parameters=list(set(parameters))
                ))
            
            logger.info(f"Discovered {len(namespaces)} REST namespaces")
            
        except Exception as e:
            logger.debug(f"REST API mapping failed: {e}")
    
    async def _map_ajax_actions(self):
        """Map AJAX actions from JavaScript files."""
        try:
            response = await self.http.get("/")
            
            if response.ok:
                actions = set(extract_ajax_actions(response.text))
                
                soup = BeautifulSoup(response.text, 'lxml')
                scripts = soup.find_all('script', src=True)
                
                for script in scripts[:10]:
                    src = script.get('src', '')
                    if '/wp-content/' in src or '/wp-includes/' in src:
                        try:
                            js_response = await self.http.get(src)
                            if js_response.ok:
                                actions.update(extract_ajax_actions(js_response.text))
                        except Exception:
                            continue
                
                for action in actions:
                    self.endpoints.ajax_actions.append(AJAXAction(
                        action=action,
                        found_in="homepage"
                    ))
            
            ajax_check = await self.http.post(
                "/wp-admin/admin-ajax.php",
                data={"action": "heartbeat"}
            )
            
            if ajax_check.ok:
                logger.info("admin-ajax.php is accessible")
                
        except Exception as e:
            logger.debug(f"AJAX mapping failed: {e}")
    
    async def _map_xmlrpc(self):
        """Map XML-RPC endpoint and methods."""
        try:
            response = await self.http.get("/xmlrpc.php")
            
            if response.status_code == 405 or response.status_code == 200:
                self.endpoints.xmlrpc_enabled = True
                logger.info("XML-RPC is enabled")
                
                list_methods_payload = '''<?xml version="1.0" encoding="utf-8"?>
                <methodCall>
                    <methodName>system.listMethods</methodName>
                    <params></params>
                </methodCall>'''
                
                methods_response = await self.http.post(
                    "/xmlrpc.php",
                    data=list_methods_payload,
                    headers={"Content-Type": "text/xml"}
                )
                
                if methods_response.ok:
                    method_pattern = r'<string>([^<]+)</string>'
                    methods = re.findall(method_pattern, methods_response.text)
                    self.endpoints.xmlrpc_methods = methods
                    
                    dangerous_methods = ["pingback.ping", "system.multicall", "wp.getUsersBlogs"]
                    for method in dangerous_methods:
                        if method in methods:
                            logger.warning(f"Dangerous XML-RPC method enabled: {method}")
                            
        except Exception as e:
            logger.debug(f"XML-RPC mapping failed: {e}")
    
    async def _map_forms(self):
        """Map HTML forms across the site."""
        pages_to_scan = [
            "/", "/wp-login.php", "/wp-login.php?action=register",
            "/wp-login.php?action=lostpassword",
        ]
        
        for page in pages_to_scan:
            try:
                response = await self.http.get(page)
                
                if response.ok:
                    forms = extract_forms(response.text)
                    
                    for form in forms:
                        has_nonce = any(
                            inp.get("name", "").endswith("nonce") or
                            "_wpnonce" in inp.get("name", "")
                            for inp in form.get("inputs", [])
                        )
                        
                        self.endpoints.forms.append(FormEndpoint(
                            action=form.get("action", ""),
                            method=form.get("method", "POST"),
                            inputs=form.get("inputs", []),
                            has_nonce=has_nonce,
                            found_on=page
                        ))
                        
            except Exception:
                continue
    
    async def _map_graphql(self):
        """Map GraphQL endpoints and test introspection."""
        logger.info("Testing GraphQL endpoints...")
        
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    types { name kind }
                    queryType { name }
                    mutationType { name }
                }
            }
            """
        }
        
        for path in self.GRAPHQL_PATHS:
            try:
                response = await self.http.post(
                    path,
                    json=introspection_query,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.ok and response.is_json:
                    data = response.json()
                    if "__schema" in str(data) or "data" in data:
                        logger.warning(f"GraphQL introspection enabled at {path}")
                        
                        queries = []
                        mutations = []
                        
                        # Try to extract full schema
                        try:
                            schema = data.get("data", {}).get("__schema", {})
                            query_type = schema.get("queryType", {})
                            mutation_type = schema.get("mutationType", {})
                            queries = [query_type.get("name")] if query_type else []
                            mutations = [mutation_type.get("name")] if mutation_type else []
                        except Exception:
                            pass
                        
                        self.endpoints.graphql_endpoints.append(GraphQLEndpoint(
                            endpoint=path,
                            introspection_enabled=True,
                            queries=queries,
                            mutations=mutations
                        ))
                        return  # Found one, no need to continue
                        
            except Exception:
                continue
    
    async def _map_admin_endpoints(self):
        """Map admin endpoints that might be exposed without auth."""
        logger.info("Testing admin endpoint exposure...")
        
        for pattern in self.ADMIN_PATTERNS:
            try:
                response = await self.http.get(pattern)
                
                if response.ok:
                    # Check if it's accessible without auth (not redirecting to login)
                    if "wp-login.php" not in response.url and "login" not in response.text.lower()[:500]:
                        logger.warning(f"Admin endpoint accessible without auth: {pattern}")
                        self.endpoints.admin_exposed.append(pattern)
                        
            except Exception:
                continue
    
    async def _map_debug_endpoints(self):
        """Map debug and development endpoints."""
        logger.info("Testing debug/backup file exposure...")
        
        for pattern in self.DEBUG_PATTERNS:
            try:
                response = await self.http.get(pattern)
                
                if response.ok and len(response.text) > 10:
                    content = response.text.lower()
                    
                    # Skip 404/error pages
                    if "not found" in content or "error" in content[:100]:
                        continue
                    
                    # Check for sensitive information
                    found_secrets = [
                        kw for kw in self.SENSITIVE_KEYWORDS
                        if kw.lower() in content
                    ]
                    
                    if found_secrets:
                        logger.vuln("critical", f"Debug endpoint exposes secrets: {pattern}")
                        self.endpoints.debug_endpoints.append(DebugEndpoint(
                            endpoint=pattern,
                            endpoint_type="SECRET_EXPOSURE",
                            secrets_found=found_secrets
                        ))
                    else:
                        logger.warning(f"Debug endpoint accessible: {pattern}")
                        self.endpoints.debug_endpoints.append(DebugEndpoint(
                            endpoint=pattern,
                            endpoint_type="DEBUG_ENDPOINT"
                        ))
                        
            except Exception:
                continue
    
    async def _map_realtime_endpoints(self):
        """Map WebSocket and SSE endpoints."""
        logger.info("Detecting WebSocket/SSE endpoints...")
        
        try:
            response = await self.http.get("/")
            if response.ok:
                # Look for WebSocket connections in JS
                ws_patterns = [
                    r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                    r'ws[s]?://[^"\'\s]+',
                    r'io\.connect\s*\(\s*["\']([^"\']+)["\']',
                    r'Socket\.connect\s*\(\s*["\']([^"\']+)["\']',
                ]
                
                ws_endpoints = set()
                for pattern in ws_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    ws_endpoints.update(matches)
                
                # Check for EventSource (SSE)
                sse_pattern = r'new\s+EventSource\s*\(\s*["\']([^"\']+)["\']'
                sse_matches = re.findall(sse_pattern, response.text, re.IGNORECASE)
                ws_endpoints.update(sse_matches)
                
                for endpoint in ws_endpoints:
                    logger.info(f"Found realtime endpoint: {endpoint}")
                    self.endpoints.realtime_endpoints.append(endpoint)
                
        except Exception as e:
            logger.debug(f"Realtime endpoint mapping failed: {e}")
    
    async def _map_v2_endpoints_detail(self):
        """Detailed mapping of wp/v2 endpoints with vulnerability analysis."""
        try:
            response = await self.http.get("/wp-json/wp/v2/")
            if response.ok and response.is_json:
                routes = response.json().get("routes", {})
                
                for route, info in routes.items():
                    endpoints = info.get("endpoints", [])
                    
                    for endpoint in endpoints:
                        # Check for permission callbacks
                        # Some plugins use __return_true which is insecure
                        callback = str(endpoint.get("callback", ""))
                        permission = str(endpoint.get("permission_callback", ""))
                        
                        if "__return_true" in permission:
                            logger.warning(f"Public endpoint with __return_true: {route}")
                        
                        # Look for IDOR opportunities
                        args = endpoint.get("args", {})
                        for param_name in args.keys():
                            if 'id' in param_name.lower():
                                logger.debug(f"Potential IDOR endpoint: {route} ({param_name})")
                                
        except Exception as e:
            logger.debug(f"Detailed v2 mapping failed: {e}")
    
    async def _bruteforce_ajax_actions(self):
        """Bruteforce common AJAX action names with improved baseline."""
        logger.info("Bruteforcing AJAX actions...")
        
        # ✅ FIX Bug #12: Multiple baseline requests to handle dynamic responses
        import random
        baselines = []
        for i in range(3):
            baseline_response = await self.http.post(
                "/wp-admin/admin-ajax.php",
                data={"action": f"nonexistent_action_{random.randint(1000, 9999)}"}
            )
            baselines.append(baseline_response.text.strip())
            await asyncio.sleep(0.1)
        
        # Take most common response as baseline
        from collections import Counter
        baseline_text = Counter(baselines).most_common(1)[0][0]
        baseline_status = baseline_response.status_code
        
        logger.debug(f"Baseline response (from 3 samples): status={baseline_status}, body={baseline_text[:50]}")
        
        discovered = []
        
        for action in self.BRUTEFORCE_AJAX_ACTIONS:
            try:
                response = await self.http.post(
                    "/wp-admin/admin-ajax.php",
                    data={"action": action}
                )
                
                response_text = response.text.strip()
                
                # Action exists IF:
                # 1. Response different from baseline
                # 2. OR contains JSON
                # 3. OR contains specific error messages
                
                action_exists = False
                
                if response_text != baseline_text:
                    action_exists = True
                elif response_text.startswith('{') or response_text.startswith('['):
                    action_exists = True  # JSON response
                elif any(keyword in response_text.lower() for keyword in 
                        ['nonce', 'permission', 'login', 'required', 'error']):
                    action_exists = True  # Error message = action exists
                
                if action_exists:
                    logger.warning(f"Discovered AJAX action: {action} (response: {response_text[:100]})")
                    
                    self.endpoints.ajax_actions.append(AJAXAction(
                        action=action,
                        found_in="bruteforce",
                        vulnerable=(response_text not in ["0", "-1"])
                    ))
                    discovered.append(action)
                
                await asyncio.sleep(0.1)  # Rate limiting
                    
            except Exception:
                continue
        
        if discovered:
            logger.info(f"Bruteforced {len(discovered)} AJAX actions")
    
    def get_testable_rest_endpoints(self) -> List[RESTEndpoint]:
        """Get REST endpoints that don't require authentication."""
        return [ep for ep in self.endpoints.rest_endpoints if not ep.requires_auth]
    
    def get_testable_ajax_actions(self) -> List[AJAXAction]:
        """Get AJAX actions for testing."""
        return self.endpoints.ajax_actions
    
    def get_forms_without_nonce(self) -> List[FormEndpoint]:
        """Get forms that lack CSRF protection."""
        return [form for form in self.endpoints.forms if not form.has_nonce]
    
    def export_for_scanners(self) -> Dict[str, List[str]]:
        """Export endpoints in format for other scanner modules."""
        return {
            "csrf_targets": [f.action for f in self.get_forms_without_nonce()],
            "ajax_targets": [a.action for a in self.endpoints.ajax_actions],
            "rest_targets": [e.route for e in self.get_testable_rest_endpoints()],
            "graphql_targets": [g.endpoint for g in self.endpoints.graphql_endpoints],
            "debug_targets": [d.endpoint for d in self.endpoints.debug_endpoints],
        }
    
    def assess_vulnerabilities(self) -> Dict[str, List[str]]:
        """Assess discovered endpoints for vulnerabilities."""
        vulnerabilities = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        # Critical: Debug endpoints with secrets
        for endpoint in self.endpoints.debug_endpoints:
            if endpoint.endpoint_type == "SECRET_EXPOSURE":
                vulnerabilities["critical"].append(
                    f"Secret exposure at {endpoint.endpoint}"
                )
        
        # High: Admin endpoints without auth
        for endpoint in self.endpoints.admin_exposed:
            vulnerabilities["high"].append(
                f"Admin endpoint without auth: {endpoint}"
            )
        
        # Medium: Forms without nonce
        for form in self.get_forms_without_nonce():
            vulnerabilities["medium"].append(
                f"Form without CSRF protection: {form.action}"
            )
        
        # Medium: GraphQL introspection
        for graphql in self.endpoints.graphql_endpoints:
            if graphql.introspection_enabled:
                vulnerabilities["medium"].append(
                    f"GraphQL introspection enabled at {graphql.endpoint}"
                )
        
        # Medium: XML-RPC dangerous methods
        dangerous = ["pingback.ping", "system.multicall"]
        for method in dangerous:
            if method in self.endpoints.xmlrpc_methods:
                vulnerabilities["medium"].append(
                    f"Dangerous XML-RPC method: {method}"
                )
        
        return vulnerabilities
    
    def get_summary(self) -> Dict:
        """Get summary of endpoint mapping."""
        return {
            "rest_endpoints": len(self.endpoints.rest_endpoints),
            "rest_public": len(self.get_testable_rest_endpoints()),
            "ajax_actions": len(self.endpoints.ajax_actions),
            "forms": len(self.endpoints.forms),
            "forms_without_csrf": len(self.get_forms_without_nonce()),
            "xmlrpc_enabled": self.endpoints.xmlrpc_enabled,
            "xmlrpc_methods": len(self.endpoints.xmlrpc_methods),
            "graphql_endpoints": len(self.endpoints.graphql_endpoints),
            "debug_endpoints": len(self.endpoints.debug_endpoints),
            "admin_exposed": len(self.endpoints.admin_exposed),
            "realtime_endpoints": len(self.endpoints.realtime_endpoints),
        }
