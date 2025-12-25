#!/usr/bin/env python3
"""
WPHunter - WordPress Intelligent Penetration Testing Tool
==========================================================
A modular, intelligent WordPress security scanner for pentest and bug bounty.

Usage:
    python wphunter.py -u https://target.com --mode full
    python wphunter.py -u https://target.com --mode recon
    python wphunter.py -u https://target.com --mode scan --proxy http://127.0.0.1:8080
"""

import asyncio
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import WPHunterConfig
from core.http_client import WPHttpClient
from core.logger import logger
from modules.recon import VersionDetector, PluginEnumerator, ThemeDetector, UserEnumerator, EndpointMapper
from modules.scanners import XSSScanner, SQLiScanner, CSRFScanner, LFIScanner, UploadScanner, AuthScanner, SSRFScanner, WAFDetector, NginxScanner
from modules.integrations import NucleiIntegration, PluginVulnScanner
from reports import ReportGenerator

app = typer.Typer(help="WPHunter - WordPress Security Scanner")
console = Console()


class WPHunter:
    """Main WPHunter orchestrator."""
    
    def __init__(self, target: str, config: WPHunterConfig):
        self.target = target.rstrip('/')
        self.config = config
        self.http = WPHttpClient(config, self.target)
        self.results = {"recon": {}, "findings": []}
    
    async def run_recon(self):
        """Run reconnaissance modules."""
        # WAF Detection (first to adjust scan parameters)
        waf_detector = WAFDetector(self.http)
        wafs = await waf_detector.detect()
        self.results["recon"]["waf"] = waf_detector.get_summary()
        
        # Adjust scan based on WAF
        if waf_detector.is_protected:
            recommendations = waf_detector.get_scan_recommendations()
            logger.warning(f"WAF detected - adjusting scan (delay: {recommendations['delay']}s)")
        
        # Version detection
        version_detector = VersionDetector(self.http)
        version_info = await version_detector.detect()
        self.results["recon"]["version"] = version_info.version
        
        # Plugin enumeration
        plugin_enum = PluginEnumerator(self.http)
        plugins = await plugin_enum.enumerate()
        self.results["recon"]["plugins"] = [{"slug": p.slug, "version": p.version} for p in plugins]
        self.results["recon"]["plugin_slugs"] = [p.slug for p in plugins]
        
        # Theme detection
        theme_detector = ThemeDetector(self.http)
        themes = await theme_detector.detect()
        self.results["recon"]["theme"] = themes[0].slug if themes else None
        self.results["recon"]["themes"] = [{"slug": t.slug, "version": t.version} for t in themes]
        
        # User enumeration
        user_enum = UserEnumerator(self.http)
        users = await user_enum.enumerate()
        self.results["recon"]["users"] = [u.username or u.display_name for u in users]
        
        # Endpoint mapping
        endpoint_mapper = EndpointMapper(self.http)
        endpoints = await endpoint_mapper.map_all()
        self.results["recon"]["endpoints"] = endpoint_mapper.get_summary()
        
        return self.results["recon"]
    
    async def run_scan(self):
        """Run vulnerability scanners."""
        recon = self.results.get("recon", {})
        
        # Collect URLs with parameters
        urls = [f"{self.target}/?s=test"]
        forms = []
        
        # WPScan API - Check for known CVEs
        wpscan_token = self.config.get_tool_config("wpscan", {}).get("api_token")
        if wpscan_token:
            vuln_scanner = PluginVulnScanner(wpscan_token)
            await vuln_scanner.scan(
                plugins=recon.get("plugins", []),
                themes=recon.get("themes", []),
                wp_version=recon.get("version")
            )
            for v in vuln_scanner.vulnerabilities:
                self.results["findings"].append({
                    "type": "Known CVE", **v.to_dict(), "severity": v.severity
                })
        
        # XSS Scanner
        xss = XSSScanner(self.http)
        xss_results = await xss.scan(urls, forms)
        for f in xss_results:
            self.results["findings"].append(f.to_dict())
        
        # SQLi Scanner
        sqli = SQLiScanner(self.http)
        sqli_results = await sqli.scan(urls, forms)
        for f in sqli_results:
            self.results["findings"].append(f.to_dict())
        
        # LFI Scanner (with plugin discovery)
        plugins = recon.get("plugin_slugs", [])
        lfi = LFIScanner(self.http)
        lfi_results = await lfi.scan(plugins=plugins)
        for f in lfi_results:
            self.results["findings"].append(f.to_dict())
        
        # SSRF Scanner
        ssrf = SSRFScanner(self.http)
        ssrf_results = await ssrf.scan()
        for f in ssrf_results:
            self.results["findings"].append(f.to_dict())
        
        # Nginx Misconfiguration Scanner
        nginx = NginxScanner(self.http)
        nginx_results = await nginx.scan()
        for f in nginx_results:
            self.results["findings"].append(f.to_dict())
        if nginx.discovered_vhosts:
            self.results["discovered_vhosts"] = nginx.discovered_vhosts
        
        # Auth Scanner
        auth = AuthScanner(self.http)
        auth_results = await auth.scan()
        for f in auth_results:
            self.results["findings"].append(f.to_dict())
        
        # Nuclei integration
        if self.config.is_tool_enabled("nuclei"):
            nuclei = NucleiIntegration()
            nuclei_results = await nuclei.scan(self.target)
            for r in nuclei_results:
                self.results["findings"].append(r.to_dict())
        
        return self.results["findings"]
    
    async def run_full(self):
        """Run full scan (recon + vuln scan)."""
        await self.run_recon()
        await self.run_scan()
        return self.results


async def main_async(target: str, mode: str, config_path: str, profile: str, proxy: str, output: str):
    """Async main function."""
    start_time = time.time()
    
    # Load config
    config = WPHunterConfig.from_yaml(config_path)
    
    # Apply profile
    if profile:
        config.set_profile(profile)
    
    # Apply proxy
    if proxy:
        config.proxy.enabled = True
        config.proxy.http = proxy
        config.proxy.https = proxy
    
    # Show banner
    logger.banner()
    logger.info(f"Target: {target}")
    logger.info(f"Mode: {mode}")
    logger.info(f"Profile: {config.active_profile}")
    
    # Run scan
    hunter = WPHunter(target, config)
    
    if mode == "recon":
        await hunter.run_recon()
    elif mode == "scan":
        await hunter.run_scan()
    else:
        await hunter.run_full()
    
    # Generate reports
    duration = time.time() - start_time
    
    reporter = ReportGenerator(output)
    paths = reporter.generate(hunter.results, target, duration)
    
    # Summary
    logger.section("Scan Complete")
    logger.info(f"Duration: {duration:.1f}s")
    logger.info(f"Findings: {len(hunter.results.get('findings', []))}")
    logger.info(f"Report: {paths['html']}")
    
    # Print HTTP stats
    stats = hunter.http.get_stats()
    logger.table_result("HTTP Statistics", stats)


@app.command()
def scan(
    target: str = typer.Option(..., "-u", "--url", help="Target WordPress URL"),
    mode: str = typer.Option("full", "-m", "--mode", help="Scan mode: recon, scan, full"),
    config: str = typer.Option("config.yaml", "-c", "--config", help="Config file path"),
    profile: str = typer.Option("normal", "-p", "--profile", help="Scan profile: stealthy, normal, aggressive"),
    proxy: str = typer.Option(None, "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)"),
    output: str = typer.Option("./reports", "-o", "--output", help="Output directory"),
):
    """Run WPHunter scan on a WordPress target."""
    asyncio.run(main_async(target, mode, config, profile, proxy, output))


@app.command()
def version():
    """Show WPHunter version."""
    console.print("[cyan]WPHunter v1.0.0[/cyan]")
    console.print("WordPress Intelligent Penetration Testing Tool")


if __name__ == "__main__":
    app()
