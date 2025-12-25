"""
WPHunter - Logger Module
========================
Rich console logging with colored output and file logging support.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for WPHunter
WPHUNTER_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red bold",
    "critical": "red bold reverse",
    "success": "green bold",
    "vuln.low": "blue",
    "vuln.medium": "yellow",
    "vuln.high": "red",
    "vuln.critical": "red bold reverse",
})

console = Console(theme=WPHUNTER_THEME)


class WPHunterLogger:
    """Custom logger for WPHunter with rich console output."""
    
    def __init__(
        self,
        name: str = "WPHunter",
        level: str = "INFO",
        log_file: Optional[str] = None,
        colored: bool = True
    ):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers.clear()
        
        # Rich console handler
        if colored:
            rich_handler = RichHandler(
                console=console,
                show_time=True,
                show_path=False,
                rich_tracebacks=True,
                tracebacks_show_locals=True,
            )
            rich_handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(rich_handler)
        else:
            # Plain console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(file_handler)
    
    def info(self, message: str):
        """Log info message."""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message."""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message."""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Log critical message."""
        self.logger.critical(message)
    
    def debug(self, message: str):
        """Log debug message."""
        self.logger.debug(message)
    
    def success(self, message: str):
        """Log success message with green styling."""
        console.print(f"[success]✓ {message}[/success]")
    
    def vuln(self, severity: str, message: str):
        """Log vulnerability finding with severity-based styling."""
        severity_lower = severity.lower()
        icon = {
            "low": "ℹ",
            "medium": "⚠",
            "high": "🔴",
            "critical": "💀"
        }.get(severity_lower, "•")
        console.print(f"[vuln.{severity_lower}]{icon} [{severity.upper()}] {message}[/vuln.{severity_lower}]")
    
    def banner(self):
        """Display WPHunter banner."""
        banner_text = """
[cyan]
██╗    ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║    ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║███╗██║██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚███╔███╔╝██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/cyan]
[dim]WordPress Intelligent Penetration Testing Tool[/dim]
[dim]v1.0.0 - For authorized security testing only[/dim]
"""
        console.print(banner_text)
    
    def section(self, title: str):
        """Print section header."""
        console.print(f"\n[bold cyan]{'═' * 60}[/bold cyan]")
        console.print(f"[bold cyan]  {title}[/bold cyan]")
        console.print(f"[bold cyan]{'═' * 60}[/bold cyan]\n")
    
    def table_result(self, title: str, data: dict):
        """Print results in a formatted table."""
        from rich.table import Table
        
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        for key, value in data.items():
            table.add_row(str(key), str(value))
        
        console.print(table)


# Global logger instance
logger = WPHunterLogger()
