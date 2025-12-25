"""
WPHunter - Enhanced Finding with CVSS Scoring & PoC Generation
==============================================================
Professional vulnerability reporting with industry standards.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class Severity(Enum):
    """CVSS severity levels."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # 0.0


@dataclass
class Finding:
    """
    Enhanced vulnerability finding with CVSS scoring and PoC generation.
    
    Supports bug bounty reporting and professional security audits.
    """
    # Basic info
    title: str
    description: str
    url: str
    method: str = "GET"
    
    # Classification
    vuln_type: str = ""  # XSS, SQLi, CSRF, etc.
    cwe: str = ""
    owasp: str = ""
    
    # CVSS v3.1
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: Severity = Severity.INFO
    
    # Evidence
    evidence: str = ""
    payload: Optional[str] = None
    response_snippet: Optional[str] = None
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    confidence: str = "high"  # high, medium, low
    exploitability: str = "easy"  # easy, medium, hard
    
    def calculate_cvss(self, 
                       attack_vector: str = "N",  # N=Network, A=Adjacent, L=Local, P=Physical
                       attack_complexity: str = "L",  # L=Low, H=High
                       privileges_required: str = "N",  # N=None, L=Low, H=High
                       user_interaction: str = "N",  # N=None, R=Required
                       scope: str = "U",  # U=Unchanged, C=Changed
                       confidentiality: str = "H",  # N=None, L=Low, H=High
                       integrity: str = "H",
                       availability: str = "N") -> float:
        """
        Calculate CVSS v3.1 score.
        
        Returns score 0.0-10.0 and sets cvss_vector.
        """
        # CVSS v3.1 base score calculation (simplified)
        # Real implementation would use official CVSS calculator
        
        self.cvss_vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        
        # Simplified scoring
        score_map = {
            "N": {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "C": 0.56, "I": 0.56, "A": 0.56},
            "L": {"AV": 0.62, "AC": 0.44, "PR": 0.62, "C": 0.22, "I": 0.22, "A": 0.22},
            "H": {"AV": 0.2, "AC": 0.44, "PR": 0.27, "C": 0.56, "I": 0.56, "A": 0.56},
            "A": {"AV": 0.62},
            "P": {"AV": 0.2},
            "R": {"UI": 0.62},
            "U": {"S": 1.0},
            "C": {"S": 1.08},
        }
        
        # Calculate impact
        impact = 1 - ((1 - score_map.get(confidentiality, {}).get("C", 0)) * 
                      (1 - score_map.get(integrity, {}).get("I", 0)) * 
                      (1 - score_map.get(availability, {}).get("A", 0)))
        
        # Calculate exploitability
        exploitability = (score_map.get(attack_vector, {}).get("AV", 0.85) * 
                         score_map.get(attack_complexity, {}).get("AC", 0.77) * 
                         score_map.get(privileges_required, {}).get("PR", 0.85) * 
                         score_map.get(user_interaction, {}).get("UI", 0.85))
        
        # Base score (simplified)
        if impact <= 0:
            score = 0.0
        else:
            score = min(10.0, (impact + exploitability) * 5.0)
        
        self.cvss_score = round(score, 1)
        
        # Set severity
        if self.cvss_score >= 9.0:
            self.severity = Severity.CRITICAL
        elif self.cvss_score >= 7.0:
            self.severity = Severity.HIGH
        elif self.cvss_score >= 4.0:
            self.severity = Severity.MEDIUM
        elif self.cvss_score > 0:
            self.severity = Severity.LOW
        else:
            self.severity = Severity.INFO
        
        return self.cvss_score
    
    def generate_poc(self, format: str = "markdown") -> str:
        """
        Generate Proof of Concept in specified format.
        
        Formats: markdown, hackerone, bugcrowd, json
        """
        if format == "markdown":
            return self._generate_markdown_poc()
        elif format == "hackerone":
            return self._generate_hackerone_poc()
        elif format == "bugcrowd":
            return self._generate_bugcrowd_poc()
        elif format == "json":
            return self._generate_json_poc()
        else:
            return self._generate_markdown_poc()
    
    def _generate_markdown_poc(self) -> str:
        """Generate markdown PoC for documentation."""
        poc = f"""# {self.title}

## Summary
{self.description}

## Severity
**{self.severity.value.upper()}** (CVSS {self.cvss_score})

**CVSS Vector:** `{self.cvss_vector}`

## Vulnerability Details
- **Type:** {self.vuln_type}
- **CWE:** {self.cwe}
- **OWASP:** {self.owasp}
- **URL:** {self.url}
- **Method:** {self.method}

## Proof of Concept

### Request
```http
{self.method} {self.url} HTTP/1.1
Host: [target]
"""
        
        if self.payload:
            poc += f"\n### Payload\n```\n{self.payload}\n```\n"
        
        if self.evidence:
            poc += f"\n### Evidence\n```\n{self.evidence[:500]}\n```\n"
        
        if self.response_snippet:
            poc += f"\n### Response\n```\n{self.response_snippet[:500]}\n```\n"
        
        poc += f"""

## Impact
{self._get_impact_description()}

## Remediation
{self.remediation}

## References
"""
        for ref in self.references:
            poc += f"- {ref}\n"
        
        return poc
    
    def _generate_hackerone_poc(self) -> str:
        """Generate HackerOne-formatted report."""
        return f"""## Summary
{self.description}

## Steps To Reproduce
1. Navigate to: {self.url}
2. Send the following {self.method} request:
```
{self.payload or 'See evidence below'}
```
3. Observe the vulnerability in the response

## Impact
{self._get_impact_description()}

## Supporting Material/References
{self.evidence[:500] if self.evidence else 'N/A'}

## Severity Assessment
**{self.severity.value.upper()}** - CVSS {self.cvss_score} ({self.cvss_vector})
"""
    
    def _generate_bugcrowd_poc(self) -> str:
        """Generate Bugcrowd-formatted report."""
        return f"""**Title:** {self.title}

**Vulnerability Type:** {self.vuln_type}

**Severity:** {self.severity.value.upper()} (CVSS {self.cvss_score})

**Description:**
{self.description}

**Proof of Concept:**
URL: {self.url}
Method: {self.method}
Payload: {self.payload or 'N/A'}

**Impact:**
{self._get_impact_description()}

**Remediation:**
{self.remediation}
"""
    
    def _generate_json_poc(self) -> str:
        """Generate JSON export."""
        import json
        return json.dumps({
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "method": self.method,
            "vuln_type": self.vuln_type,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "payload": self.payload,
            "remediation": self.remediation,
            "references": self.references,
            "confidence": self.confidence,
            "exploitability": self.exploitability
        }, indent=2)
    
    def _get_impact_description(self) -> str:
        """Get impact description based on vulnerability type."""
        impact_map = {
            "XSS": "Attackers can execute arbitrary JavaScript in victim browsers, potentially stealing session cookies, performing actions on behalf of users, or defacing the website.",
            "SQLi": "Attackers can read, modify, or delete database contents, potentially compromising all data stored in the database including user credentials and sensitive information.",
            "CSRF": "Attackers can perform unauthorized actions on behalf of authenticated users, potentially leading to account takeover or data manipulation.",
            "LFI": "Attackers can read arbitrary files from the server, potentially exposing sensitive configuration files, source code, or credentials.",
            "RCE": "Attackers can execute arbitrary commands on the server, leading to complete system compromise.",
            "IDOR": "Attackers can access resources belonging to other users, potentially exposing sensitive personal or business data.",
            "Upload": "Attackers can upload malicious files, potentially leading to remote code execution or stored XSS attacks.",
            "XXE": "Attackers can read arbitrary files, perform SSRF attacks, or cause denial of service through XML entity expansion.",
        }
        
        return impact_map.get(self.vuln_type, "This vulnerability could allow attackers to compromise the security of the application.")
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "method": self.method,
            "vuln_type": self.vuln_type,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity.value,
            "evidence": self.evidence[:300] if self.evidence else "",
            "remediation": self.remediation,
            "confidence": self.confidence,
            "exploitability": self.exploitability
        }
