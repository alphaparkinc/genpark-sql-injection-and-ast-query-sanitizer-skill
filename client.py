"""SQL Injection and AST Query Sanitizer.
100% Python Standard Library.
"""

import re
from typing import Dict, Any, List, Optional


class SQLSanitizerEngine:
    """Security engine for auditing database statements: flags tautology and union-based
    SQL injection exploits, audits parameterized placeholders, and sanitizes identifiers."""

    # Core threat patterns
    THREAT_PATTERNS = [
        (re.compile(r'\b(?:OR|AND)\s+[\'"]?(\w+)[\'"]?\s*=\s*[\'"]?\1[\'"]?', re.I), "TAUTOLOGY_INJECTION", 0.95),
        (re.compile(r'\b(?:OR|AND)\s+\d+\s*=\s*\d+', re.I), "NUMERIC_TAUTOLOGY_INJECTION", 0.95),
        (re.compile(r'\bUNION\s+(?:ALL\s+)?SELECT\b', re.I), "UNION_BASED_EXFILTRATION", 0.95),
        (re.compile(r';\s*(?:DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT)\b', re.I), "STACKED_DESTRUCTIVE_QUERY", 0.90),
        (re.compile(r'--\s*|\/\*.*?\*\/|#\s*', re.S), "COMMENT_TRUNCATION_EXPLOIT", 0.85),
        (re.compile(r'\b(?:SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)\b', re.I), "TIME_BASED_BLIND_INJECTION", 0.90),
        (re.compile(r'\b(?:XP_CMDSHELL|EXEC\s*\(|EXECUTE\s*\(|LOAD_FILE)\b', re.I), "COMMAND_EXECUTION_ATTEMPT", 0.95),
    ]

    @classmethod
    def scan_for_injection(cls, sql_query: str) -> Dict[str, Any]:
        """Audits a raw SQL query string for injection vectors."""
        threats_found = []
        highest_risk = 0.0

        for pattern, threat_type, confidence in cls.THREAT_PATTERNS:
            matches = list(pattern.finditer(sql_query))
            for m in matches:
                threats_found.append({
                    "threat_type": threat_type,
                    "matched_pattern": m.group(0),
                    "confidence": confidence,
                    "position": m.span(),
                })
                if confidence > highest_risk:
                    highest_risk = confidence

        is_malicious = len(threats_found) > 0

        return {
            "is_vulnerable": is_malicious,
            "risk_score": highest_risk,
            "threats_count": len(threats_found),
            "threats": threats_found,
            "verdict": "BLOCKED" if highest_risk >= 0.90 else ("FLAGGED" if is_malicious else "SAFE"),
        }

    @classmethod
    def verify_parameterization(
        cls,
        query_template: str,
        parameters: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Verifies that user data is bound via placeholders rather than concatenated directly."""
        # Detect standard parameterized markers: ?, :name, %s, $1
        has_question_marks = "?" in query_template
        named_placeholders = re.findall(r':[a-zA-Z_][a-zA-Z0-9_]*', query_template)
        has_py_placeholders = "%s" in query_template
        has_pg_placeholders = bool(re.search(r'\$\d+', query_template))

        total_placeholders = (
            query_template.count("?")
            + len(named_placeholders)
            + query_template.count("%s")
            + len(re.findall(r'\$\d+', query_template))
        )

        has_params = parameters is not None and (len(parameters) > 0 if isinstance(parameters, (list, dict, tuple)) else True)

        is_properly_parameterized = (total_placeholders > 0 and has_params) or (total_placeholders == 0 and not has_params)

        return {
            "is_parameterized": total_placeholders > 0,
            "total_placeholders": total_placeholders,
            "placeholder_styles_detected": {
                "positional_qmark": has_question_marks,
                "named_colon": len(named_placeholders) > 0,
                "printf_format": has_py_placeholders,
                "postgres_dollar": has_pg_placeholders,
            },
            "parameters_supplied": has_params,
            "safe_for_execution": is_properly_parameterized,
        }

    @classmethod
    def sanitize_identifier(cls, identifier: str) -> Dict[str, Any]:
        """Validates that a dynamic table or column name strictly consists of alphanumeric characters and underscores."""
        clean_id = identifier.strip()
        is_valid = bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{0,63}$', clean_id))

        return {
            "raw_identifier": identifier,
            "is_valid": is_valid,
            "sanitized_identifier": f'"{clean_id}"' if is_valid else None,
            "error": None if is_valid else "Invalid SQL identifier: must be alphanumeric starting with letter/underscore and <= 64 chars.",
        }
