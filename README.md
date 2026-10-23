# genpark-sql-injection-and-ast-query-sanitizer-skill

Lexical SQL injection vulnerability scanner, AST query sanitizer, and parameterized statement verifier.

100% Python Standard Library implementation with zero external dependencies.

## Key Capabilities

- **Heuristic & Lexical SQL Injection Scanner**: Identifies tautology exploits (`OR 1=1`), UNION-based exfiltration, stacked query execution, and comment truncation.
- **Parameterized Query Verification**: Inspects SQL query templates across standard placeholder formats (`?`, `:name`, `%s`, `$1`) to enforce bind isolation.
- **Dynamic Identifier Sanitizer**: Enforces strict alphanumeric/underscore whitelist guards on table and column names to prevent dynamic identifier injection attacks.
- **Deterministic Risk Scoring & Verdicts**: Emits actionable `BLOCKED`, `FLAGGED`, or `SAFE` audit ratings.

## Architecture

```
[Raw SQL Query / Parameterized Template + Data Bindings]
                           │
                           ▼
┌───────────────────────────────────────────────────────┐
│                 SQLSanitizerEngine                    │
│  - Threat Token Matcher (Tautologies, UNION, Stacked) │
│  - Parameter Placeholder Completeness Verifier        │
│  - Whitelist Dynamic Identifier Normalizer            │
│  - Risk Confidence Arbiter (BLOCKED / FLAGGED / SAFE) │
└───────────────────────────────────────────────────────┘
                           │
                           ▼
[Security Verdict / Flagged Threats / Sanitized Identifier]
```

## MCP Server Integration

Run standard MCP stdio server:
```bash
python mcp_server.py
```

Exposed Tools:
- `scan_for_injection`: Scans raw SQL statement for tautologies, UNION exfiltration, stacked queries, and comment truncations.
- `verify_parameterization`: Verifies that query template properly isolates parameters via bind placeholders.
- `sanitize_identifier`: Validates dynamic SQL table/column identifiers against identifier injection whitelist.

## Quickstart (Python API)

```python
from client import SQLSanitizerEngine

audit = SQLSanitizerEngine.scan_for_injection("SELECT * FROM users WHERE id = 1 OR 'a'='a'")
print("Verdict:", audit["verdict"])
print("Threats Count:", audit["threats_count"])
```

---

## GenPark Ecosystem

- **Official Website**: [https://www.genpark.ai](https://www.genpark.ai)
- **LinkedIn Page**: [https://www.linkedin.com/company/92955550](https://www.linkedin.com/company/92955550)
