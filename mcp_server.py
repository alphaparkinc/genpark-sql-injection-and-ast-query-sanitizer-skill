"""MCP server for SQL Injection and AST Query Sanitizer."""
import sys
import json
from client import SQLSanitizerEngine


def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "scan_for_injection",
                    "description": "Scans raw SQL statement for tautologies, UNION exfiltration, stacked queries, and comment truncations",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "sql_query": {"type": "string"},
                        },
                        "required": ["sql_query"],
                    },
                },
                {
                    "name": "verify_parameterization",
                    "description": "Verifies that query template properly isolates parameters via bind placeholders",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query_template": {"type": "string"},
                            "parameters": {"type": "object"},
                        },
                        "required": ["query_template"],
                    },
                },
                {
                    "name": "sanitize_identifier",
                    "description": "Validates dynamic SQL table/column identifiers against identifier injection whitelist",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "identifier": {"type": "string"},
                        },
                        "required": ["identifier"],
                    },
                },
            ]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name == "scan_for_injection":
            res = SQLSanitizerEngine.scan_for_injection(args.get("sql_query", ""))
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
        elif tool_name == "verify_parameterization":
            res = SQLSanitizerEngine.verify_parameterization(
                query_template=args.get("query_template", ""),
                parameters=args.get("parameters"),
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
        elif tool_name == "sanitize_identifier":
            res = SQLSanitizerEngine.sanitize_identifier(args.get("identifier", ""))
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}


if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
