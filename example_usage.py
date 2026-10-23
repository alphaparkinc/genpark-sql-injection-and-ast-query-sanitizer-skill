"""Example usage for SQL Injection and AST Query Sanitizer."""
from client import SQLSanitizerEngine


def main():
    print("=== 1. Scanning Malicious SQL Injections ===")
    malicious_queries = [
        "SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
        "SELECT id, name FROM products WHERE category = 'tech' UNION SELECT username, password_hash FROM admin_users",
        "SELECT * FROM orders WHERE id = 120; DROP TABLE customers; --",
    ]

    for q in malicious_queries:
        res = SQLSanitizerEngine.scan_for_injection(q)
        print(f"\nQuery: {q}")
        print(f"Verdict: {res['verdict']} (Risk: {res['risk_score']})")
        for t in res["threats"]:
            print(f"  - Detected [{t['threat_type']}]: '{t['matched_pattern']}'")

    print("\n=== 2. Verifying Safe Parameterized Queries ===")
    safe_template = "SELECT * FROM users WHERE email = :user_email AND status = :status"
    param_check = SQLSanitizerEngine.verify_parameterization(
        query_template=safe_template,
        parameters={"user_email": "dev@genpark.ai", "status": "active"},
    )
    print("Is Parameterized:", param_check["is_parameterized"])
    print("Safe for Execution:", param_check["safe_for_execution"])
    print("Styles:", param_check["placeholder_styles_detected"])

    print("\n=== 3. Dynamic SQL Identifier Sanitization ===")
    valid_id = "user_billing_history"
    invalid_id = "users; DROP TABLE sessions; --"

    print(f"Identifier '{valid_id}':", SQLSanitizerEngine.sanitize_identifier(valid_id)["sanitized_identifier"])
    print(f"Identifier '{invalid_id}': Valid =", SQLSanitizerEngine.sanitize_identifier(invalid_id)["is_valid"])


if __name__ == "__main__":
    main()
