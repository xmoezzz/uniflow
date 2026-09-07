# Built-in security baseline

The UniFlow 1.0 baseline contains 200 unique direct checks:

| Pack | Rules | Scope |
|---|---:|---|
| `cert-c-cpp.yml` | 75 | C/C++ memory, string, I/O, error handling, command execution, SQL, TLS, XML, permissions, privilege, dynamic loading, concurrency, and ownership hazards |
| `python-security.yml` | 50 | Dynamic execution, unsafe deserialization, command/SQL/LDAP injection, TLS/crypto, archive handling, Django/Flask/Jinja configuration, JWT, AWS, and cleartext transport |
| `java-security.yml` | 50 | Command/SQL/expression execution, native and framework deserialization, XML/XXE, TLS/crypto, Spring Security, CORS/cookies, reflection/native loading, Android WebView, and archive traversal |
| `common-security.yml` | 25 | Private keys, provider-specific access tokens, embedded credentials, hardcoded secrets, cleartext endpoints, and disabled TLS verification |

The common pack runs for every supported language frontend. The C/C++, Java, and Python packs add ecosystem-specific checks on top of those shared rules.

Rules use structured HIR call constraints where the frontend exposes the required information. Source-only patterns are used for language constructs, configuration assignments, and signatures that are not represented as calls. Confidence indicates expected precision: `high` rules are specific API/configuration signatures, `medium` rules need local review, and `low` rules are intentionally broad audit prompts.

This catalog is a practical baseline, not a claim of complete CERT, CWE, or OWASP conformance. Data-flow rules and MIT-derived API source/sink models are maintained separately under `rules/mit/`.
