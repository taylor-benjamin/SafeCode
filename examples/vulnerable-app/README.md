# Intentionally vulnerable demo app

**Do not deploy or copy this code.** It exists so SAFECODE has something to find in demos and tests.

| File | Problems | Checklist rules |
|------|----------|-----------------|
| `app.py` | hardcoded API key, SQL injection, `eval`, `http://` URL, `verify=False` | SC-001, SC-003, SC-008 |
| `server.js` | SQL injection, `eval`, `http://` URL, `rejectUnauthorized: false` | SC-003, SC-008 |
| `requirements.txt`, `package-lock.json` | old dependency versions with known CVEs | SC-002 |

The API key in `app.py` is a random string that is not valid for any service. It looks like a credential so that Gitleaks flags it.

Secrets hidden in *git history* can't be demonstrated inside this folder, because it isn't its own repository. The test suite covers that case by building a temporary repo (see `tests/test_scanners_integration.py`).
