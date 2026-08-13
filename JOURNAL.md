## 1. Project Purpose

This project is a local-first API security scanner designed to test APIs that the operator owns or is explicitly authorized to assess.

The scanner is designed around controlled, detection-oriented security testing rather than unrestricted offensive scanning.

The application allows an authenticated user to:

1. Define an authorized target.
2. Select security scanner modules.
3. Create a scan.
4. Execute scanner modules against the authorized API.
5. Persist findings.
6. Review severity, evidence, OWASP category, and remediation guidance.

The system intentionally uses a host allow-list so that the scanner cannot simply be pointed at arbitrary third-party infrastructure.

---

## 2. Current Scanner Modules

The project currently contains four scanner modules.

| Module | Purpose |
|---|---|
| `sqli` | Detect error-based and boolean-blind SQL injection indicators |
| `idor` | Detect potential broken object-level authorization |
| `auth_bypass` | Detect missing or weak authentication controls |
| `rate_limit` | Detect missing or ineffective rate limiting |

The scanners are intended to remain detection-oriented and non-destructive.

---

## 3. Technology Stack

### Backend

- FastAPI
- Pydantic v2
- SQLAlchemy 2 async
- PostgreSQL
- Alembic
- JWT authentication
- `python-jose`
- `passlib`
- `bcrypt`
- `httpx`
- `respx`
- `pytest`
- `pytest-asyncio`

### Frontend

- React 18
- TypeScript
- Vite
- React Router

### Development and Infrastructure

- Docker
- Docker Compose
- `just`

---

## 4. Engineering Principles

The project is being developed around the following principles.

### 4.1 Safe by default

The scanner must verify that a target is authorized before scanner execution begins.

The host allow-list is therefore considered a core security control rather than a testing convenience.

### 4.2 Detection before exploitation

The scanner should identify security weaknesses without intentionally causing destructive changes.

Destructive database operations are outside the current project scope.

### 4.3 Evidence-driven findings

Every security finding should provide enough information for an engineer to understand:

- what was detected;
- why it was detected;
- what request or response produced the evidence;
- how severe the issue is;
- which OWASP category applies;
- how the issue can be remediated.

### 4.4 Layered testing

The project separates scanner testing from application integration testing.

Scanner tests should validate detection logic independently.

Integration tests should validate:

- authentication;
- authorization;
- scan creation;
- ownership;
- persistence;
- host allow-list enforcement.

### 4.5 Fail closed

Security-sensitive operations should reject invalid authentication and authorization rather than attempting to continue.

---

## 5. Session: 2026-08-13

### Objective

The objective of this session was to investigate the existing failing test state, identify the actual root causes, make the smallest appropriate fixes, and establish a reliable testing baseline.

---

## 6. Dependency Issue

The dependency file contained a malformed line where two packages had been joined together.

The malformed entry was:

```text
slowapi>=0.1.10email-validator>=2.1.0
````

The dependencies need to exist as separate entries:

```text
slowapi>=0.1.10
email-validator>=2.1.0
```

The session also identified a compatibility issue involving `passlib`, `bcrypt`, and Python 3.13.

The project currently relies on:

```text
bcrypt==4.0.1
```

This dependency should be explicitly pinned so a clean installation does not unexpectedly introduce a newer incompatible version.

---

## 7. Authentication Test Failure

### Observed behavior

The scan-creation integration test contained its own authentication helper.

That helper attempted to use:

```text
/api/auth/token
```

with form data.

The actual application authentication route uses:

```text
/api/auth/login
```

with a JSON request body.

### Root cause

The test helper had diverged from the actual authentication contract implemented by the application.

This caused authentication-dependent tests to fail before the scan functionality itself could be evaluated.

### Resolution

The test helper was aligned with the actual registration and login flow used by the application.

The important engineering lesson is that test helpers should not maintain an independent version of the application's API contract.

---

## 8. Host Allow-List Test Failure

### Observed behavior

The production configuration allows hosts such as:

```text
localhost
127.0.0.1
host.docker.internal
```

The integration tests used:

```text
target.test
```

The application rejected this target.

### Root cause

The rejection was actually correct behavior.

The test target was not included in the production allow-list.

### Resolution

The test environment was given a test-only override allowing:

```text
target.test
```

The production security behavior remains strict.

This distinction is important:

> The test should adapt to the security model rather than weakening the security model to satisfy the test.

---

## 9. Boolean-Blind SQL Injection Test

### Observed behavior

The scanner URL-encodes SQL injection payloads.

A payload such as:

```text
1 OR 1=1
```

can appear in the HTTP request as an encoded value such as:

```text
1+OR+1%3D1
```

The existing test mock attempted to match the raw encoded representation.

As a result, the mock failed to recognize the actual payload.

### Root cause

The scanner and test mock were operating on different representations of the same request.

### Resolution

The test mock was changed to decode the URL before checking the payload.

The detection logic was also adjusted so that a meaningful response-length difference can still act as a signal when the false-condition response body is empty.

### Engineering lesson

Security test fixtures need to model the actual wire-level behavior of the application.

---

## 10. Focused Test Results

The relevant scanner tests reached:

```text
5 passed
```

The scan-creation integration tests reached:

```text
5 passed
```

Combined focused result:

```text
10/10 relevant tests passing
```

The code changes were committed as:

```text
13103d1 fix: auth helper, allow-list for tests, boolean-blind SQLi detection
```

---

## 11. Architecture Decisions

### Scanner interface

Scanner implementations should remain modular.

A scanner receives a scan context containing information such as:

* target base URL;
* endpoints;
* HTTP client;
* request headers.

The scanner returns finding objects rather than directly coupling detection logic to persistence.

This allows the detection logic to be independently tested.

### Database testing

Integration tests use an in-memory SQLite database where practical.

This allows application-level tests to execute without requiring a running PostgreSQL service.

### Ownership

Scans are owner-scoped.

A user should only be able to access scans belonging to that user.

---

## 12. Important Repository Files

| File                                  | Responsibility                                     |
| ------------------------------------- | -------------------------------------------------- |
| `backend/app/config.py`               | Application configuration and environment settings |
| `backend/app/scanners/base.py`        | Scanner context and shared scanner behavior        |
| `backend/app/scanners/sqli.py`        | SQL injection detection                            |
| `backend/app/routers/auth.py`         | Registration and authentication                    |
| `backend/app/routers/scans.py`        | Scan creation and scan access                      |
| `backend/tests/conftest.py`           | Test application and database fixtures             |
| `backend/tests/scanners/`             | Scanner unit tests                                 |
| `backend/tests/test_scan_creation.py` | Scan creation integration tests                    |
| `frontend/`                           | React dashboard                                    |
| `docker-compose.yml`                  | Local multi-service environment                    |
| `justfile`                            | Development command runner                         |

---

## 13. Known Remaining Work

The following work has not yet been fully validated during this session:

* Full backend test suite.
* IDOR scanner test coverage.
* Authentication bypass scanner test coverage.
* Rate-limit scanner test coverage.
* Frontend behavior.
* Full Docker Compose execution.
* Production-like environment validation.

The boolean-blind SQL injection detector is currently heuristic and may require additional validation before being considered production hardened.

---

## 14. Security Boundaries

The following boundaries are intentional.

### Allowed

* Testing APIs owned by the operator.
* Testing APIs for which explicit authorization exists.
* Detection-oriented requests.
* Non-destructive security payloads.
* Authenticated scanning.
* Owner-scoped findings.

### Not allowed by project design

* Arbitrary internet scanning.
* Scanning hosts outside the configured allow-list.
* Destructive SQL operations.
* Unauthorized testing.
* General-purpose offensive automation.

---

## 15. Next Investigation

The next engineering session should begin with validation rather than feature expansion.

Recommended sequence:

1. Pin the known dependency version.
2. Perform a clean dependency installation.
3. Run the complete backend test suite.
4. Identify every remaining failure.
5. Determine whether each failure is a regression, missing test setup, or existing defect.
6. Fix blockers.
7. Re-run the complete suite.
8. Establish test parity for IDOR, authentication bypass, and rate-limit scanners.
9. Validate the frontend.
10. Validate Docker Compose.

---

## 16. Session Summary

The 2026-08-13 session identified several independent failures that initially appeared to be one broken test system.

The failures were traced to:

* malformed dependency formatting;
* `passlib`/`bcrypt` compatibility;
* an outdated authentication endpoint in a test helper;
* a test target rejected by the intended host allow-list;
* URL encoding differences in the boolean-blind SQL injection test.

The focused test suite is now green.

The immediate goal is therefore not to add more scanner features, but to establish a reproducible and trustworthy engineering baseline.

---

## 17. Git History

Current code-fix commit:

```text
13103d1 fix: auth helper, allow-list for tests, boolean-blind SQLi detection
```

Documentation should be committed separately after the files have been reviewed and verified.

EOF

echo "JOURNAL.md created."
git status --short

```
```
### Test Baseline Restored

The initial test run produced:

- 19 passed
- 14 errors

All 14 errors shared the same root cause during the `test_engine` fixture:

```text
ValueError: the greenlet library is required to use this function.
No module named 'greenlet'