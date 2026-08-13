## 1. Planning Objective

The purpose of this document is to define the engineering work required to move the API Security Scanner from its current development state toward a reliable, testable, and maintainable security-testing application.

The project should prioritize correctness and security boundaries before adding additional features.

---

# 2. Current State

| Component | Current State |
|---|---|
| Authentication | Implemented |
| JWT authentication | Implemented |
| Scan creation | Implemented |
| Scan ownership | Implemented |
| Host allow-list | Implemented |
| SQLi scanner | Implemented |
| IDOR scanner | Implemented; requires additional validation |
| Auth bypass scanner | Implemented; requires additional validation |
| Rate-limit scanner | Implemented; requires additional validation |
| Scanner unit tests | Partially validated |
| Integration tests | Partially validated |
| React frontend | Implemented |
| Docker Compose | Implemented |
| Documentation | Being established |

---

# 3. Milestone 1 — Establish a Green Baseline

**Priority:** P0

## Objective

Create a reproducible baseline where the project can be installed, tested, and understood without relying on undocumented local state.

### Tasks

- [ ] Pin `bcrypt==4.0.1`.
- [ ] Perform a clean dependency installation.
- [ ] Run the complete backend test suite.
- [ ] Record every remaining failure.
- [ ] Determine the root cause of every remaining failure.
- [ ] Fix regressions before adding new functionality.
- [ ] Re-run the complete backend test suite.
- [ ] Confirm the focused SQLi tests remain green.
- [ ] Confirm scan creation tests remain green.
- [ ] Commit documentation.
- [ ] Push the completed milestone.

### Validation

```bash
pytest -v
````

Focused validation:

```bash
pytest backend/tests/scanners/test_sqli.py backend/tests/test_scan_creation.py -v
```

---

# 4. Milestone 2 — Authentication and Authorization Hardening

**Priority:** P0

## Objective

Ensure that authentication and authorization cannot be bypassed through normal application paths.

### Authentication

* [ ] Test successful registration.
* [ ] Test successful login.
* [ ] Test invalid credentials.
* [ ] Test malformed credentials.
* [ ] Test protected routes without authentication.
* [ ] Test expired or invalid JWT behavior.
* [ ] Confirm authentication test helpers use the actual application API.

### Authorization

* [ ] Confirm users can retrieve their own scans.
* [ ] Confirm users cannot retrieve another user's scans.
* [ ] Confirm users cannot access another user's findings.
* [ ] Add explicit cross-user regression tests.
* [ ] Verify authorization failures return the expected status.

### Definition of done

Authentication and ownership tests should pass consistently from a clean environment.

---

# 5. Milestone 3 — Host Allow-List Security

**Priority:** P0

## Objective

Preserve the scanner's core safety boundary.

### Tasks

* [ ] Document `ALLOWED_SCAN_HOSTS`.
* [ ] Confirm production defaults remain restrictive.
* [ ] Confirm unauthorized hosts are rejected.
* [ ] Add a regression test for an unauthorized host.
* [ ] Confirm `target.test` exists only as a test fixture override.
* [ ] Confirm test configuration cannot accidentally weaken production settings.
* [ ] Review configuration caching behavior.

### Definition of done

A scan cannot execute against a target outside the configured allow-list.

---

# 6. Milestone 4 — SQL Injection Scanner

**Priority:** P1

## Current state

The SQL injection scanner currently supports:

* error-based detection;
* boolean-blind detection.

The focused tests currently pass.

### Tasks

* [x] Correct URL-decoding behavior in the test mock.
* [x] Correct boolean-blind length-difference handling.
* [x] Validate focused SQLi tests.
* [ ] Validate SQLi behavior against the complete test suite.
* [ ] Review false-positive conditions.
* [ ] Review false-negative conditions.
* [ ] Add additional safe payload variants if required.
* [ ] Document detection assumptions.

### Optional future work

A timing-based blind SQLi detector may be evaluated later.

This should not be enabled by default without sufficient testing because timing-based detection can increase false positives and create additional load.

---

# 7. Milestone 5 — IDOR Scanner

**Priority:** P1

## Objective

Bring the IDOR scanner to the same testing standard as the SQLi scanner.

### Tasks

* [ ] Review implementation.
* [ ] Identify the expected endpoint structure.
* [ ] Build isolated unit tests.
* [ ] Mock authorized object access.
* [ ] Mock unauthorized object access.
* [ ] Test neighboring identifiers.
* [ ] Verify evidence generation.
* [ ] Verify severity assignment.
* [ ] Verify remediation guidance.
* [ ] Add integration coverage where appropriate.

### Definition of done

The scanner has repeatable tests proving both detection and non-detection behavior.

---

# 8. Milestone 6 — Authentication Bypass Scanner

**Priority:** P1

## Objective

Validate that the authentication bypass scanner reliably identifies missing or weak authentication controls without generating destructive traffic.

### Tasks

* [ ] Review implementation.
* [ ] Test unauthenticated requests.
* [ ] Test malformed authentication.
* [ ] Test invalid tokens.
* [ ] Test protected HTTP methods.
* [ ] Test expected authenticated behavior.
* [ ] Validate evidence.
* [ ] Validate severity.
* [ ] Validate remediation guidance.

---

# 9. Milestone 7 — Rate-Limit Scanner

**Priority:** P1

## Objective

Validate rate-limit detection while keeping test traffic controlled.

### Tasks

* [ ] Review implementation.
* [ ] Test repeated requests.
* [ ] Test HTTP 429 behavior.
* [ ] Test rate-limit headers.
* [ ] Test positive detection.
* [ ] Test negative detection.
* [ ] Establish safe request limits.
* [ ] Confirm tests do not create unnecessary load.

---

# 10. Milestone 8 — Scanner Architecture

**Priority:** P1

## Objective

Keep every scanner modular and independently testable.

Each scanner should:

* [ ] Extend the shared scanner abstraction.
* [ ] Receive a standard scan context.
* [ ] Return structured finding data.
* [ ] Avoid unnecessary persistence coupling.
* [ ] Have deterministic unit tests where possible.
* [ ] Define clear severity behavior.
* [ ] Produce evidence.
* [ ] Produce remediation guidance.

### Adding a new scanner

The expected workflow is:

```text
1. Create scanner implementation.
2. Register scanner.
3. Add scanner module type.
4. Add tests.
5. Add integration coverage.
6. Update README.
7. Update JOURNAL.md.
8. Update PLANNING.md.
9. Commit the change.
```

---

# 11. Milestone 9 — Backend Observability

**Priority:** P2

## Objective

Make scan execution understandable when something fails.

### Tasks

* [ ] Review scan status transitions.
* [ ] Ensure scanner failures are recorded.
* [ ] Populate `error_message` consistently.
* [ ] Review background task failure behavior.
* [ ] Add structured logging where useful.
* [ ] Make partial scan results observable.
* [ ] Confirm findings are persisted safely.

---

# 12. Milestone 10 — Frontend Validation

**Priority:** P2

## Objective

Validate the React dashboard against the real backend.

### Tasks

* [ ] Start backend.
* [ ] Start frontend.
* [ ] Register account.
* [ ] Log in.
* [ ] Create scan.
* [ ] View scan status.
* [ ] View findings.
* [ ] Verify severity display.
* [ ] Verify OWASP category display.
* [ ] Verify remediation display.
* [ ] Test error states.
* [ ] Test empty states.
* [ ] Test authorization behavior.

---

# 13. Milestone 11 — Docker Validation

**Priority:** P2

## Objective

Confirm the documented development environment works from a clean state.

### Tasks

* [ ] Start Docker Compose.
* [ ] Confirm PostgreSQL starts.
* [ ] Confirm backend starts.
* [ ] Confirm frontend starts.
* [ ] Run migrations.
* [ ] Verify API health.
* [ ] Verify dashboard access.
* [ ] Run backend tests in the container.
* [ ] Verify environment variables.
* [ ] Confirm no secrets are committed.

---

# 14. Documentation Plan

Documentation should remain synchronized with implementation.

### `README.md`

The README should explain:

* what the project does;
* what the scanner modules do;
* the safety model;
* technology stack;
* quick start;
* testing;
* architecture;
* extension workflow;
* repository layout.

### `JOURNAL.md`

The journal records:

* what was attempted;
* what failed;
* root causes;
* fixes;
* test results;
* engineering decisions;
* remaining issues.

### `PLANNING.md`

This file records:

* current status;
* milestones;
* priorities;
* unfinished work;
* definition of done.

---

# 15. Security Scope

The scanner is intentionally constrained.

## Supported

* Authorized API security testing.
* Local development targets.
* Explicitly allow-listed hosts.
* Detection-oriented testing.
* Non-destructive payloads.
* Authenticated scan workflows.

## Explicitly out of scope

* Arbitrary internet scanning.
* Unauthorized target scanning.
* Destructive SQL operations.
* Destructive application mutations.
* General-purpose offensive automation.
* Full authenticated crawling.
* Full OpenAPI-driven discovery.

---

# 16. Git Workflow

## Existing code fix

```text
13103d1 fix: auth helper, allow-list for tests, boolean-blind SQLi detection
```

## Documentation commit

After reviewing all three documentation files:

```bash
git add README.md JOURNAL.md PLANNING.md
git commit -m "docs: establish project journal planning and README"
```

## Verify

```bash
git status
git log -3 --oneline
```

## Push

```bash
git push origin main
```

---

# 17. Definition of Done

The current project milestone is complete when:

* [ ] Dependencies install cleanly.
* [ ] Full backend tests have been executed.
* [ ] Remaining failures are understood.
* [ ] Authentication is validated.
* [ ] Authorization is validated.
* [ ] Host allow-list behavior is validated.
* [ ] SQLi scanner tests pass.
* [ ] IDOR scanner tests are established.
* [ ] Authentication bypass tests are established.
* [ ] Rate-limit tests are established.
* [ ] README reflects actual implementation.
* [ ] JOURNAL.md documents actual engineering history.
* [ ] PLANNING.md reflects current priorities.
* [ ] Git status is clean.
* [ ] Documentation is committed.
* [ ] Changes are pushed to the repository.

---

# 18. Planning Philosophy

The project should not measure progress by the number of features added.

Engineering progress should be measured by:

```text
Reproducibility
    ↓
Correctness
    ↓
Test coverage
    ↓
Security boundaries
    ↓
Observability
    ↓
Usability
    ↓
Feature expansion
```

The objective is to make the scanner trustworthy before making it larger.

EOF

echo "PLANNING.md created."
git status --short

```
```
