from tests.conftest import register_and_login


async def test_scan_rejected_for_host_not_on_allowlist(client):
    token = await register_and_login(client, "scanner-user@example.com")

    resp = await client.post(
        "/api/scans",
        json={
            "target_base_url": "http://evil.example.com",
            "modules": ["rate_limit"],
            "endpoints": ["/api/x"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 400
    assert "allow-list" in resp.json()["detail"]


async def test_scan_accepted_for_allowlisted_host(client):
    token = await register_and_login(client, "scanner-user-2@example.com")

    resp = await client.post(
        "/api/scans",
        json={
            "target_base_url": "http://localhost:9",  # nothing listens here; the scan will just fail fast
            "modules": ["rate_limit"],
            "endpoints": ["/api/x"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "pending"
    assert body["target_base_url"] == "http://localhost:9"


async def test_background_scan_task_actually_persists_to_the_test_database(client):
    """
    Regression test for a real bug found during review: `run_scan` used to
    import the production `AsyncSessionLocal` directly instead of going
    through dependency injection, so it silently bypassed
    `dependency_overrides[get_db]` in tests. It only "worked" before because
    the fake production Postgres host was unreachable and failed fast --
    the scan's final state was never actually being written anywhere this
    test suite could see it.

    Now that `run_scan` receives its session-maker via the
    `get_sessionmaker` dependency (also overridden in `conftest.py`), the
    scan it runs in the background writes its final status to the same
    in-memory test database this test queries -- so this assertion is only
    meaningful because that wiring is now correct.
    """
    token = await register_and_login(client, "scanner-user-3@example.com")

    create_resp = await client.post(
        "/api/scans",
        json={
            "target_base_url": "http://localhost:9",
            "modules": ["rate_limit"],
            "endpoints": ["/api/x"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    scan_id = create_resp.json()["id"]

    # By the time the AsyncClient call above returns, the ASGITransport has
    # already run the background task to completion in the same event loop
    # -- so the scan should already be in a terminal state.
    resp = await client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token}"})
    body = resp.json()
    assert body["status"] == "failed"
    assert body["error_message"] is not None


async def test_scans_are_scoped_to_their_owner(client):
    token_a = await register_and_login(client, "owner-a@example.com")
    token_b = await register_and_login(client, "owner-b@example.com")

    create_resp = await client.post(
        "/api/scans",
        json={"target_base_url": "http://localhost:9", "modules": ["rate_limit"], "endpoints": []},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    scan_id = create_resp.json()["id"]

    # Owner B should not be able to see owner A's scan.
    resp = await client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert resp.status_code == 404

    # Owner A can.
    resp = await client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 200


async def test_list_scans_requires_auth(client):
    resp = await client.get("/api/scans")
    assert resp.status_code == 401
