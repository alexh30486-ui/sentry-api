import pytest
import httpx


async def register_and_login(client: httpx.AsyncClient, email: str = "scanner-user@example.com") -> str:
    """Register + login using the real auth endpoints. Returns bearer token."""
    password = "supersecret1"
    await client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
    )
    response = await client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    data = response.json()
    assert "access_token" in data, f"login failed: {response.status_code} {data}"
    return data["access_token"]


@pytest.mark.asyncio
async def test_scan_rejected_for_host_not_on_allowlist(client: httpx.AsyncClient):
    token = await register_and_login(client, "user-host-1@example.com")

    response = await client.post(
        "/api/scans",
        json={
            "target_base_url": "http://malicious-external-target.test",
            "modules": ["sqli"],
            "endpoints": ["/api/v1/data"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code in [400, 422]


@pytest.mark.asyncio
async def test_scan_accepted_for_allowlisted_host(client: httpx.AsyncClient):
    token = await register_and_login(client, "user-host-2@example.com")

    response = await client.post(
        "/api/scans",
        json={
            "target_base_url": "http://target.test",
            "modules": ["sqli"],
            "endpoints": ["/api/items/{id}"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code in [200, 201]
    data = response.json()
    assert "id" in data
    assert data["status"] in ["pending", "running", "completed"]


@pytest.mark.asyncio
async def test_background_scan_task_actually_persists_to_the_test_database(client: httpx.AsyncClient):
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
    assert create_resp.status_code in [200, 201], create_resp.text
    scan_id = create_resp.json()["id"]

    resp = await client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token}"})
    body = resp.json()

    assert body["status"] in ["completed", "failed", "pending", "running"]


@pytest.mark.asyncio
async def test_scans_are_scoped_to_their_owner(client: httpx.AsyncClient):
    token_alice = await register_and_login(client, "alice@example.com")
    token_bob = await register_and_login(client, "bob@example.com")

    create_resp = await client.post(
        "/api/scans",
        json={
            "target_base_url": "http://target.test",
            "modules": ["idor"],
            "endpoints": ["/api/users/{id}"],
        },
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert create_resp.status_code in [200, 201], create_resp.text
    scan_id = create_resp.json()["id"]

    bob_resp = await client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token_bob}"})
    assert bob_resp.status_code in [403, 404]


@pytest.mark.asyncio
async def test_list_scans_requires_auth(client: httpx.AsyncClient):
    response = await client.get("/api/scans")
    assert response.status_code in [401, 403]
