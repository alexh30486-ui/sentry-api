from tests.conftest import register_and_login


async def test_register_returns_created_user_without_password(client):
    resp = await client.post(
        "/api/auth/register",
        json={"email": "alex@example.com", "password": "supersecret1", "full_name": "Alex"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == "alex@example.com"
    assert "password" not in body
    assert "hashed_password" not in body


async def test_duplicate_registration_returns_409(client):
    payload = {"email": "dup@example.com", "password": "supersecret1"}
    first = await client.post("/api/auth/register", json=payload)
    second = await client.post("/api/auth/register", json=payload)
    assert first.status_code == 201
    assert second.status_code == 409


async def test_full_login_flow_returns_usable_token(client):
    token = await register_and_login(client, "flow@example.com")
    resp = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "flow@example.com"


async def test_wrong_password_returns_401(client):
    await client.post(
        "/api/auth/register", json={"email": "wrongpw@example.com", "password": "supersecret1"}
    )
    resp = await client.post(
        "/api/auth/login", json={"email": "wrongpw@example.com", "password": "not-it"}
    )
    assert resp.status_code == 401


async def test_me_rejects_missing_token(client):
    resp = await client.get("/api/auth/me")
    assert resp.status_code == 401


async def test_me_rejects_garbage_token(client):
    resp = await client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


async def test_login_is_rate_limited_after_ten_attempts_per_minute(client):
    """The login endpoint is capped at 10/minute per IP. Hammer it with bad
    credentials and confirm it starts returning 429 instead of just 401
    forever -- that's the actual brute-force protection this limit exists
    for."""
    await client.post(
        "/api/auth/register", json={"email": "bruteforce@example.com", "password": "supersecret1"}
    )

    statuses = []
    for _ in range(13):
        resp = await client.post(
            "/api/auth/login",
            json={"email": "bruteforce@example.com", "password": "wrong-guess"},
        )
        statuses.append(resp.status_code)

    assert statuses[:10] == [401] * 10
    assert 429 in statuses[10:]


async def test_register_is_rate_limited_after_five_attempts_per_minute(client):
    """The register endpoint is capped at 5/minute per IP to blunt
    automated account-creation spam."""
    statuses = []
    for i in range(7):
        resp = await client.post(
            "/api/auth/register",
            json={"email": f"spam{i}@example.com", "password": "supersecret1"},
        )
        statuses.append(resp.status_code)

    assert statuses[:5] == [201] * 5
    assert 429 in statuses[5:]
