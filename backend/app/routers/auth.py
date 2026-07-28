from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.rate_limit import limiter
from app.core.security import create_access_token, hash_password, verify_password
from app.database import get_db
from app.models.user import User
from app.schemas.auth import Token, UserCreate, UserLogin, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account",
    responses={
        201: {
            "description": "Account created",
            "content": {
                "application/json": {
                    "example": {
                        "id": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
                        "email": "alex@example.com",
                        "full_name": "Alex Hernandez",
                        "is_active": True,
                    }
                }
            },
        },
        409: {
            "description": "Email already registered",
            "content": {
                "application/json": {"example": {"detail": "Email already registered"}}
            },
        },
        429: {"description": "Too many registration attempts from this IP"},
    },
)
@limiter.limit("5/minute")
async def register(
    request: Request, payload: UserCreate, db: AsyncSession = Depends(get_db)
) -> User:
    """
    Register a new user account.

    Rate limited to **5 requests/minute per IP** to blunt automated
    account-creation spam. Passwords are hashed with bcrypt before storage
    and are never logged or returned in any response.

    Example request body:
    ```json
    {"email": "alex@example.com", "password": "correct-horse-battery", "full_name": "Alex Hernandez"}
    ```
    """
    existing = await db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post(
    "/login",
    response_model=Token,
    summary="Exchange credentials for a bearer token",
    responses={
        200: {
            "description": "Login succeeded",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer",
                    }
                }
            },
        },
        401: {
            "description": "Incorrect email or password",
            "content": {
                "application/json": {"example": {"detail": "Incorrect email or password"}}
            },
        },
        429: {"description": "Too many login attempts from this IP"},
    },
)
@limiter.limit("10/minute")
async def login(
    request: Request, payload: UserLogin, db: AsyncSession = Depends(get_db)
) -> Token:
    """
    Log in with email/password and receive a JWT bearer token.

    Rate limited to **10 requests/minute per IP** -- this is the endpoint a
    credential-stuffing attack would target, so it gets the tightest limit
    in the API. The token is valid for `ACCESS_TOKEN_EXPIRE_MINUTES`
    (default 24h) and must be sent as `Authorization: Bearer <token>` on
    subsequent requests.
    """
    user = await db.scalar(select(User).where(User.email == payload.email))
    if user is None or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    token = create_access_token(subject=str(user.id))
    return Token(access_token=token)


@router.get(
    "/me",
    response_model=UserOut,
    summary="Get the currently authenticated user",
    responses={401: {"description": "Missing, expired, or invalid bearer token"}},
)
async def me(current_user: User = Depends(get_current_user)) -> User:
    """Return the profile of the user identified by the bearer token."""
    return current_user
