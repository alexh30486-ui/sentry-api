set dotenv-load := true

# List all available commands
default:
    @just --list

# Bring the full stack up (Postgres + backend + frontend), building images if needed
up:
    docker compose up -d --build

# Tail logs from all services
logs:
    docker compose logs -f

# Stop and remove containers (keeps the Postgres volume)
down:
    docker compose down

# Stop containers and wipe the Postgres volume -- use for a clean slate
nuke:
    docker compose down -v

# Rebuild images from scratch, no layer cache
build:
    docker compose build --no-cache

# Run backend tests inside the backend container
test:
    docker compose exec backend pytest -v

# Run backend tests with a coverage report
test-cov:
    docker compose exec backend pytest --cov=app --cov-report=term-missing

# Open a shell in the backend container
shell-backend:
    docker compose exec backend bash

# Open a shell in the frontend container
shell-frontend:
    docker compose exec frontend sh

# Apply pending Alembic migrations
migrate:
    docker compose exec backend alembic upgrade head

# Generate a new Alembic migration from model changes: just makemigration "add foo column"
makemigration message:
    docker compose exec backend alembic revision --autogenerate -m "{{message}}"

# Roll back the last migration
migrate-down:
    docker compose exec backend alembic downgrade -1

# Open a psql shell against the scanner database
psql:
    docker compose exec db psql -U scanner -d scanner_db

# Lint/typecheck the frontend
lint-frontend:
    docker compose exec frontend npm run lint

# Restart just the backend (useful after editing scanner modules)
restart-backend:
    docker compose restart backend
