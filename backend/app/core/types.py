"""
Cross-dialect UUID column type.

The models originally used `postgresql.UUID` directly, which is efficient in
production but makes the models impossible to exercise against SQLite in
tests -- and spinning up a real Postgres container for every test run is
slow and a bad fit for CI. This TypeDecorator stores a native UUID on
Postgres and falls back to a CHAR(32) hex string on any other dialect
(SQLite, used by the test suite), so the same models work against both
without any test-only model duplication.
"""
from __future__ import annotations

import uuid

from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.types import CHAR, TypeDecorator


class GUID(TypeDecorator):
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return str(value)
        if not isinstance(value, uuid.UUID):
            value = uuid.UUID(value)
        return value.hex

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)
