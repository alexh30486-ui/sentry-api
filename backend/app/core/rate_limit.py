"""
Shared slowapi Limiter instance.

Kept in its own module (rather than instantiated in factory.py) so router
modules can import it directly for the `@limiter.limit(...)` decorator
without a circular import back to the app factory.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
