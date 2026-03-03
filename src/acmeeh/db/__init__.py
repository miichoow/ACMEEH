"""Database subsystem for ACMEEH.

Public API::

    from acmeeh.db import init_database, UnitOfWork
"""

from acmeeh.db.init import (
    advisory_lock,
    get_pool_health,
    init_database,
    is_pool_healthy,
    log_pool_stats,
    reinit_pool_after_fork,
)
from acmeeh.db.unit_of_work import UnitOfWork

__all__ = [
    "UnitOfWork",
    "advisory_lock",
    "get_pool_health",
    "init_database",
    "is_pool_healthy",
    "log_pool_stats",
    "reinit_pool_after_fork",
]
