"""
Worker ARQ : exécute les scans déposés dans la file par l'API.

Lancement :  arq scanner.worker.WorkerSettings
"""

from typing import Any

from arq.connections import RedisSettings

from scanner.infrastructure.config import settings
from scanner.infrastructure.database import close_databases, init_databases
from scanner.repositories.redis_stream import RedisScanEventStream
from scanner.services.scan_jobs import run_scan_job


async def startup(ctx: dict[str, Any]) -> None:
    mongo_repo, redis_repo = await init_databases()
    ctx["mongo_repo"] = mongo_repo
    ctx["redis_repo"] = redis_repo
    ctx["event_stream"] = RedisScanEventStream(redis_repo.redis)


async def shutdown(ctx: dict[str, Any]) -> None:
    await close_databases(ctx["mongo_repo"], ctx["redis_repo"])


class WorkerSettings:
    functions = [run_scan_job]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    max_jobs = 5
    job_timeout = 300
