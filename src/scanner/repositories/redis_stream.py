"""
Flux d'événements de scan sur Redis Streams.

Pourquoi un Stream et pas du Pub/Sub ?
→ Pub/Sub oublie tout ce qui n'est pas écouté à l'instant T. Un Stream
  garde les événements : un client qui se connecte en retard, ou qui se
  reconnecte après une coupure, relit depuis où il s'est arrêté.
"""

import json
from typing import Any

from redis.asyncio import Redis

from scanner.core.interfaces.event_stream import IScanEventStream, StreamEvent

STREAM_TTL_SECONDS = 3600


def _text(value: bytes | str) -> str:
    return value.decode() if isinstance(value, bytes) else value


class RedisScanEventStream(IScanEventStream):
    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    @staticmethod
    def _key(scan_id: str) -> str:
        return f"scan:{scan_id}:events"

    async def publish(self, scan_id: str, event: str, data: dict[str, Any]) -> str:
        key = self._key(scan_id)
        entry_id = await self.redis.xadd(key, {"event": event, "data": json.dumps(data)})
        await self.redis.expire(key, STREAM_TTL_SECONDS)
        return _text(entry_id)

    async def read(
        self, scan_id: str, last_id: str = "0-0", block_ms: int = 15000
    ) -> list[StreamEvent]:
        response = await self.redis.xread({self._key(scan_id): last_id}, count=100, block=block_ms)
        events: list[StreamEvent] = []
        for _key, entries in response or []:
            for entry_id, fields in entries:
                values = {_text(k): _text(v) for k, v in fields.items()}
                events.append(
                    StreamEvent(_text(entry_id), values["event"], json.loads(values["data"]))
                )
        return events
