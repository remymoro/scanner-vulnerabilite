import fakeredis

from scanner.repositories.redis_stream import RedisScanEventStream


async def test_publish_then_read_returns_events_in_order():
    stream = RedisScanEventStream(fakeredis.FakeAsyncRedis())
    await stream.publish("s1", "check_complete", {"check_name": "WAF"})
    await stream.publish("s1", "scan_complete", {"overall_score": 80})

    events = await stream.read("s1", block_ms=10)

    assert [e.event for e in events] == ["check_complete", "scan_complete"]
    assert events[0].data == {"check_name": "WAF"}


async def test_read_resumes_after_last_id():
    stream = RedisScanEventStream(fakeredis.FakeAsyncRedis())
    first = await stream.publish("s1", "check_complete", {"n": 1})
    await stream.publish("s1", "scan_complete", {"n": 2})

    events = await stream.read("s1", last_id=first, block_ms=10)

    assert [e.event for e in events] == ["scan_complete"]


async def test_streams_are_isolated_per_scan():
    stream = RedisScanEventStream(fakeredis.FakeAsyncRedis())
    await stream.publish("s1", "scan_complete", {})
    assert await stream.read("s2", block_ms=10) == []
