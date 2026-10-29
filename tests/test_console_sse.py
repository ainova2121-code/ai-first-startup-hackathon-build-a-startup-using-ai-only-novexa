"""sse_events: a published update reaches the stream as a rendered fragment, a target that
vanished between publish and read is silently skipped (not an error, not a stall), and the
generator cleans up its subscription when the connection closes."""

import asyncio

from purpleteam.console.events import Broadcaster
from purpleteam.console.sse import KEEPALIVE_SECONDS, sse_events


def test_a_published_update_is_rendered_and_streamed():
    broadcaster = Broadcaster()

    async def scenario():
        gen = sse_events(broadcaster, lambda target_id: f"<tr id='target-{target_id}'>x</tr>")

        async def publish_soon():
            await asyncio.sleep(0.02)
            broadcaster.publish({"target_id": "t1"})

        asyncio.create_task(publish_soon())
        return await gen.__anext__()

    chunk = asyncio.run(asyncio.wait_for(scenario(), timeout=2))
    assert chunk == "event: fleet-update\ndata: <tr id='target-t1'>x</tr>\n\n"


def test_a_vanished_target_is_skipped_and_does_not_stall_the_next_real_update():
    broadcaster = Broadcaster()
    known = {"real"}  # only "real" resolves to a fragment; "gone" simulates a mid-race removal

    async def scenario():
        gen = sse_events(broadcaster, lambda target_id: f"<tr>{target_id}</tr>" if target_id in known else None)

        async def publish_both():
            await asyncio.sleep(0.02)
            broadcaster.publish({"target_id": "gone"})
            broadcaster.publish({"target_id": "real"})

        asyncio.create_task(publish_both())
        return await gen.__anext__()  # must be "real" -- "gone" never produces a chunk at all

    chunk = asyncio.run(asyncio.wait_for(scenario(), timeout=2))
    assert chunk == "event: fleet-update\ndata: <tr>real</tr>\n\n"


def test_the_keepalive_interval_fits_inside_typical_proxy_idle_timeouts():
    assert KEEPALIVE_SECONDS <= 30


def test_cancelling_the_connection_unsubscribes_it():
    """A browser tab closing cancels the route's read of this generator -- the subscription must
    not leak, or a long-running console would accumulate dead subscribers forever."""
    broadcaster = Broadcaster()

    async def scenario():
        gen = sse_events(broadcaster, lambda target_id: "x")
        task = asyncio.create_task(gen.__anext__())
        await asyncio.sleep(0.02)  # let it run up to its first suspend point (subscribed, waiting)
        assert len(broadcaster._subscribers) == 1
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert len(broadcaster._subscribers) == 0

    asyncio.run(asyncio.wait_for(scenario(), timeout=2))
