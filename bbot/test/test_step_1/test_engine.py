from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_engine():
    from bbot.core.engine import EngineClient, EngineServer

    counter = 0
    yield_cancelled = False
    yield_errored = False
    return_started = False
    return_finished = False
    return_cancelled = False
    return_errored = False

    class TestEngineServer(EngineServer):
        CMDS = {
            0: "return_thing",
            1: "yield_stuff",
        }

        async def return_thing(self, n):
            nonlocal return_started
            nonlocal return_finished
            nonlocal return_cancelled
            nonlocal return_errored
            try:
                return_started = True
                await asyncio.sleep(n)
                return_finished = True
                return f"thing{n}"
            except asyncio.CancelledError:
                return_cancelled = True
                raise
            except Exception:
                return_errored = True
                raise

        async def yield_stuff(self, n):
            nonlocal counter
            nonlocal yield_cancelled
            nonlocal yield_errored
            try:
                for i in range(n):
                    yield f"thing{i}"
                    counter += 1
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                yield_cancelled = True
                raise
            except Exception:
                yield_errored = True
                raise

    class TestEngineClient(EngineClient):
        SERVER_CLASS = TestEngineServer

        async def return_thing(self, n):
            return await self.run_and_return("return_thing", n)

        async def yield_stuff(self, n):
            async for _ in self.run_and_yield("yield_stuff", n):
                yield _

    test_engine = TestEngineClient()

    # test return functionality
    return_res = await test_engine.return_thing(1)
    assert return_res == "thing1"

    # test async generator
    assert counter == 0
    assert yield_cancelled is False
    yield_res = [r async for r in test_engine.yield_stuff(13)]
    assert yield_res == [f"thing{i}" for i in range(13)]
    assert len(yield_res) == 13
    assert counter == 13

    # test async generator with cancellation
    counter = 0
    yield_cancelled = False
    yield_errored = False
    agen = test_engine.yield_stuff(1000)
    async for r in agen:
        if counter > 10:
            await agen.aclose()
            break
    await asyncio.sleep(5)
    assert yield_cancelled is True
    assert yield_errored is False
    assert counter < 15

    # test async generator with error
    yield_cancelled = False
    yield_errored = False
    agen = test_engine.yield_stuff(None)
    with pytest.raises(BBOTEngineError):
        async for _ in agen:
            pass
    assert yield_cancelled is False
    assert yield_errored is True

    # test return with cancellation
    return_started = False
    return_finished = False
    return_cancelled = False
    return_errored = False
    task = asyncio.create_task(test_engine.return_thing(2))
    await asyncio.sleep(1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.1)
    assert return_started is True
    assert return_finished is False
    assert return_cancelled is True
    assert return_errored is False

    # test return with late cancellation
    return_started = False
    return_finished = False
    return_cancelled = False
    return_errored = False
    task = asyncio.create_task(test_engine.return_thing(1))
    await asyncio.sleep(2)
    task.cancel()
    result = await task
    assert result == "thing1"
    assert return_started is True
    assert return_finished is True
    assert return_cancelled is False
    assert return_errored is False

    # test return with error
    return_started = False
    return_finished = False
    return_cancelled = False
    return_errored = False
    with pytest.raises(BBOTEngineError):
        result = await test_engine.return_thing(None)
    assert return_started is True
    assert return_finished is False
    assert return_cancelled is False
    assert return_errored is True

    await test_engine.shutdown()
