from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_engine():
    from bbot.core.engine import EngineClient, EngineServer

    counter = 0

    class TestEngineServer(EngineServer):

        CMDS = {
            0: "return_thing",
            1: "yield_stuff",
        }

        async def return_thing(self):
            return "thing"

        async def yield_stuff(self, n):
            nonlocal counter
            for i in range(n):
                yield f"thing{i}"
                counter += 1
                await asyncio.sleep(0.1)

    class TestEngineClient(EngineClient):

        SERVER_CLASS = TestEngineServer

        async def return_thing(self):
            return await self.run_and_return("return_thing")

        async def yield_stuff(self, n):
            async for _ in self.run_and_yield("yield_stuff", n):
                yield _

    # test return functionality
    test_engine = TestEngineClient()
    return_res = await test_engine.return_thing()
    assert return_res == "thing"

    # test async generator
    assert counter == 0
    yield_res = [r async for r in test_engine.yield_stuff(13)]
    assert yield_res == [f"thing{i}" for i in range(13)]
    assert len(yield_res) == 13
    assert counter == 13

    # test async generator with cancellation
    counter = 0
    agen = test_engine.yield_stuff(1000)
    async for r in agen:
        if counter > 10:
            await agen.aclose()
            break
    await asyncio.sleep(5)
    assert counter < 15
