class BrowserEngine:
    """
    A browser BBOT can drive. An engine installs its browser and launches it. Everything else (pages,
    challenges, crash recovery, the visit cache) is engine-independent and lives in BrowserHelper.

    `launch()` returns a browser with Playwright's async API, which covers Camoufox, Patchright, and stock
    Playwright Chromium/Firefox/WebKit. BrowserHelper uses only this part of that API, so an engine without it
    needs an adapter for just this subset:

        Browser:        new_context(), close(), on("disconnected")
        BrowserContext: new_page(), route(), close()
        Page:           goto(), on("response"), main_frame, title(), content(), screenshot(), evaluate(),
                        wait_for_load_state(), close(), is_closed()
        Response:       url, status, frame, request (method, resource_type, is_navigation_request()),
                        body(), headers_array(), server_addr()
        Route:          request (url, headers), abort(), continue_()
    """

    name = ""
    # installed by the deps installer only when web.enable_browser is on, in the same shape as a module's deps
    deps = {}
    # the directory under BBOT's tools dir that deps install the browser into
    install_dirname = ""

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper

    async def launch(self):
        """Start a browser and return it."""
        raise NotImplementedError

    async def stop(self):
        """Release whatever launch() started besides the browser itself (e.g. a driver process)."""

    @property
    def errors(self):
        """Exception types that mean the browser or a page failed."""
        return ()
