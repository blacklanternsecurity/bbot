import json
import asyncio
import logging
import traceback
import warnings
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4.builder import XMLParsedAsHTMLWarning

from bbot.core.helpers.misc import truncate_filename, bytes_to_human, get_exception_chain
from bbot.errors import WordlistError, WebError
from .blast_response import BlasthttpResponse, BlasthttpHTTPError

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

log = logging.getLogger("bbot.core.helpers.web")


class WebHelper:
    """
    Main utility class for managing HTTP operations in BBOT. Uses blasthttp (Rust) as the
    HTTP engine for all requests, downloads, and wordlist retrieval.

    All requests go through the shared blasthttp client on the parent helper,
    which supports global rate limiting via ``web.http_rate_limit``.

    Attributes:
        parent_helper (object): The parent helper object containing scan configurations.
        http_debug (bool): Flag to indicate whether HTTP debugging is enabled.
        ssl_verify (bool): Flag to indicate whether SSL verification is enabled.

    Examples:
        Basic web request:
        >>> response = await self.helpers.request("https://www.evilcorp.com")

        Download file:
        >>> filename = await self.helpers.download("https://www.evilcorp.com/passwords.docx")

        Download wordlist (cached for 30 days by default):
        >>> filename = await self.helpers.wordlist("https://www.evilcorp.com/wordlist.txt")
    """

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.preset = self.parent_helper.preset
        self.config = self.preset.config
        self.web_config = self.config.get("web", {})
        self.web_spider_depth = self.web_config.get("spider_depth", 1)
        self.web_spider_distance = self.web_config.get("spider_distance", 0)
        self.target = self.preset.target
        self.http_debug = self.web_config.get("debug", False)
        self.ssl_verify = self.web_config.get("ssl_verify", False)
        # Pre-compute config values for request preprocessing
        self._http_timeout = self.web_config.get("http_timeout", 20)
        self._http_retries = self.web_config.get("http_retries", 1)
        self._http_proxy = self.web_config.get("http_proxy", None)
        ua = self.web_config.get("user_agent", "BBOT")
        ua_suffix = self.web_config.get("user_agent_suffix") or ""
        self._user_agent = f"{ua} {ua_suffix}".strip()
        self._custom_headers = self.web_config.get("http_headers", {})
        self._custom_cookies = self.web_config.get("http_cookies", {})

    @property
    def client(self):
        """The shared rate-limited blasthttp client for target-directed traffic."""
        return self.parent_helper.blasthttp

    def _build_blasthttp_kwargs(self, url, **kwargs):
        """
        Translate request kwargs into blasthttp.request() kwargs.

        Handles: method, headers, body/data/json, timeout, follow_redirects,
        max_redirects, proxy, retries, params, cookies, auth.

        Returns (url, method, blast_kwargs) — url may be modified if params were appended.
        """
        method = kwargs.pop("method", "GET")
        headers = kwargs.pop("headers", None) or {}
        body = kwargs.pop("body", None)
        data = kwargs.pop("data", None)
        json_body = kwargs.pop("json", None)
        timeout = kwargs.pop("timeout", self._http_timeout)
        follow_redirects = kwargs.pop("follow_redirects", None)
        max_redirects = kwargs.pop("max_redirects", None)
        proxy = kwargs.pop("proxy", self._http_proxy)
        retries = kwargs.pop("retries", self._http_retries)
        params = kwargs.pop("params", None)
        cookies = kwargs.pop("cookies", None)
        auth = kwargs.pop("auth", None)
        max_body_size = kwargs.pop("max_body_size", None)
        request_target = kwargs.pop("request_target", None)
        resolve_ip = kwargs.pop("resolve_ip", None)
        ignore_bbot_global_settings = kwargs.pop("ignore_bbot_global_settings", False)

        # -- URL params --
        if params:
            parsed = urlparse(url)
            existing = parse_qs(parsed.query, keep_blank_values=True)
            if isinstance(params, dict):
                existing.update(params)
            new_query = urlencode(existing, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))

        # -- Headers as list of tuples --
        header_list = []

        if not ignore_bbot_global_settings:
            # User-Agent (can be overridden by caller)
            if "User-Agent" not in headers:
                header_list.append(("User-Agent", self._user_agent))

            # Scan-level custom headers (only for in-scope URLs)
            if self.target.in_target(url):
                for hk, hv in self._custom_headers.items():
                    if hk not in headers:
                        header_list.append((hk, str(hv)))

                # Scan-level custom cookies (merge with caller cookies)
                if self._custom_cookies:
                    if cookies is None:
                        cookies = {}
                    for ck, cv in self._custom_cookies.items():
                        if ck not in cookies:
                            cookies[ck] = cv

        # Caller-supplied headers
        for hk, hv in headers.items():
            if isinstance(hv, list):
                for v in hv:
                    header_list.append((hk, str(v)))
            else:
                header_list.append((hk, str(hv)))

        # -- JSON body --
        if json_body is not None:
            body = json.dumps(json_body)
            # Only set Content-Type if not already provided
            if not any(k.lower() == "content-type" for k, _ in header_list):
                header_list.append(("Content-Type", "application/json"))

        # -- Form data --
        if data is not None and body is None:
            if isinstance(data, dict):
                body = urlencode(data)
                if not any(k.lower() == "content-type" for k, _ in header_list):
                    header_list.append(("Content-Type", "application/x-www-form-urlencoded"))
            elif isinstance(data, (str, bytes)):
                body = str(data) if isinstance(data, bytes) else data

        # -- Cookies --
        if cookies:
            cookie_str = "; ".join(f"{ck}={cv}" for ck, cv in cookies.items())
            header_list.append(("Cookie", cookie_str))

        # -- Basic auth --
        if auth:
            import base64

            user, passwd = auth
            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            header_list.append(("Authorization", f"Basic {cred}"))

        blast_kwargs = {
            "method": method,
            "headers": header_list,
            "timeout": int(timeout) if timeout else self._http_timeout,
            "verify_certs": bool(self.ssl_verify),
            "retries": int(retries),
        }

        if body is not None:
            blast_kwargs["body"] = str(body)
        if follow_redirects is not None:
            blast_kwargs["follow_redirects"] = follow_redirects
        if max_redirects is not None:
            blast_kwargs["max_redirects"] = int(max_redirects)
        if proxy:
            blast_kwargs["proxy"] = proxy
        if max_body_size is not None:
            blast_kwargs["max_body_size"] = int(max_body_size)
        if request_target is not None:
            blast_kwargs["request_target"] = request_target
        if resolve_ip is not None:
            blast_kwargs["resolve_ip"] = resolve_ip

        return url, method, blast_kwargs

    async def request(self, *args, **kwargs):
        """
        Asynchronous function for making HTTP requests, intended to be the most basic web request function
        used widely across BBOT and within this helper class. Handles various exceptions and timeouts
        that might occur during the request.

        This function automatically respects the scan's global timeout, proxy, headers, etc.
        Headers you specify will be merged with the scan's. Your arguments take ultimate precedence,
        meaning you can override the scan's values if you want.

        Args:
            url (str): The URL to send the request to.
            method (str, optional): The HTTP method to use for the request. Defaults to 'GET'.
            headers (dict, optional): Dictionary of HTTP headers to send with the request.
            params (dict, optional): Dictionary, list of tuples, or bytes to send in the query string.
            cookies (dict, optional): Dictionary or CookieJar object containing cookies.
            json (Any, optional): A JSON serializable Python object to send in the body.
            data (dict, optional): Dictionary, list of tuples, or bytes to send in the body.
            body (str, optional): Raw string body to send (not URL-encoded).
            auth (tuple, optional): Auth tuple to enable Basic/Digest/Custom HTTP auth.
            timeout (float, optional): The maximum time to wait for the request to complete.
            proxy (str, optional): HTTP proxy URL.
            allow_redirects (bool, optional): Enables or disables redirection. Defaults to None.
            raise_error (bool, optional): Whether to raise exceptions for HTTP connect, timeout errors. Defaults to False.
            request_target (str, optional): Override the HTTP request-line target.
            resolve_ip (str, optional): Connect TCP to this IP instead of DNS resolution.
            ignore_bbot_global_settings (bool, optional): Skip User-Agent/header/cookie merging.

        Raises:
            WebError: If raise_error is True and the request fails.

        Returns:
            Response or None: The HTTP response object.

        Examples:
            >>> response = await self.helpers.request("https://www.evilcorp.com")

            >>> response = await self.helpers.request("https://api.evilcorp.com/", method="POST", data="stuff")

        Note:
            If the web request fails, it will return None unless `raise_error` is `True`.
        """
        raise_error = kwargs.pop("raise_error", False)
        kwargs.pop("cache_for", None)
        kwargs.pop("client", None)
        kwargs.pop("stream", None)
        if kwargs.pop("files", None) is not None:
            log.warning("blasthttp does not support multipart file uploads (files= kwarg)")

        # allow vs follow
        allow_redirects = kwargs.pop("allow_redirects", None)
        if allow_redirects is not None and "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = allow_redirects

        # In case of URL only as positional arg
        if len(args) == 1:
            kwargs["url"] = args[0]
            args = ()

        url = kwargs.pop("url", "")

        if not url:
            if raise_error:
                error = WebError("No URL provided")
                raise error
            return None

        if "method" not in kwargs:
            kwargs["method"] = "GET"

        # Translate kwargs to blasthttp format
        url, method, blast_kwargs = self._build_blasthttp_kwargs(url, **kwargs)

        try:
            if self.http_debug:
                log.trace(f"blasthttp request: {method} {url}")

            # Run in executor — blasthttp blocks the thread (tokio runtime)
            blast_response = await self.parent_helper.run_in_executor_io(self.client.request, url, **blast_kwargs)

            response = BlasthttpResponse(blast_response, request_url=url, method=method)

            if self.http_debug:
                log.trace(
                    f"blasthttp response from {url}: {response.status_code} "
                    f"(Length: {len(response.content)}) headers: {response.headers}"
                )
            return response

        except RuntimeError as e:
            error_msg = str(e)
            if raise_error:
                error = WebError(error_msg)
                raise error
            # Classify error for appropriate log level
            lower = error_msg.lower()
            if "timeout" in lower:
                log.verbose(f"HTTP timeout to URL: {url}")
            elif "connect" in lower or "connection" in lower:
                log.debug(f"HTTP connect failed to URL: {url}")
            else:
                log.trace(f"blasthttp error for {url}: {error_msg}")
        except BaseException as e:
            if not any(isinstance(_e, asyncio.exceptions.CancelledError) for _e in get_exception_chain(e)):
                log.trace(f"Unhandled exception with request to URL: {url}: {e}")
                log.trace(traceback.format_exc())
            raise

    async def request_batch(self, urls, threads=10, **kwargs):
        """
        Given a list of URLs, request them in parallel and yield responses as they come in.

        Args:
            urls (list[str]): List of URLs to visit
            threads (int): Max concurrent requests. Defaults to 10.
            **kwargs: Keyword arguments to pass through to request()

        Examples:
            >>> async for url, response in self.helpers.request_batch(urls, headers={"X-Test": "Test"}):
            >>>     if response is not None and response.status_code == 200:
            >>>         self.hugesuccess(response)
        """
        tasks = {}
        urls = list(urls)
        semaphore = asyncio.Semaphore(threads)

        async def _request(url):
            async with semaphore:
                return url, await self.request(url, **kwargs)

        for url in urls:
            task = asyncio.create_task(_request(url))
            tasks[task] = True

        while tasks:
            finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                del tasks[task]
                url, response = task.result()
                yield url, response

    async def request_custom_batch(self, urls_and_kwargs, threads=10):
        """
        Make web requests in parallel with custom options for each request. Yield responses as they come in.

        Similar to ``request_batch`` except it allows individual arguments for each URL.

        Args:
            urls_and_kwargs (list[tuple]): List of tuples in the format: (url, kwargs, custom_tracker)
                where custom_tracker is an optional value for your own internal use.
            threads (int): Max concurrent requests. Defaults to 10.

        Examples:
            >>> urls_and_kwargs = [
            >>>     ("http://evilcorp.com/1", {"method": "GET"}, "request-1"),
            >>>     ("http://evilcorp.com/2", {"method": "POST"}, "request-2"),
            >>> ]
            >>> async for url, kwargs, custom_tracker, response in self.helpers.request_custom_batch(
            >>>     urls_and_kwargs
            >>> ):
            >>>     if response is not None and response.status_code == 200:
            >>>         self.hugesuccess(response)
        """
        tasks = {}
        semaphore = asyncio.Semaphore(threads)

        for entry in urls_and_kwargs:
            url = entry[0]
            entry_kwargs = entry[1] if len(entry) > 1 and isinstance(entry[1], dict) else {}
            tracker = entry[2] if len(entry) > 2 else None

            async def _request(_url=url, _kwargs=entry_kwargs, _tracker=tracker):
                async with semaphore:
                    return _url, _kwargs, _tracker, await self.request(_url, **_kwargs)

            task = asyncio.create_task(_request())
            tasks[task] = True

        while tasks:
            finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                del tasks[task]
                url, kw, tracker, response = task.result()
                yield url, kw, tracker, response

    async def download(self, url, **kwargs):
        """
        Asynchronous function for downloading files from a given URL. Supports caching with an optional
        time period in hours via the "cache_hrs" keyword argument. In case of successful download,
        returns the full path of the saved filename. If the download fails, returns None.

        Args:
            url (str): The URL of the file to download.
            filename (str, optional): The filename to save the downloaded file as.
                If not provided, will generate based on URL.
            max_size (str or int): Maximum filesize as a string ("5MB") or integer in bytes.
            cache_hrs (float, optional): The number of hours to cache the downloaded file.
                A negative value disables caching. Defaults to -1.
            method (str, optional): The HTTP method to use for the request, defaults to 'GET'.
            raise_error (bool, optional): Whether to raise exceptions for HTTP connect, timeout errors. Defaults to False.
            **kwargs: Additional keyword arguments to pass to request().

        Returns:
            Path or None: The full path of the downloaded file as a Path object if successful, otherwise None.

        Examples:
            >>> filepath = await self.helpers.download("https://www.evilcorp.com/passwords.docx", cache_hrs=24)
        """
        success = False
        warn = kwargs.pop("warn", True)
        raise_error = kwargs.get("raise_error", False)
        filename = kwargs.pop("filename", self.parent_helper.cache_filename(url))
        filename = truncate_filename(Path(filename).resolve())
        max_size = kwargs.pop("max_size", None)
        if max_size is not None:
            max_size = self.parent_helper.human_to_bytes(max_size)
        cache_hrs = float(kwargs.pop("cache_hrs", -1))

        if cache_hrs > 0 and self.parent_helper.is_cached(url):
            log.debug(f"{url} is cached at {self.parent_helper.cache_filename(url)}")
            success = True
        else:
            try:
                kwargs["follow_redirects"] = kwargs.pop("follow_redirects", True)
                if "method" not in kwargs:
                    kwargs["method"] = "GET"
                kwargs["raise_error"] = True
                # Use a longer timeout for downloads (default 5 minutes)
                if "timeout" not in kwargs:
                    kwargs["timeout"] = 300
                # Raise the body size limit for downloads
                if "max_body_size" not in kwargs:
                    if max_size is not None:
                        kwargs["max_body_size"] = max_size
                    else:
                        kwargs["max_body_size"] = 500 * 1024 * 1024  # 500MB default

                response = await self.request(url, **kwargs)

                if response is None:
                    raise BlasthttpHTTPError(f"No response from {url}")

                log.debug(f"Download result: HTTP {response.status_code}")
                response.raise_for_status()

                content = response.content
                # Truncate if max_size specified
                if max_size is not None:
                    if len(content) > max_size:
                        log.verbose(
                            f"Size of response from {url} exceeds {bytes_to_human(max_size)}, file will be truncated"
                        )
                        content = content[:max_size]

                with open(filename, "wb") as f:
                    f.write(content)
                success = True

            except (BlasthttpHTTPError, WebError, RuntimeError) as e:
                log_fn = log.verbose
                if warn:
                    log_fn = log.warning
                log_fn(f"Failed to download {url}: {e}")
                if raise_error:
                    _response = getattr(e, "response", None)
                    error = WebError(str(e))
                    error.response = _response
                    raise error

        if success:
            return filename

    async def wordlist(self, path, lines=None, zip=False, zip_filename=None, **kwargs):
        """
        Asynchronous function for retrieving wordlists, either from a local path or a URL.
        Allows for optional line-based truncation and caching. Returns the full path of the wordlist
        file or a truncated version of it.

        Args:
            path (str): The local or remote path of the wordlist.
            lines (int, optional): Number of lines to read from the wordlist.
                If specified, will return a truncated wordlist with this many lines.
            zip (bool, optional): Whether to unzip the file after downloading. Defaults to False.
            zip_filename (str, optional): The name of the file to extract from the ZIP archive.
                Required if zip is True.
            cache_hrs (float, optional): Number of hours to cache the downloaded wordlist.
                Defaults to 720 hours (30 days) for remote wordlists.
            **kwargs: Additional keyword arguments to pass to the 'download' function for remote wordlists.

        Returns:
            Path: The full path of the wordlist (or its truncated version) as a Path object.

        Raises:
            WordlistError: If the path is invalid or the wordlist could not be retrieved or found.

        Examples:
            Fetching full wordlist
            >>> wordlist_path = await self.helpers.wordlist("https://www.evilcorp.com/wordlist.txt")

            Fetching and truncating to the first 100 lines
            >>> wordlist_path = await self.helpers.wordlist("/root/rockyou.txt", lines=100)
        """
        import zipfile

        if not path:
            raise WordlistError(f"Invalid wordlist: {path}")
        if "cache_hrs" not in kwargs:
            # 4320 hrs = 180 days = 6 months
            kwargs["cache_hrs"] = 4320
        if self.parent_helper.is_url(path):
            filename = await self.download(str(path), **kwargs)
            if filename is None:
                raise WordlistError(f"Unable to retrieve wordlist from {path}")
        else:
            filename = Path(path).resolve()
            if not filename.is_file():
                raise WordlistError(f"Unable to find wordlist at {path}")

        if zip:
            if not zip_filename:
                raise WordlistError("zip_filename must be specified when zip is True")
            try:
                with zipfile.ZipFile(filename, "r") as zip_ref:
                    if zip_filename not in zip_ref.namelist():
                        raise WordlistError(f"File {zip_filename} not found in the zip archive {filename}")
                    zip_ref.extract(zip_filename, filename.parent)
                    filename = filename.parent / zip_filename
            except Exception as e:
                raise WordlistError(f"Error unzipping file {filename}: {e}")

        if lines is None:
            return filename
        else:
            lines = int(lines)
            with open(filename) as f:
                read_lines = f.readlines()
            cache_key = f"{filename}:{lines}"
            truncated_filename = self.parent_helper.cache_filename(cache_key)
            with open(truncated_filename, "w") as f:
                for line in read_lines[:lines]:
                    f.write(line)
            return truncated_filename

    def beautifulsoup(
        self,
        markup,
        features="html.parser",
        builder=None,
        parse_only=None,
        from_encoding=None,
        exclude_encodings=None,
        element_classes=None,
        **kwargs,
    ):
        """
        Naviate, Search, Modify, Parse, or PrettyPrint HTML Content.
        More information at https://beautiful-soup-4.readthedocs.io/en/latest/

        Args:
            markup: A string or a file-like object representing markup to be parsed.
            features: Desirable features of the parser to be used.
                This may be the name of a specific parser ("lxml",
                "lxml-xml", "html.parser", or "html5lib") or it may be
                the type of markup to be used ("html", "html5", "xml").
                Defaults to 'html.parser'.
            builder: A TreeBuilder subclass to instantiate (or instance to use)
                instead of looking one up based on `features`.
            parse_only: A SoupStrainer. Only parts of the document
                matching the SoupStrainer will be considered.
            from_encoding: A string indicating the encoding of the
                document to be parsed.
            exclude_encodings = A list of strings indicating
                encodings known to be wrong.
            element_classes = A dictionary mapping BeautifulSoup
                classes like Tag and NavigableString, to other classes you'd
                like to be instantiated instead as the parse tree is
                built.
            **kwargs = For backwards compatibility purposes.

        Returns:
            soup: An instance of the BeautifulSoup class

        Todo:
            - Write tests for this function

        Examples:
            >>> soup = self.helpers.beautifulsoup(event.data["body"], "html.parser")
            Perform an html parse of the 'markup' argument and return a soup instance

            >>> email_type = soup.find(type="email")
            Searches the soup instance for all occurrences of the passed in argument
        """
        try:
            # If a response object is passed, extract the text
            if hasattr(markup, "text") and not isinstance(markup, (str, bytes)):
                markup = markup.text
            soup = BeautifulSoup(
                markup, features, builder, parse_only, from_encoding, exclude_encodings, element_classes, **kwargs
            )
            return soup
        except Exception as e:
            log.debug(f"Error parsing beautifulsoup: {e}")
            return False

    def response_to_json(self, response):
        """
        Convert web response to JSON object, to a JSON-serializable dict.
        """

        if response is None:
            return

        import mmh3
        from datetime import datetime
        from hashlib import md5, sha256
        from bbot.core.helpers.misc import tagify, urlparse, split_host_port, smart_decode

        request = response.request
        url = str(request.url)
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        scheme = parsed_url.scheme.lower()
        host, port = split_host_port(f"{scheme}://{netloc}")

        raw_headers = "\r\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        raw_headers_encoded = raw_headers.encode()

        headers = {}
        for k, v in response.headers.items():
            k = tagify(k, delimiter="_")
            headers[k] = v

        j = {
            "timestamp": datetime.now().isoformat(),
            "hash": {
                "body_md5": md5(response.content).hexdigest(),
                "body_mmh3": mmh3.hash(response.content),
                "body_sha256": sha256(response.content).hexdigest(),
                # "body_simhash": "TODO",
                "header_md5": md5(raw_headers_encoded).hexdigest(),
                "header_mmh3": mmh3.hash(raw_headers_encoded),
                "header_sha256": sha256(raw_headers_encoded).hexdigest(),
                # "header_simhash": "TODO",
            },
            "header": headers,
            "body": smart_decode(response.content),
            "content_type": headers.get("content_type", "").split(";")[0].strip(),
            "url": url,
            "host": str(host),
            "port": port,
            "scheme": scheme,
            "method": response.request.method,
            "path": parsed_url.path,
            "raw_header": raw_headers,
            "status_code": response.status_code,
        }

        return j
