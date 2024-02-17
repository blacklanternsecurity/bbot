import re
import ssl
import anyio
import httpx
import asyncio
import logging
import warnings
import traceback
from pathlib import Path
from bs4 import BeautifulSoup
from contextlib import asynccontextmanager

from httpx._models import Cookies
from socksio.exceptions import SOCKSError

from bbot.core.errors import WordlistError, CurlError
from bbot.core.helpers.ratelimiter import RateLimiter

from bs4 import MarkupResemblesLocatorWarning
from bs4.builder import XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

log = logging.getLogger("bbot.core.helpers.web")


class DummyCookies(Cookies):
    def extract_cookies(self, *args, **kwargs):
        pass


class BBOTAsyncClient(httpx.AsyncClient):
    """
    A subclass of httpx.AsyncClient tailored with BBOT-specific configurations and functionalities.
    This class provides rate limiting, logging, configurable timeouts, user-agent customization, custom
    headers, and proxy settings. Additionally, it allows the disabling of cookies, making it suitable
    for use across an entire scan.

    Attributes:
        _bbot_scan (object): BBOT scan object containing configuration details.
        _rate_limiter (RateLimiter): A rate limiter object to limit web requests.
        _persist_cookies (bool): Flag to determine whether cookies should be persisted across requests.

    Examples:
        >>> async with BBOTAsyncClient(_bbot_scan=bbot_scan_object) as client:
        >>>     response = await client.request("GET", "https://example.com")
        >>>     print(response.status_code)
        200
    """

    def __init__(self, *args, **kwargs):
        self._bbot_scan = kwargs.pop("_bbot_scan")
        web_requests_per_second = self._bbot_scan.config.get("web_requests_per_second", 100)
        self._rate_limiter = RateLimiter(web_requests_per_second, "Web")

        http_debug = self._bbot_scan.config.get("http_debug", None)
        if http_debug:
            log.trace(f"Creating AsyncClient: {args}, {kwargs}")

        self._persist_cookies = kwargs.pop("persist_cookies", True)

        # timeout
        http_timeout = self._bbot_scan.config.get("http_timeout", 20)
        if not "timeout" in kwargs:
            kwargs["timeout"] = http_timeout

        # headers
        headers = kwargs.get("headers", None)
        if headers is None:
            headers = {}
        # user agent
        user_agent = self._bbot_scan.config.get("user_agent", "BBOT")
        if "User-Agent" not in headers:
            headers["User-Agent"] = user_agent
        kwargs["headers"] = headers
        # proxy
        proxies = self._bbot_scan.config.get("http_proxy", None)
        kwargs["proxies"] = proxies

        super().__init__(*args, **kwargs)
        if not self._persist_cookies:
            self._cookies = DummyCookies()

    async def request(self, *args, **kwargs):
        async with self._rate_limiter:
            return await super().request(*args, **kwargs)

    def build_request(self, *args, **kwargs):
        request = super().build_request(*args, **kwargs)
        # add custom headers if the URL is in-scope
        if self._bbot_scan.in_scope(str(request.url)):
            for hk, hv in self._bbot_scan.config.get("http_headers", {}).items():
                # don't clobber headers
                if hk not in request.headers:
                    request.headers[hk] = hv
        return request

    def _merge_cookies(self, cookies):
        if self._persist_cookies:
            return super()._merge_cookies(cookies)
        return cookies


class WebHelper:
    """
    Main utility class for managing HTTP operations in BBOT. It serves as a wrapper around the BBOTAsyncClient,
    which itself is a subclass of httpx.AsyncClient. The class provides functionalities to make HTTP requests,
    download files, and handle cached wordlists.

    Attributes:
        parent_helper (object): The parent helper object containing scan configurations.
        http_debug (bool): Flag to indicate whether HTTP debugging is enabled.
        ssl_verify (bool): Flag to indicate whether SSL verification is enabled.
        web_client (BBOTAsyncClient): An instance of BBOTAsyncClient for making HTTP requests.
        client_only_options (tuple): A tuple of options only applicable to the web client.

    Examples:
        Basic web request:
        >>> response = await self.helpers.request("https://www.evilcorp.com")

        Download file:
        >>> filename = await self.helpers.download("https://www.evilcorp.com/passwords.docx")

        Download wordlist (cached for 30 days by default):
        >>> filename = await self.helpers.wordlist("https://www.evilcorp.com/wordlist.txt")
    """

    client_only_options = (
        "retries",
        "max_redirects",
    )

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.http_debug = self.parent_helper.config.get("http_debug", False)
        self._ssl_context_noverify = None
        self.ssl_verify = self.parent_helper.config.get("ssl_verify", False)
        if self.ssl_verify is False:
            self.ssl_verify = self.ssl_context_noverify()
        self.web_client = self.AsyncClient(persist_cookies=False)

    def AsyncClient(self, *args, **kwargs):
        kwargs["_bbot_scan"] = self.parent_helper.scan
        retries = kwargs.pop("retries", self.parent_helper.config.get("http_retries", 1))
        kwargs["transport"] = httpx.AsyncHTTPTransport(retries=retries, verify=self.ssl_verify)
        kwargs["verify"] = self.ssl_verify
        return BBOTAsyncClient(*args, **kwargs)

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
            files (dict, optional): Dictionary of 'name': file-like-objects for multipart encoding upload.
            auth (tuple, optional): Auth tuple to enable Basic/Digest/Custom HTTP auth.
            timeout (float, optional): The maximum time to wait for the request to complete.
            proxies (dict, optional): Dictionary mapping protocol schemes to proxy URLs.
            allow_redirects (bool, optional): Enables or disables redirection. Defaults to None.
            stream (bool, optional): Enables or disables response streaming.
            raise_error (bool, optional): Whether to raise exceptions for HTTP connect, timeout errors. Defaults to False.
            client (httpx.AsyncClient, optional): A specific httpx.AsyncClient to use for the request. Defaults to self.web_client.
            cache_for (int, optional): Time in seconds to cache the request. Not used currently. Defaults to None.

        Raises:
            httpx.TimeoutException: If the request times out.
            httpx.ConnectError: If the connection fails.
            httpx.RequestError: For other request-related errors.

        Returns:
            httpx.Response or None: The HTTP response object returned by the httpx library.

        Examples:
            >>> response = await self.helpers.request("https://www.evilcorp.com")

            >>> response = await self.helpers.request("https://api.evilcorp.com/", method="POST", data="stuff")

        Note:
            If the web request fails, it will return None unless `raise_error` is `True`.
        """

        raise_error = kwargs.pop("raise_error", False)
        # TODO: use this
        cache_for = kwargs.pop("cache_for", None)  # noqa

        client = kwargs.get("client", self.web_client)

        # allow vs follow, httpx why??
        allow_redirects = kwargs.pop("allow_redirects", None)
        if allow_redirects is not None and "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = allow_redirects

        # in case of URL only, assume GET request
        if len(args) == 1:
            kwargs["url"] = args[0]
            args = []

        url = kwargs.get("url", "")

        if not args and "method" not in kwargs:
            kwargs["method"] = "GET"

        client_kwargs = {}
        for k in list(kwargs):
            if k in self.client_only_options:
                v = kwargs.pop(k)
                client_kwargs[k] = v

        if client_kwargs:
            client = self.AsyncClient(**client_kwargs)

        async with self._acatch(url, raise_error):
            if self.http_debug:
                logstr = f"Web request: {str(args)}, {str(kwargs)}"
                log.trace(logstr)
            response = await client.request(*args, **kwargs)
            if self.http_debug:
                log.trace(
                    f"Web response from {url}: {response} (Length: {len(response.content)}) headers: {response.headers}"
                )
            return response

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
            **kwargs: Additional keyword arguments to pass to the httpx request.

        Returns:
            Path or None: The full path of the downloaded file as a Path object if successful, otherwise None.

        Examples:
            >>> filepath = await self.helpers.download("https://www.evilcorp.com/passwords.docx", cache_hrs=24)
        """
        success = False
        filename = kwargs.pop("filename", self.parent_helper.cache_filename(url))
        follow_redirects = kwargs.pop("follow_redirects", True)
        max_size = kwargs.pop("max_size", None)
        warn = kwargs.pop("warn", True)
        raise_error = kwargs.pop("raise_error", False)
        if max_size is not None:
            max_size = self.parent_helper.human_to_bytes(max_size)
        cache_hrs = float(kwargs.pop("cache_hrs", -1))
        total_size = 0
        chunk_size = 8192
        log.debug(f"Downloading file from {url} with cache_hrs={cache_hrs}")
        if cache_hrs > 0 and self.parent_helper.is_cached(url):
            log.debug(f"{url} is cached at {self.parent_helper.cache_filename(url)}")
            success = True
        else:
            # kwargs["raise_error"] = True
            # kwargs["stream"] = True
            kwargs["follow_redirects"] = follow_redirects
            if not "method" in kwargs:
                kwargs["method"] = "GET"
            try:
                async with self._acatch(url, raise_error), self.AsyncClient().stream(url=url, **kwargs) as response:
                    status_code = getattr(response, "status_code", 0)
                    log.debug(f"Download result: HTTP {status_code}")
                    if status_code != 0:
                        response.raise_for_status()
                        with open(filename, "wb") as f:
                            agen = response.aiter_bytes(chunk_size=chunk_size)
                            async for chunk in agen:
                                if max_size is not None and total_size + chunk_size > max_size:
                                    log.verbose(
                                        f"Filesize of {url} exceeds {self.parent_helper.bytes_to_human(max_size)}, file will be truncated"
                                    )
                                    agen.aclose()
                                    break
                                total_size += chunk_size
                                f.write(chunk)
                        success = True
            except httpx.HTTPError as e:
                log_fn = log.verbose
                if warn:
                    log_fn = log.warning
                log_fn(f"Failed to download {url}: {e}")
                return

        if success:
            return filename.resolve()

    async def wordlist(self, path, lines=None, **kwargs):
        """
        Asynchronous function for retrieving wordlists, either from a local path or a URL.
        Allows for optional line-based truncation and caching. Returns the full path of the wordlist
        file or a truncated version of it.

        Args:
            path (str): The local or remote path of the wordlist.
            lines (int, optional): Number of lines to read from the wordlist.
                If specified, will return a truncated wordlist with this many lines.
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
        if not path:
            raise WordlistError(f"Invalid wordlist: {path}")
        if not "cache_hrs" in kwargs:
            kwargs["cache_hrs"] = 720
        if self.parent_helper.is_url(path):
            filename = await self.download(str(path), **kwargs)
            if filename is None:
                raise WordlistError(f"Unable to retrieve wordlist from {path}")
        else:
            filename = Path(path).resolve()
            if not filename.is_file():
                raise WordlistError(f"Unable to find wordlist at {path}")

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

    async def api_page_iter(self, url, page_size=100, json=True, next_key=None, **requests_kwargs):
        """
        An asynchronous generator function for iterating through paginated API data.

        This function continuously makes requests to a specified API URL, incrementing the page number
        or applying a custom pagination function, and yields the received data one page at a time.
        It is well-suited for APIs that provide paginated results.

        Args:
            url (str): The initial API URL. Can contain placeholders for 'page', 'page_size', and 'offset'.
            page_size (int, optional): The number of items per page. Defaults to 100.
            json (bool, optional): If True, attempts to deserialize the response content to a JSON object. Defaults to True.
            next_key (callable, optional): A function that takes the last page's data and returns the URL for the next page. Defaults to None.
            **requests_kwargs: Arbitrary keyword arguments that will be forwarded to the HTTP request function.

        Yields:
            dict or httpx.Response: If 'json' is True, yields a dictionary containing the parsed JSON data. Otherwise, yields the raw HTTP response.

        Note:
            The loop will continue indefinitely unless manually stopped. Make sure to break out of the loop once the last page has been received.

        Examples:
            >>> agen = api_page_iter('https://api.example.com/data?page={page}&page_size={page_size}')
            >>> try:
            >>>     async for page in agen:
            >>>         subdomains = page["subdomains"]
            >>>         self.hugesuccess(subdomains)
            >>>         if not subdomains:
            >>>             break
            >>> finally:
            >>>     agen.aclose()
        """
        page = 1
        offset = 0
        result = None
        while 1:
            if result and callable(next_key):
                try:
                    new_url = next_key(result)
                except Exception as e:
                    log.debug(f"Failed to extract next page of results from {url}: {e}")
                    log.debug(traceback.format_exc())
            else:
                new_url = url.format(page=page, page_size=page_size, offset=offset)
            result = await self.request(new_url, **requests_kwargs)
            try:
                if json:
                    result = result.json()
                yield result
            except Exception:
                log.warning(f'Error in api_page_iter() for url: "{new_url}"')
                log.trace(traceback.format_exc())
                break
            finally:
                offset += page_size
                page += 1

    async def curl(self, *args, **kwargs):
        """
        An asynchronous function that runs a cURL command with specified arguments and options.

        This function constructs and executes a cURL command based on the provided parameters.
        It offers support for various cURL options such as headers, post data, and cookies.

        Args:
            *args: Variable length argument list for positional arguments. Unused in this function.
            url (str): The URL for the cURL request. Mandatory.
            raw_path (bool, optional): If True, activates '--path-as-is' in cURL. Defaults to False.
            headers (dict, optional): A dictionary of HTTP headers to include in the request.
            ignore_bbot_global_settings (bool, optional): If True, ignores the global settings of BBOT. Defaults to False.
            post_data (dict, optional): A dictionary containing data to be sent in the request body.
            method (str, optional): The HTTP method to use for the request (e.g., 'GET', 'POST').
            cookies (dict, optional): A dictionary of cookies to include in the request.
            path_override (str, optional): Overrides the request-target to use in the HTTP request line.
            head_mode (bool, optional): If True, includes '-I' to fetch headers only. Defaults to None.
            raw_body (str, optional): Raw string to be sent in the body of the request.
            **kwargs: Arbitrary keyword arguments that will be forwarded to the HTTP request function.

        Returns:
            str: The output of the cURL command.

        Raises:
            CurlError: If 'url' is not supplied.

        Examples:
            >>> output = await curl(url="https://example.com", headers={"X-Header": "Wat"})
            >>> print(output)
        """
        url = kwargs.get("url", "")

        if not url:
            raise CurlError("No URL supplied to CURL helper")

        curl_command = ["curl", url, "-s"]

        raw_path = kwargs.get("raw_path", False)
        if raw_path:
            curl_command.append("--path-as-is")

        # respect global ssl verify settings
        if self.ssl_verify is not True:
            curl_command.append("-k")

        headers = kwargs.get("headers", {})

        ignore_bbot_global_settings = kwargs.get("ignore_bbot_global_settings", False)

        if ignore_bbot_global_settings:
            log.debug("ignore_bbot_global_settings enabled. Global settings will not be applied")
        else:
            http_timeout = self.parent_helper.config.get("http_timeout", 20)
            user_agent = self.parent_helper.config.get("user_agent", "BBOT")

            if "User-Agent" not in headers:
                headers["User-Agent"] = user_agent

            # only add custom headers if the URL is in-scope
            if self.parent_helper.scan.in_scope(url):
                for hk, hv in self.parent_helper.scan.config.get("http_headers", {}).items():
                    headers[hk] = hv

            # add the timeout
            if not "timeout" in kwargs:
                timeout = http_timeout

            curl_command.append("-m")
            curl_command.append(str(timeout))

        for k, v in headers.items():
            if isinstance(v, list):
                for x in v:
                    curl_command.append("-H")
                    curl_command.append(f"{k}: {x}")

            else:
                curl_command.append("-H")
                curl_command.append(f"{k}: {v}")

        post_data = kwargs.get("post_data", {})
        if len(post_data.items()) > 0:
            curl_command.append("-d")
            post_data_str = ""
            for k, v in post_data.items():
                post_data_str += f"&{k}={v}"
            curl_command.append(post_data_str.lstrip("&"))

        method = kwargs.get("method", "")
        if method:
            curl_command.append("-X")
            curl_command.append(method)

        cookies = kwargs.get("cookies", "")
        if cookies:
            curl_command.append("-b")
            cookies_str = ""
            for k, v in cookies.items():
                cookies_str += f"{k}={v}; "
            curl_command.append(f'{cookies_str.rstrip(" ")}')

        path_override = kwargs.get("path_override", None)
        if path_override:
            curl_command.append("--request-target")
            curl_command.append(f"{path_override}")

        head_mode = kwargs.get("head_mode", None)
        if head_mode:
            curl_command.append("-I")

        raw_body = kwargs.get("raw_body", None)
        if raw_body:
            curl_command.append("-d")
            curl_command.append(raw_body)

        output = (await self.parent_helper.run(curl_command)).stdout
        return output

    def is_spider_danger(self, source_event, url):
        """
        Determines whether visiting a URL could potentially trigger a web-spider-like happening.

        This function assesses the depth and distance of a URL in relation to the parent helper's
        configuration settings for web spidering. If the URL exceeds the specified depth or distance,
        the function returns True, indicating a possible web-spider risk.

        Args:
            source_event: The source event object that discovered the URL.
            url (str): The URL to evaluate for web-spider risk.

        Returns:
            bool: True if visiting the URL might trigger a web-spider-like event, False otherwise.

        Todo:
            - Write tests for this function

        Examples:
            >>> is_spider_danger(source_event_obj, "https://example.com/subpage")
            True

            >>> is_spider_danger(source_event_obj, "https://example.com/")
            False
        """
        url_depth = self.parent_helper.url_depth(url)
        web_spider_depth = self.parent_helper.scan.config.get("web_spider_depth", 1)
        spider_distance = getattr(source_event, "web_spider_distance", 0) + 1
        web_spider_distance = self.parent_helper.scan.config.get("web_spider_distance", 0)
        if (url_depth > web_spider_depth) or (spider_distance > web_spider_distance):
            return True
        return False

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
            Searches the soup instance for all occurances of the passed in argument
        """
        try:
            soup = BeautifulSoup(
                markup, features, builder, parse_only, from_encoding, exclude_encodings, element_classes, **kwargs
            )
            return soup
        except Exception as e:
            log.debug(f"Error parsing beautifulsoup: {e}")
            return False

    def ssl_context_noverify(self):
        if self._ssl_context_noverify is None:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.options &= ~ssl.OP_NO_SSLv2 & ~ssl.OP_NO_SSLv3
            ssl_context.set_ciphers("ALL:@SECLEVEL=0")
            ssl_context.options |= 0x4  # Add the OP_LEGACY_SERVER_CONNECT option
            self._ssl_context_noverify = ssl_context
        return self._ssl_context_noverify

    @asynccontextmanager
    async def _acatch(self, url, raise_error):
        """
        Asynchronous context manager to handle various httpx errors during a request.

        Yields:
            None

        Note:
            This function is internal and should generally not be used directly.
            `url`, `args`, `kwargs`, and `raise_error` should be in the same context as this function.
        """
        try:
            yield
        except httpx.TimeoutException:
            log.verbose(f"HTTP timeout to URL: {url}")
            if raise_error:
                raise
        except httpx.ConnectError:
            log.debug(f"HTTP connect failed to URL: {url}")
            if raise_error:
                raise
        except httpx.RequestError as e:
            log.trace(f"Error with request to URL: {url}: {e}")
            log.trace(traceback.format_exc())
            if raise_error:
                raise
        except ssl.SSLError as e:
            msg = f"SSL error with request to URL: {url}: {e}"
            log.trace(msg)
            log.trace(traceback.format_exc())
            if raise_error:
                raise httpx.RequestError(msg)
        except anyio.EndOfStream as e:
            msg = f"AnyIO error with request to URL: {url}: {e}"
            log.trace(msg)
            log.trace(traceback.format_exc())
            if raise_error:
                raise httpx.RequestError(msg)
        except SOCKSError as e:
            msg = f"SOCKS error with request to URL: {url}: {e}"
            log.trace(msg)
            log.trace(traceback.format_exc())
            if raise_error:
                raise httpx.RequestError(msg)
        except BaseException as e:
            # don't log if the error is the result of an intentional cancellation
            if not any(
                isinstance(_e, asyncio.exceptions.CancelledError) for _e in self.parent_helper.get_exception_chain(e)
            ):
                log.trace(f"Unhandled exception with request to URL: {url}: {e}")
                log.trace(traceback.format_exc())
            raise


user_keywords = [re.compile(r, re.I) for r in ["user", "login", "email"]]
pass_keywords = [re.compile(r, re.I) for r in ["pass"]]


def is_login_page(html):
    """
    Determines if the provided HTML content contains a login page.

    This function parses the HTML to search for forms with input fields typically used for
    authentication. If it identifies password fields or a combination of username and password
    fields, it returns True.

    Args:
        html (str): The HTML content to analyze.

    Returns:
        bool: True if the HTML contains a login page, otherwise False.

    Examples:
        >>> is_login_page('<form><input type="text" name="username"><input type="password" name="password"></form>')
        True

        >>> is_login_page('<form><input type="text" name="search"></form>')
        False
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        log.debug(f"Error parsing html: {e}")
        return False

    forms = soup.find_all("form")

    # first, check for obvious password fields
    for form in forms:
        if form.find_all("input", {"type": "password"}):
            return True

    # next, check for forms that have both a user-like and password-like field
    for form in forms:
        user_fields = sum(bool(form.find_all("input", {"name": r})) for r in user_keywords)
        pass_fields = sum(bool(form.find_all("input", {"name": r})) for r in pass_keywords)
        if user_fields and pass_fields:
            return True
    return False
