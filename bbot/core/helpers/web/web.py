import re
import logging
import warnings
import traceback
from pathlib import Path
from bs4 import BeautifulSoup

from bbot.core.engine import EngineClient
from bbot.core.helpers.misc import truncate_filename
from bbot.errors import WordlistError, CurlError, WebError

from bs4 import MarkupResemblesLocatorWarning
from bs4.builder import XMLParsedAsHTMLWarning

from .engine import HTTPEngine

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

log = logging.getLogger("bbot.core.helpers.web")


class WebHelper(EngineClient):

    SERVER_CLASS = HTTPEngine
    ERROR_CLASS = WebError

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

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.preset = self.parent_helper.preset
        self.config = self.preset.config
        self.web_config = self.config.get("web", {})
        self.web_spider_depth = self.web_config.get("spider_depth", 1)
        self.web_spider_distance = self.web_config.get("spider_distance", 0)
        self.web_clients = {}
        self.target = self.preset.target
        self.ssl_verify = self.config.get("ssl_verify", False)
        engine_debug = self.config.get("engine", {}).get("debug", False)
        super().__init__(
            server_kwargs={"config": self.config, "target": self.parent_helper.preset.target.radix_only},
            debug=engine_debug,
        )

    def AsyncClient(self, *args, **kwargs):
        # cache by retries to prevent unwanted accumulation of clients
        # (they are not garbage-collected)
        retries = kwargs.get("retries", 1)
        try:
            return self.web_clients[retries]
        except KeyError:
            from .client import BBOTAsyncClient

            client = BBOTAsyncClient.from_config(self.config, self.target, *args, persist_cookies=False, **kwargs)
            self.web_clients[client.retries] = client
            return client

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
        return await self.run_and_return("request", *args, **kwargs)

    async def request_batch(self, urls, *args, **kwargs):
        """
        Given a list of URLs, request them in parallel and yield responses as they come in.

        Args:
            urls (list[str]): List of URLs to visit
            *args: Positional arguments to pass through to httpx
            **kwargs: Keyword arguments to pass through to httpx

        Examples:
            >>> async for url, response in self.helpers.request_batch(urls, headers={"X-Test": "Test"}):
            >>>     if response is not None and response.status_code == 200:
            >>>         self.hugesuccess(response)
        """
        agen = self.run_and_yield("request_batch", urls, *args, **kwargs)
        while 1:
            try:
                yield await agen.__anext__()
            except (StopAsyncIteration, GeneratorExit):
                await agen.aclose()
                break

    async def request_custom_batch(self, urls_and_kwargs):
        """
        Make web requests in parallel with custom options for each request. Yield responses as they come in.

        Similar to `request_batch` except it allows individual arguments for each URL.

        Args:
            urls_and_kwargs (list[tuple]): List of tuples in the format: (url, kwargs, custom_tracker)
                where custom_tracker is an optional value for your own internal use. You may use it to
                help correlate requests, etc.

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
        agen = self.run_and_yield("request_custom_batch", urls_and_kwargs)
        while 1:
            try:
                yield await agen.__anext__()
            except (StopAsyncIteration, GeneratorExit):
                await agen.aclose()
                break

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
        filename = truncate_filename(Path(filename).resolve())
        kwargs["filename"] = filename
        max_size = kwargs.pop("max_size", None)
        if max_size is not None:
            max_size = self.parent_helper.human_to_bytes(max_size)
            kwargs["max_size"] = max_size
        cache_hrs = float(kwargs.pop("cache_hrs", -1))
        if cache_hrs > 0 and self.parent_helper.is_cached(url):
            log.debug(f"{url} is cached at {self.parent_helper.cache_filename(url)}")
            success = True
        else:
            success = await self.run_and_return("download", url, **kwargs)

        if success:
            return filename

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
            if result is None:
                log.verbose(f"api_page_iter() got no response for {url}")
                break
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
            http_timeout = self.parent_helper.web_config.get("http_timeout", 20)
            user_agent = self.parent_helper.web_config.get("user_agent", "BBOT")

            if "User-Agent" not in headers:
                headers["User-Agent"] = user_agent

            # only add custom headers if the URL is in-scope
            if self.parent_helper.preset.in_scope(url):
                for hk, hv in self.web_config.get("http_headers", {}).items():
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

    user_keywords = [re.compile(r, re.I) for r in ["user", "login", "email"]]
    pass_keywords = [re.compile(r, re.I) for r in ["pass"]]

    def is_login_page(self, html):
        """
        TODO: convert this into an excavate YARA rule

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
            user_fields = sum(bool(form.find_all("input", {"name": r})) for r in self.user_keywords)
            pass_fields = sum(bool(form.find_all("input", {"name": r})) for r in self.pass_keywords)
            if user_fields and pass_fields:
                return True
        return False

    def response_to_json(self, response):
        """
        Convert web response to JSON object, similar to the output of `httpx -irr -json`
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
