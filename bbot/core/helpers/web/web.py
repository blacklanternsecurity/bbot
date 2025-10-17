import logging
import warnings
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
            server_kwargs={"config": self.config, "target": self.parent_helper.preset.target},
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
            proxy (str, optional): HTTP proxy URL.
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
        raise_error = kwargs.get("raise_error", False)
        result = await self.run_and_return("request", *args, **kwargs)
        if isinstance(result, dict) and "_request_error" in result:
            if raise_error:
                error_msg = result["_request_error"]
                response = result["_response"]
                error = self.ERROR_CLASS(error_msg)
                error.response = response
                raise error
        return result

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
        raise_error = kwargs.get("raise_error", False)
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
            result = await self.run_and_return("download", url, **kwargs)
            if isinstance(result, dict) and "_download_error" in result:
                if raise_error:
                    error_msg = result["_download_error"]
                    response = result["_response"]
                    error = self.ERROR_CLASS(error_msg)
                    error.response = response
                    raise error
            elif result:
                success = True

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
            kwargs["cache_hrs"] = 720
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
        cookies = kwargs.get("cookies", {})

        ignore_bbot_global_settings = kwargs.get("ignore_bbot_global_settings", False)

        if ignore_bbot_global_settings:
            http_timeout = 20  # setting 20 as a worse-case setting
            log.debug("ignore_bbot_global_settings enabled. Global settings will not be applied")
        else:
            http_timeout = self.parent_helper.web_config.get("http_timeout", 20)
            user_agent = self.parent_helper.web_config.get("user_agent", "BBOT")

            if "User-Agent" not in headers:
                headers["User-Agent"] = user_agent

            # only add custom headers / cookies if the URL is in-scope
            if self.parent_helper.preset.in_scope(url):
                for hk, hv in self.web_config.get("http_headers", {}).items():
                    # Only add the header if it doesn't already exist in the headers dictionary
                    if hk not in headers:
                        headers[hk] = hv

                for ck, cv in self.web_config.get("http_cookies", {}).items():
                    # don't clobber cookies
                    if ck not in cookies:
                        cookies[ck] = cv

        # add the timeout
        if "timeout" not in kwargs:
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
            curl_command.append(f"{cookies_str.rstrip(' ')}")

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
        log.verbose(f"Running curl command: {curl_command}")
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
            Searches the soup instance for all occurrences of the passed in argument
        """
        try:
            soup = BeautifulSoup(
                markup, features, builder, parse_only, from_encoding, exclude_encodings, element_classes, **kwargs
            )
            return soup
        except Exception as e:
            log.debug(f"Error parsing beautifulsoup: {e}")
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
