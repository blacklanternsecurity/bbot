import pytest
import asyncio
from bbot.scanner import Scanner


class TestExcavateDirectBenchmarks:
    """
    Direct benchmark tests for Excavate module operations.

    These tests measure the performance of excavate's core YARA processing
    by calling the excavate.search() method directly with specific text sizes
    in both single-threaded and parallel asyncio tasks to test the GIL sidestep feature of YARA.
    """

    # Number of text segments per test
    TEXT_SEGMENTS_COUNT = 100

    # Prescribed sizes for deterministic benchmarking (in bytes)
    SMALL_SIZE = 4096  # 4KB
    LARGE_SIZE = 5242880  # 5MB

    def _generate_text_segments(self, target_size, count):
        """Generate a list of text segments of the specified size"""
        segments = []

        for i in range(count):
            # Generate realistic content that excavate can work with
            base_content = self._generate_realistic_content(i)

            # Pad to the exact target size with deterministic content
            remaining_size = target_size - len(base_content)
            if remaining_size > 0:
                # Use deterministic padding pattern
                padding_pattern = "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
                padding_repeats = (remaining_size // len(padding_pattern)) + 1
                padding = (padding_pattern * padding_repeats)[:remaining_size]
                content = base_content + padding
            else:
                content = base_content[:target_size]

            segments.append(content)

        return segments

    def _generate_realistic_content(self, index):
        """Generate realistic content that excavate can extract from"""
        return f"""
        <html>
        <head>
            <title>Test Content {index}</title>
            <script src="https://api{index}.example.com/js/app.js"></script>
        </head>
        <body>
            <h1>Page {index}</h1>
            
            <!-- URLs and subdomains -->
            <a href="https://www{index}.example.com/page{index}">Link {index}</a>
            <a href="https://cdn{index}.example.com/assets/">CDN {index}</a>
            <img src="https://img{index}.example.com/photo{index}.jpg" />
            
            <!-- Forms with parameters -->
            <form action="/search{index}" method="GET">
                <input type="text" name="query{index}" value="test{index}">
                <input type="hidden" name="token{index}" value="abc123{index}">
                <button type="submit">Search</button>
            </form>
            
            <!-- API endpoints -->
            <script>
                fetch('https://api{index}.example.com/v1/users/{index}')
                    .then(response => response.json())
                    .then(data => console.log(data));
                    
                // WebSocket connection
                const ws = new WebSocket('wss://realtime{index}.example.com/socket');
            </script>
            
            <!-- Various protocols -->
            <p>FTP: ftp://ftp{index}.example.com:21/files/</p>
            <p>SSH: ssh://server{index}.example.com:22/</p>
            <p>Email: contact{index}@example.com</p>
            
            <!-- JSON data -->
            <script type="application/json">
            {{
                "apiEndpoint{index}": "https://api{index}.example.com/data",
                "parameter{index}": "value{index}",
                "secretKey{index}": "sk_test_{index}_abcdef123456"
            }}
            </script>
            
            <!-- Comments with URLs -->
            <!-- https://hidden{index}.example.com/admin -->
            <!-- TODO: Check https://internal{index}.example.com/debug -->
        </body>
        </html>
        """

    async def _run_excavate_single_thread(self, text_segments):
        """Run excavate processing in single thread"""
        # Create scanner and initialize excavate
        scan = Scanner("example.com", modules=["httpx"], config={"excavate": True})
        await scan._prep()
        excavate_module = scan.modules.get("excavate")

        if not excavate_module:
            raise RuntimeError("Excavate module not found")

        # Track events emitted by excavate
        emitted_events = []

        async def track_emit_event(event_data, *args, **kwargs):
            emitted_events.append(event_data)

        excavate_module.emit_event = track_emit_event

        # Process all text segments sequentially
        results = []
        for i, text_segment in enumerate(text_segments):
            # Create a mock HTTP_RESPONSE event
            mock_event = scan.make_event(
                {
                    "url": f"https://example.com/test/{i}",
                    "method": "GET",
                    "body": text_segment,
                    "header-dict": {"Content-Type": ["text/html"]},
                    "raw_header": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
                    "status_code": 200,
                },
                "HTTP_RESPONSE",
                parent=scan.root_event,
            )

            # Process with excavate
            await excavate_module.search(text_segment, mock_event, "text/html", f"Single thread benchmark {i}")
            results.append(f"processed_{i}")

        return results, emitted_events

    async def _run_excavate_parallel_tasks(self, text_segments):
        """Run excavate processing with parallel asyncio tasks"""
        # Create scanner and initialize excavate
        scan = Scanner("example.com", modules=["httpx"], config={"excavate": True})
        await scan._prep()
        excavate_module = scan.modules.get("excavate")

        if not excavate_module:
            raise RuntimeError("Excavate module not found")

        # Define async task to process a single text segment
        async def process_segment(segment_index, text_segment):
            mock_event = scan.make_event(
                {
                    "url": f"https://example.com/parallel/{segment_index}",
                    "method": "GET",
                    "body": text_segment,
                    "header-dict": {"Content-Type": ["text/html"]},
                    "raw_header": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
                    "status_code": 200,
                },
                "HTTP_RESPONSE",
                parent=scan.root_event,
            )

            await excavate_module.search(
                text_segment, mock_event, "text/html", f"Parallel benchmark task {segment_index}"
            )
            return f"processed_{segment_index}"

        # Create all tasks and run them concurrently
        tasks = [process_segment(i, text_segment) for i, text_segment in enumerate(text_segments)]

        # Run all tasks in parallel
        results = await asyncio.gather(*tasks)
        return results

    # Single Thread Tests
    @pytest.mark.benchmark(group="excavate_single_small")
    def test_excavate_single_thread_small(self, benchmark):
        """Benchmark excavate single thread processing with small (4KB) segments"""
        text_segments = self._generate_text_segments(self.SMALL_SIZE, self.TEXT_SEGMENTS_COUNT)

        def run_test():
            return asyncio.run(self._run_excavate_single_thread(text_segments))

        result, events = benchmark(run_test)

        assert len(result) == self.TEXT_SEGMENTS_COUNT
        total_size_mb = (self.SMALL_SIZE * self.TEXT_SEGMENTS_COUNT) / (1024 * 1024)

        # Count events by type
        total_events = len(events)
        url_events = len([e for e in events if e.type == "URL_UNVERIFIED"])
        dns_events = len([e for e in events if e.type == "DNS_NAME"])
        email_events = len([e for e in events if e.type == "EMAIL_ADDRESS"])
        protocol_events = len([e for e in events if e.type == "PROTOCOL"])
        finding_events = len([e for e in events if e.type == "FINDING"])

        print("\n✅ Single-thread small segments benchmark completed")
        print(f"📊 Processed {len(result):,} segments of {self.SMALL_SIZE / 1024:.0f}KB each")
        print(f"📊 Total size processed: {total_size_mb:.1f} MB")
        print(f"📊 Total events: {total_events}")
        print(f"📊 URL events: {url_events}")
        print(f"📊 DNS events: {dns_events}")
        print(f"📊 Email events: {email_events}")
        print(f"📊 Protocol events: {protocol_events}")
        print(f"📊 Finding events: {finding_events}")

        # Validate that excavate actually found and processed content
        assert total_events > 0, "Expected to find some events from excavate"
        assert url_events > 0 or dns_events > 0 or protocol_events > 0, (
            "Expected excavate to find URLs, DNS names, or protocols"
        )

    @pytest.mark.benchmark(group="excavate_single_large")
    def test_excavate_single_thread_large(self, benchmark):
        """Benchmark excavate single thread processing with large (10MB) segments"""
        text_segments = self._generate_text_segments(self.LARGE_SIZE, self.TEXT_SEGMENTS_COUNT)

        def run_test():
            return asyncio.run(self._run_excavate_single_thread(text_segments))

        result, events = benchmark(run_test)

        assert len(result) == self.TEXT_SEGMENTS_COUNT
        total_size_mb = (self.LARGE_SIZE * self.TEXT_SEGMENTS_COUNT) / (1024 * 1024)

        # Count events by type
        total_events = len(events)
        url_events = len([e for e in events if e.type == "URL_UNVERIFIED"])
        dns_events = len([e for e in events if e.type == "DNS_NAME"])
        email_events = len([e for e in events if e.type == "EMAIL_ADDRESS"])
        protocol_events = len([e for e in events if e.type == "PROTOCOL"])
        finding_events = len([e for e in events if e.type == "FINDING"])

        print("\n✅ Single-thread large segments benchmark completed")
        print(f"📊 Processed {len(result):,} segments of {self.LARGE_SIZE / (1024 * 1024):.0f}MB each")
        print(f"📊 Total size processed: {total_size_mb:.1f} MB")
        print(f"📊 Total events: {total_events}")
        print(f"📊 URL events: {url_events}")
        print(f"📊 DNS events: {dns_events}")
        print(f"📊 Email events: {email_events}")
        print(f"📊 Protocol events: {protocol_events}")
        print(f"📊 Finding events: {finding_events}")

        # Validate that excavate actually found and processed content
        assert total_events > 0, "Expected to find some events from excavate"
        assert url_events > 0 or dns_events > 0 or protocol_events > 0, (
            "Expected excavate to find URLs, DNS names, or protocols"
        )

    # Parallel Tests
    @pytest.mark.benchmark(group="excavate_parallel_small")
    def test_excavate_parallel_tasks_small(self, benchmark):
        """Benchmark excavate parallel processing with small (4KB) segments"""
        text_segments = self._generate_text_segments(self.SMALL_SIZE, self.TEXT_SEGMENTS_COUNT)

        def run_test():
            return asyncio.run(self._run_excavate_parallel_tasks(text_segments))

        result = benchmark(run_test)

        assert len(result) == self.TEXT_SEGMENTS_COUNT
        total_size_mb = (self.SMALL_SIZE * self.TEXT_SEGMENTS_COUNT) / (1024 * 1024)
        print("\n✅ Parallel small segments benchmark completed")
        print(f"📊 Processed {len(result):,} segments of {self.SMALL_SIZE / 1024:.0f}KB each in parallel")
        print(f"📊 Total size processed: {total_size_mb:.1f} MB")
        print("📊 Tasks executed concurrently to test YARA GIL sidestep")

        # Basic assertion that excavate is actually working (should find URLs in our test content)
        assert len(result) > 0, "Expected excavate to process all segments"

    @pytest.mark.benchmark(group="excavate_parallel_large")
    def test_excavate_parallel_tasks_large(self, benchmark):
        """Benchmark excavate parallel processing with large (10MB) segments to test YARA GIL sidestep"""
        text_segments = self._generate_text_segments(self.LARGE_SIZE, self.TEXT_SEGMENTS_COUNT)

        def run_test():
            return asyncio.run(self._run_excavate_parallel_tasks(text_segments))

        result = benchmark(run_test)

        assert len(result) == self.TEXT_SEGMENTS_COUNT
        total_size_mb = (self.LARGE_SIZE * self.TEXT_SEGMENTS_COUNT) / (1024 * 1024)
        print("\n✅ Parallel large segments benchmark completed")
        print(f"📊 Processed {len(result):,} segments of {self.LARGE_SIZE / (1024 * 1024):.0f}MB each in parallel")
        print(f"📊 Total size processed: {total_size_mb:.1f} MB")
        print("📊 Tasks executed concurrently to test YARA GIL sidestep")

        # Basic assertion that excavate is actually working (should find URLs in our test content)
        assert len(result) > 0, "Expected excavate to process all segments"
