from .base import ModuleTestBase

from bbot.scanner import Scanner


class TestCloudCheck(ModuleTestBase):
    targets = ["http://127.0.0.1:8888", "asdf2.storage.googleapis.com"]
    modules_overrides = ["http", "excavate", "cloudcheck"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": "<a href='http://asdf.s3.amazonaws.com'/>"})

        scan = Scanner(config={"cloudcheck": True})
        await scan._prep()
        module = scan.modules["cloudcheck"]
        from cloudcheck import providers

        # make sure we have at least one provider
        assert providers.Amazon.name == "Amazon"

        ip_event = scan.make_event("8.8.8.8", parent=scan.root_event)
        aws_event1 = scan.make_event("amazonaws.com", parent=scan.root_event)
        aws_event2 = scan.make_event("asdf.amazonaws.com", parent=scan.root_event)
        aws_event3 = scan.make_event("asdfamazonaws.com", parent=scan.root_event)
        aws_event4 = scan.make_event("test.asdf.aws", parent=scan.root_event)

        other_event1 = scan.make_event("cname.evilcorp.com", parent=scan.root_event)
        other_event2 = scan.make_event("cname2.evilcorp.com", parent=scan.root_event)
        other_event3 = scan.make_event("cname3.evilcorp.com", parent=scan.root_event)
        other_event2.resolved_hosts = ("8.8.8.8",)
        other_event3.resolved_hosts = ("asdf.amazonaws.com",)

        for event in (ip_event, other_event2):
            await module.handle_event(ip_event)
            assert "google" in ip_event.tags
            assert "cloud" in ip_event.tags
            # check host_metadata has structured info
            assert "8.8.8.8" in ip_event.host_metadata
            assert "google" in ip_event.host_metadata["8.8.8.8"]["cloud_providers"]
            assert ip_event.host_metadata["8.8.8.8"]["cloud_providers"]["google"]["match"] == "ip"

        for event in (aws_event1, aws_event2, aws_event4, other_event3):
            await module.handle_event(event)
            assert "amazon" in event.tags, f"{event} was not properly cloud-tagged"
            assert "cloud" in event.tags, f"{event} was not properly cloud-tagged"

        # check match types in host_metadata
        assert aws_event1.host_metadata["amazonaws.com"]["cloud_providers"]["amazon"]["match"] == "domain"
        assert other_event3.host_metadata["asdf.amazonaws.com"]["cloud_providers"]["amazon"]["match"] == "cname"

        for event in (aws_event3, other_event1):
            await module.handle_event(event)
            assert "amazon" not in event.tags, f"{event} was improperly cloud-tagged"
            assert "cloud" not in event.tags, f"{event} was improperly cloud-tagged"

        google_event1 = scan.make_event("asdf.googleapis.com", parent=scan.root_event)
        google_event2 = scan.make_event("asdf.google", parent=scan.root_event)
        google_event3 = scan.make_event("asdf.evilcorp.com", parent=scan.root_event)
        google_event3.resolved_hosts = ("asdf.storage.googleapis.com",)

        for event in (google_event1, google_event2, google_event3):
            await module.handle_event(event)
            assert "google" in event.tags, f"{event} was not properly cloud-tagged"
            assert "cloud" in event.tags, f"{event} was not properly cloud-tagged"

        # ── Parent-inheritance regression tests ────────────────────────
        # cloudcheck has a fast path where a child event with hosts ⊆ parent's
        # hosts inherits the parent's cloud tags instead of re-running lookups.
        # Correctness requires that tags are only inherited PER HOST — a child
        # without parent's cloud-tagged host must NOT inherit that tag.

        # Build a parent with TWO hosts: one matches Amazon (via CNAME), the
        # other doesn't. Parent's event-level tags will include "amazon" /
        # "cloud" because of the matching host.
        inherit_parent = scan.make_event("evilcorp.com", parent=scan.root_event)
        inherit_parent.resolved_hosts = ("asdf.amazonaws.com", "10.0.0.1")
        await module.handle_event(inherit_parent)
        assert "amazon" in inherit_parent.tags, "parent should have inherited amazon from CNAME"
        assert "cloud" in inherit_parent.tags
        assert "asdf.amazonaws.com" in inherit_parent.host_metadata
        # the non-matching hosts must NOT appear in host_metadata
        assert "10.0.0.1" not in inherit_parent.host_metadata
        assert "evilcorp.com" not in inherit_parent.host_metadata

        # CASE A — child host set is a SUBSET of parent's but EXCLUDES the
        # Amazon-matching host. The child must not inherit "amazon" / "cloud".
        # This is the leak the regression test guards against.
        child_excludes_match = scan.make_event("evilcorp.com", parent=inherit_parent)
        child_excludes_match.resolved_hosts = ("10.0.0.1",)
        await module.handle_event(child_excludes_match)
        assert "amazon" not in child_excludes_match.tags, "amazon tag leaked from parent host the child doesn't have"
        assert "cloud" not in child_excludes_match.tags, "cloud tag leaked from parent host the child doesn't have"
        assert "asdf.amazonaws.com" not in child_excludes_match.host_metadata, "metadata for excluded host leaked"

        # CASE B — child INCLUDES the Amazon-matching host. It should inherit
        # "amazon" / "cloud", and `match` is recomputed from child's view
        # (here "asdf.amazonaws.com" is at position 1, so still "cname").
        child_includes_match = scan.make_event("evilcorp.com", parent=inherit_parent)
        child_includes_match.resolved_hosts = ("asdf.amazonaws.com",)
        await module.handle_event(child_includes_match)
        assert "amazon" in child_includes_match.tags
        assert "cloud" in child_includes_match.tags
        assert "asdf.amazonaws.com" in child_includes_match.host_metadata
        assert (
            child_includes_match.host_metadata["asdf.amazonaws.com"]["cloud_providers"]["amazon"]["match"] == "cname"
        )

        # CASE C — child whose primary host IS the Amazon CNAME target.
        # Subset gate still passes (host is in parent's resolved_hosts), and
        # `match` recomputes to "domain" from child's perspective (i==0).
        child_cname_as_primary = scan.make_event("asdf.amazonaws.com", parent=inherit_parent)
        await module.handle_event(child_cname_as_primary)
        assert "amazon" in child_cname_as_primary.tags
        assert child_cname_as_primary.host_metadata["asdf.amazonaws.com"]["cloud_providers"]["amazon"]["match"] == (
            "domain"
        ), "match should be recomputed from child's perspective, not inherited as parent's 'cname'"

        # CASE D — child whose hosts are DISJOINT from parent's. Subset gate
        # fails → falls back to normal lookup. Child gets Google tags from a
        # real lookup, not via inheritance.
        child_disjoint = scan.make_event("8.8.8.8", parent=inherit_parent)
        await module.handle_event(child_disjoint)
        assert "google" in child_disjoint.tags
        assert "cloud" in child_disjoint.tags

        # ── _minimize() must not wipe resolved_hosts ───────────────────
        # Real scan flow: a DNS_NAME gets processed by dnsresolve + cloudcheck,
        # then Event._minimize() decrements its consumer count. Later, child
        # events (URL, OPEN_TCP_PORT) that share the DNS_NAME's host reach
        # dnsresolve and copy the parent's resolved_hosts (line 156). If
        # _minimize() wiped resolved_hosts, that copy carries nothing and
        # cloudcheck's per-host filter has no IPs to match against, so the
        # cloud tag never inherits.
        minimized = scan.make_event("minimize.evilcorp.com", parent=scan.root_event)
        minimized.resolved_hosts = ("asdf.amazonaws.com", "10.0.0.1")
        await module.handle_event(minimized)
        # drive _module_consumers below 0 so the wipe block runs
        minimized._minimize()
        minimized._minimize()
        assert minimized.resolved_hosts, (
            "_minimize() must preserve resolved_hosts — dnsresolve line 156 copies it to child "
            "URL/OPEN_TCP_PORT events, and cloudcheck's per-host inheritance needs those IPs"
        )
        # cloud host_metadata already survives minimization; confirm
        assert "asdf.amazonaws.com" in minimized.host_metadata

        # ── URL/OPEN_TCP_PORT propagation end-to-end ──────────────────
        # Together with the _minimize() preservation above, this exercises
        # the real flow: parent DNS_NAME cloud-tagged, then minimized, then a
        # URL child gets its resolved_hosts populated (mirroring dnsresolve),
        # and cloudcheck's existing subset-gate + per-host filter should copy
        # the cloud tag onto the child.
        url_child = scan.make_event(
            "http://minimize.evilcorp.com/",
            "URL",
            parent=minimized,
            tags=["status-200", "in-scope"],
        )
        # simulate dnsresolve intercept: child inherits parent's resolved_hosts
        url_child._resolved_hosts = minimized.resolved_hosts
        await module.handle_event(url_child)
        assert "amazon" in url_child.tags, (
            "URL child of amazon-tagged DNS_NAME must inherit the cloud tag "
            "once its resolved_hosts carries the parent's IPs"
        )
        assert "cloud" in url_child.tags
        assert "asdf.amazonaws.com" in url_child.host_metadata

        port_child = scan.make_event(
            "minimize.evilcorp.com:443",
            "OPEN_TCP_PORT",
            parent=minimized,
        )
        port_child._resolved_hosts = minimized.resolved_hosts
        await module.handle_event(port_child)
        assert "amazon" in port_child.tags, "OPEN_TCP_PORT child must inherit cloud tag from parent"
        assert "asdf.amazonaws.com" in port_child.host_metadata

        # ── YARA prefilter short-circuit ───────────────────────────────
        # When no host could possibly match any bucket regex (mismatched
        # suffix) the prefilter returns no matches and we skip the Python
        # regex loop entirely. We can't easily assert "loop was skipped"
        # from outside, but we can verify the prefilter behavior directly.
        # No false negatives are checked above by the full TestCloudCheck
        # scan flow (which asserts STORAGE_BUCKET events are still emitted
        # for asdf.s3.amazonaws.com / asdf2.storage.googleapis.com).
        assert module._bucket_yara is not None, "bucket YARA prefilter must compile at setup"
        # known bucket hostnames must hit the prefilter
        for hostname in ("foo.s3.amazonaws.com", "bar.r2.dev", "baz.blob.core.windows.net"):
            assert module._bucket_yara.match(data=hostname), f"prefilter must hit on real bucket hostname {hostname}"
        # ordinary hostnames must not
        for hostname in ("evilcorp.com", "www.example.com", "api.foo.bar.net"):
            assert not module._bucket_yara.match(data=hostname), (
                f"prefilter must not hit on non-bucket hostname {hostname}"
            )

        # ── LRU cache on cloudcheck.lookup() ───────────────────────────
        # repeated hosts hit the cache instead of re-issuing the Future-
        # based lookup. The cloudcheck Rust binding has read-only attrs,
        # so we swap the entire helper-level instance with a counting
        # wrapper rather than monkey-patching `.lookup` on the Rust object.
        class _CountingCloudCheck:
            def __init__(self, real):
                self.real = real
                self.calls = 0

            def lookup(self, target):
                self.calls += 1
                return self.real.lookup(target)

        original_cc = scan.helpers._cloudcheck
        counter = _CountingCloudCheck(original_cc)
        scan.helpers._cloudcheck = counter
        try:
            # clear the cache so the first miss is observable
            module._lookup_cache.clear()
            # first event: 1 host + 1 IP → 2 real lookups
            cache_event1 = scan.make_event("cache-test-1.evilcorp.com", parent=scan.root_event)
            cache_event1.resolved_hosts = ("203.0.113.42",)
            await module.handle_event(cache_event1)
            first_round = counter.calls
            assert first_round >= 2, f"expected ≥2 lookups (host + IP), got {first_round}"

            # second event with the same hosts: 0 additional real lookups
            cache_event2 = scan.make_event("cache-test-1.evilcorp.com", parent=scan.root_event)
            cache_event2.resolved_hosts = ("203.0.113.42",)
            await module.handle_event(cache_event2)
            assert counter.calls == first_round, (
                f"LRU cache miss: expected no new lookups, got {counter.calls - first_round}"
            )

            # third event with a NEW host: exactly one extra lookup
            cache_event3 = scan.make_event("cache-test-2.evilcorp.com", parent=scan.root_event)
            cache_event3.resolved_hosts = ("203.0.113.42",)
            await module.handle_event(cache_event3)
            assert counter.calls == first_round + 1, (
                f"expected 1 new lookup for new host, got {counter.calls - first_round}"
            )
        finally:
            scan.helpers._cloudcheck = original_cc

        await scan._cleanup()

    def check(self, module_test, events):
        assert 2 == len([e for e in events if e.type == "STORAGE_BUCKET"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "STORAGE_BUCKET"
                and e.data["name"] == "asdf"
                and str(e.module) == "cloudcheck"
                and e.scope_distance == 1
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "STORAGE_BUCKET"
                and e.data["name"] == "asdf2"
                and str(e.module) == "cloudcheck"
                and e.scope_distance == 0
            ]
        )

        # verify host_metadata is populated by cloudcheck on real scan events
        url_events = [e for e in events if e.type == "URL"]
        for url_event in url_events:
            if url_event.host_metadata:
                # check structure: {host: {cloud_providers: {name: {types: [...], match: "..."}}}}
                for host, meta in url_event.host_metadata.items():
                    assert "cloud_providers" in meta, f"host_metadata for {host} missing cloud_providers"
                    for provider_name, provider_info in meta["cloud_providers"].items():
                        assert "types" in provider_info, f"cloud_providers[{provider_name}] missing types"
                        assert "match" in provider_info, f"cloud_providers[{provider_name}] missing match"
                        assert provider_info["match"] in ("ip", "domain", "cname"), (
                            f"unexpected match type: {provider_info['match']}"
                        )
