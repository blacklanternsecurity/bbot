import time
import asyncpg

from bbot.modules.templates.subdomain_enum import subdomain_enum


class crt_db(subdomain_enum):
    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query crt.sh (certificate transparency) for subdomains via PostgreSQL",
        "created_date": "2025-03-27",
        "author": "@TheTechromancer",
    }

    deps_pip = ["asyncpg"]

    db_host = "crt.sh"
    db_port = 5432
    db_user = "guest"
    db_name = "certwatch"
    reject_wildcards = False

    async def setup(self):
        self.db_conn = None
        return await super().setup()

    async def _connect(self):
        return await asyncpg.connect(
            host=self.db_host,
            port=self.db_port,
            user=self.db_user,
            database=self.db_name,
            statement_cache_size=0,  # Disable automatic statement preparation
        )

    async def request_url(self, query):
        # asyncpg connections can drop mid-scan when the upstream Postgres restarts,
        # exhausts shared memory, or idles us out. Reconnect on the next call.
        if self.db_conn is None or self.db_conn.is_closed():
            self.db_conn = await self._connect()

        sql = """
        WITH ci AS (
            SELECT array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES
            FROM (
                SELECT DISTINCT cai.CERTIFICATE, cai.NAME_VALUE
                FROM certificate_and_identities cai
                WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
                    AND cai.NAME_VALUE ILIKE ('%.' || $1)
                LIMIT 50000
            ) sub
            GROUP BY sub.CERTIFICATE
        )
        SELECT DISTINCT unnest(NAME_VALUES) as name_value FROM ci;
        """
        start = time.time()
        try:
            results = await self.db_conn.fetch(sql, query)
        except (asyncpg.InterfaceError, asyncpg.PostgresConnectionError, ConnectionError):
            # connection died between requests; drop it so the next call reconnects
            self.db_conn = None
            raise
        except asyncpg.OutOfMemoryError as e:
            # upstream is overloaded; bail out for the rest of the scan rather than hammer it
            self.set_error_state(f"crt.sh Postgres reported out-of-memory: {e}")
            return []
        end = time.time()
        self.verbose(f"SQL query executed in: {end - start} seconds with {len(results):,} results")
        return results

    async def parse_results(self, results, query):
        domains = set()
        for row in results:
            domain = row["name_value"]
            if domain:
                for d in domain.splitlines():
                    domains.add(d.lower())
        return domains

    async def cleanup(self):
        if self.db_conn:
            await self.db_conn.close()
