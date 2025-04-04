import time
import asyncpg

from bbot.modules.templates.subdomain_enum import subdomain_enum


class crt_db(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
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

    async def request_url(self, query):
        if not self.db_conn:
            self.db_conn = await asyncpg.connect(
                host=self.db_host,
                port=self.db_port,
                user=self.db_user,
                database=self.db_name,
                statement_cache_size=0,  # Disable automatic statement preparation
            )

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
        results = await self.db_conn.fetch(sql, query)
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
