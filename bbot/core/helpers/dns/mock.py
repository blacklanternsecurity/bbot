import dns
import logging

log = logging.getLogger("bbot.core.helpers.dns.mock")


class MockResolver:
    def __init__(self, mock_data=None, custom_lookup_fn=None):
        self.mock_data = mock_data if mock_data else {}
        self._custom_lookup_fn = custom_lookup_fn
        self.nameservers = ["127.0.0.1"]

    async def resolve_address(self, ipaddr, *args, **kwargs):
        modified_kwargs = {}
        modified_kwargs.update(kwargs)
        modified_kwargs["rdtype"] = "PTR"
        return await self.resolve(str(dns.reversename.from_address(ipaddr)), *args, **modified_kwargs)

    def _lookup(self, query, rdtype):
        query = query.strip(".")
        ret = []
        if self._custom_lookup_fn is not None:
            answers = self._custom_lookup_fn(query, rdtype)
            if answers is not None:
                ret.extend(list(answers))
        answers = self.mock_data.get(query, {}).get(rdtype, [])
        if answers:
            ret.extend(list(answers))
        if not ret:
            raise dns.resolver.NXDOMAIN(f"No answer found for {query} {rdtype}")
        return ret

    def create_dns_response(self, query_name, answers, rdtype):
        query_name = query_name.strip(".")
        message_text = f"""id 1234
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
{query_name}. IN {rdtype}
;ANSWER"""
        for answer in answers:
            if answer == "":
                answer = '""'
            message_text += f"\n{query_name}. 1 IN {rdtype} {answer}"

        message_text += "\n;AUTHORITY\n;ADDITIONAL\n"
        message = dns.message.from_text(message_text)
        # log.verbose(message_text)
        return message

    async def resolve(self, query_name, rdtype=None):
        if rdtype is None:
            rdtype = "A"
        elif isinstance(rdtype, str):
            rdtype = rdtype.upper()
        else:
            rdtype = str(rdtype.name).upper()

        domain_name = dns.name.from_text(query_name)
        rdtype_obj = dns.rdatatype.from_text(rdtype)

        if "_NXDOMAIN" in self.mock_data and query_name in self.mock_data["_NXDOMAIN"]:
            # Simulate the NXDOMAIN exception
            raise dns.resolver.NXDOMAIN

        try:
            answers = self._lookup(query_name, rdtype)
            log.verbose(f"Answers for {query_name}:{rdtype}: {answers}")
            response = self.create_dns_response(query_name, answers, rdtype)
            answer = dns.resolver.Answer(domain_name, rdtype_obj, dns.rdataclass.IN, response)
            return answer
        except dns.resolver.NXDOMAIN:
            return []
