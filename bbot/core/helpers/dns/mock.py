import dns


class MockResolver:

    def __init__(self, mock_data=None):
        self.mock_data = mock_data if mock_data else {}
        self.nameservers = ["127.0.0.1"]

    async def resolve_address(self, ipaddr, *args, **kwargs):
        modified_kwargs = {}
        modified_kwargs.update(kwargs)
        modified_kwargs["rdtype"] = "PTR"
        return await self.resolve(str(dns.reversename.from_address(ipaddr)), *args, **modified_kwargs)

    def create_dns_response(self, query_name, rdtype):
        query_name = query_name.strip(".")
        answers = self.mock_data.get(query_name, {}).get(rdtype, [])
        if not answers:
            raise dns.resolver.NXDOMAIN(f"No answer found for {query_name} {rdtype}")

        message_text = f"""id 1234
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
{query_name}. IN {rdtype}
;ANSWER"""
        for answer in answers:
            message_text += f"\n{query_name}. 1 IN {rdtype} {answer}"

        message_text += "\n;AUTHORITY\n;ADDITIONAL\n"
        message = dns.message.from_text(message_text)
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
            response = self.create_dns_response(query_name, rdtype)
            answer = dns.resolver.Answer(domain_name, rdtype_obj, dns.rdataclass.IN, response)
            return answer
        except dns.resolver.NXDOMAIN:
            return []
