from .base import BaseModule
import re
import jwt as j


class jwt(BaseModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["INFO", "VULNERABILITY"]
    flags = ["passive"]
    deps_pip = ["pyjwt"]
    suppress_dupes = False

    def handle_event(self, event):

        jwt_candidates = []
        response_header = event.data["response-header"]
        response_body = event.data["response-body"]
        m = re.findall(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*", f"{response_header}{response_body}")

        for result in m:
            jwt_candidates.append(result)

        for jwt_candidate in jwt_candidates:

            try:
                j.decode(jwt_candidate, options={"verify_signature": False})
                jwt_headers = j.get_unverified_header(jwt_candidate)
                if jwt_headers["alg"].upper()[0:2] == "HS":
                    self.emit_event(f"JWT Identified [{jwt_candidate}]]", "INFO", event, tags=["crackable"])
                else:
                    self.emit_event(f"JWT Identified [{jwt_candidate}]]", "INFO", event)

            except jwt.exceptions.DecodeError:
                self.debug(f"Error decoding JWT candidate {jwt_candidate}")
