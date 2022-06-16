from .base import BaseModule
import re
from jwt import PyJWT
from jwt.exceptions import DecodeError


class jwt(BaseModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["INFO", "VULNERABILITY"]
    deps_pip = ["PyJWT"]
    suppress_dupes = False

    def handle_event(self, event):

        jwt_candidates = []
        response_header = event.data["response-header"]
        response_body = event.data["response-body"]
        m = re.findall(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*", f"{response_header}{response_body}")

        for result in m:
            jwt_candidates.append(result)

        for jwt_candidate in jwt_candidates:
            j = PyJWT()

            try:
                j.decode(jwt_candidate, options={"verify_signature": False})
                self.emit_event(f"JWT Identified [{jwt_candidate}]]", "INFO", event)
            except DecodeError:
                self.debug(f"Error decodeing JWT candidate {jwt_candidate}")
