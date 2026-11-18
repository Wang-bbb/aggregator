# -*- coding: utf-8 -*-

from __future__ import annotations

import utils
from outbound.base import OutboundVerifier, VerifyContext
from outbound.common import QuotedStr


class _UserPassVerifier(OutboundVerifier):
    def verify_fields(self, item: dict[str, object], ctx: VerifyContext) -> bool:
        # Public proxy lists often serialize missing credentials as the literal
        # strings "None" or "null". Treat those as absent, not real passwords.
        for field in ("username", "password"):
            value = item.get(field, None)
            if value is None:
                item.pop(field, None)
                continue

            if isinstance(value, str):
                value = utils.trim(value)
                if value.lower() in ("", "none", "null"):
                    item.pop(field, None)
                    continue
            elif not utils.is_number(value):
                return False

            if utils.is_number(value):
                item[field] = QuotedStr(value)
            else:
                item[field] = value

        # HTTP/SOCKS basic authentication requires a complete username/password
        # pair. If either side is missing, omit both and use no authentication.
        if not item.get("username") or not item.get("password"):
            item.pop("username", None)
            item.pop("password", None)

        return True

    def auth_field(self, item: dict[str, object]) -> str | None:
        return None

    def duplicate_key(self, item: dict[str, object]) -> tuple[str, object]:
        return (self.type_name,)


class HttpVerifier(_UserPassVerifier):
    type_name = "http"


class Socks5Verifier(_UserPassVerifier):
    type_name = "socks5"
