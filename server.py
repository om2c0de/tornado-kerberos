import logging
import os
import sys
from abc import abstractmethod
from typing import Optional, Awaitable

import tornado.escape
import tornado.ioloop
import tornado.web

from sso import KerberosAuthMixin

# Initialize logger
logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


class KerberosAuthHandler(KerberosAuthMixin):

    def get(self):
        auth_header = self.request.headers.get("Authorization")
        if auth_header:
            self.get_authenticated_user(self._on_auth)
            return
        self.authenticate_redirect()

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Kerberos auth failed")
        self.set_secure_cookie("user", tornado.escape.json_encode(user))
        logging.debug(f"KerberosAuthHandler user: {user}")   # To see what you get
        next_url = self.get_argument("next", None)    # To redirect properly
        if next_url:
            self.redirect(next_url)
        else:
            self.redirect("/")

    @abstractmethod
    def data_received(self, chunk: bytes) -> Optional[Awaitable[None]]:
        ...


if __name__ == "__main__":
    endpoints = [
        (r"/auth", KerberosAuthHandler)
    ]
    settings = {
        "cookie_secret": "iYR123qg4UUdsgf4CRung6BFUBhizAciid8oq1YfJR3gN",
        "static_path": os.path.join(os.path.dirname(__file__), "static"),
        "gzip": True,
        "login_url": "/auth",
        "debug": True,
        "realm": "gpnhpetest.gpndt.test",
        "sso_realm": "gpnhpetest.gpndt.test",
        "sso_service": "HTTP"   # Should pretty much always be HTTP
    }
    app = tornado.web.Application(endpoints, **settings)
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
