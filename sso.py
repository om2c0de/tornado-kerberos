import base64
import logging
import os
import sys
from abc import abstractmethod
from typing import Optional, Awaitable

# Platform-specific Kerberos requirements
if sys.platform == 'win32':
    import kerberos_sspi as kerberos
    import pywintypes

    pywintypes_error = pywintypes.error
else:
    import kerberos

    pywintypes_error = OSError


import tornado.httpserver
import tornado.ioloop
import tornado.web


class HeadersAlreadyWrittenException(Exception):
    pass


class KerberosAuthMixin(tornado.web.RequestHandler):
    """
    Authenticates users via Kerberos-based Single Sign-On.  Requires that you
    define 'sso_realm' and 'sso_service' in your Tornado Application settings.
    For example::

        settings = dict(
            cookie_secret="iYR123qg4UUdsgf4CRung6BFUBhizAciid8oq1YfJR3gN",
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            gzip=True,
            login_url="/auth",
            debug=True,
            sso_realm="EXAMPLE.COM",
            sso_service="HTTP" # Should pretty much always be HTTP
        )

    NOTE: If you're using 'HTTP' as the service it must be in all caps or it
    might not work with some browsers/clients (which auto-capitalize all
    services).

    To implement this mixin::

        from sso import KerberosAuthMixin


        class KerberosAuthHandler(tornado.web.RequestHandler, KerberosAuthMixin):

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
    """

    @abstractmethod
    def data_received(self, chunk: bytes) -> Optional[Awaitable[None]]:
        pass

    def initialize(self):
        """
        Print out helpful error messages if the requisite settings aren't
        configured.

        NOTE: It won't hurt anything to override this method in your
        RequestHandler.
        """
        self.require_setting("sso_realm", "Kerberos/GSSAPI Single Sign-On")
        self.require_setting("sso_service", "Kerberos/GSSAPI Single Sign-On")

    def get_authenticated_user(self, callback):
        """
        Processes the client's Authorization header and calls
        self.auth_negotiate() or self.auth_basic() depending on what headers
        were provided by the client.
        """
        keytab = self.settings.get('sso_keytab', None)
        if keytab:
            # The kerberos module does not take a keytab as a parameter when
            # performing authentication but you can still specify it via an
            # environment variable:
            os.environ['KRB5_KTNAME'] = keytab
        auth_header = self.request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Negotiate'):
            self.auth_negotiate(auth_header, callback)
        elif auth_header and auth_header.startswith('Basic '):
            self.auth_basic(auth_header, callback)

    def auth_negotiate(self, auth_header, callback):
        """
        Perform Negotiate (GSSAPI/SSO) authentication via Kerberos.
        """
        auth_str = auth_header.split()[1]
        # Initialize Kerberos Context
        context = None
        try:
            result, context = kerberos.authGSSServerInit(self.settings['sso_service'])
            if result is not kerberos.AUTH_GSS_COMPLETE:
                raise tornado.web.HTTPError(500, "Kerberos Init failed")
            result = kerberos.authGSSServerStep(context, auth_str)
            if result is kerberos.AUTH_GSS_COMPLETE:
                gss_string = kerberos.authGSSServerResponse(context)
                self.set_header('WWW-Authenticate', f"Negotiate {gss_string}")
            else:    # Fall back to Basic auth
                self.auth_basic(auth_header, callback)
            # NOTE: The user we get from Negotiate is a full UPN (user@REALM)
            user = kerberos.authGSSServerUserName(context)
        except (kerberos.GSSError, pywintypes_error) as e:
            logging.error(f"Kerberos Error: {e}")
            raise tornado.web.HTTPError(500, "Kerberos Init failed")
        finally:
            if context:
                kerberos.authGSSServerClean(context)
        callback(user)

    def auth_basic(self, auth_header, callback):
        """
        Perform Basic authentication using Kerberos against
        `self.settings['sso_realm']`.
        """
        auth_decoded = base64.decodebytes(auth_header[6:])
        username, password = auth_decoded.split(':', 1)
        try:
            kerberos.checkPassword(username, password, self.settings['sso_service'], self.settings['sso_realm'])
        except Exception as e:    # Basic auth failed
            if self.settings['debug']:
                print(e)    # Very useful for debugging Kerberos errors
            return self.authenticate_redirect()
        # NOTE: Basic auth just gives us the username without the @REALM part
        #       so we have to add it:
        user = f"{username}@{self.settings['sso_realm']}"
        callback(user)

    def authenticate_redirect(self):
        """
        Informs the browser that this resource requires authentication (status
        code 401) which should prompt the browser to reply with credentials.

        The browser will be informed that we support both Negotiate (GSSAPI/SSO)
        and Basic auth.
        """
        # NOTE: I know this isn't technically a redirect but I wanted to make
        # this process as close as possible to how things work in tornado.auth.
        if self._headers_written:
            raise HeadersAlreadyWrittenException
        self.set_status(401)
        self.add_header("WWW-Authenticate", "Negotiate")
        self.add_header("WWW-Authenticate", f'Basic realm="{self.settings["realm"]}"')
        self.finish()
        return False
