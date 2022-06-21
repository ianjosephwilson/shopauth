"""
@NOTE: Resolution for shop name overloading.

shop_name: The name of the shop, used as a subdomain of myshopify.com
shop_host: The shopname and the correct top level domain: "{shop_name}.myshopify.com".
encoded_shop_host: Almost base64 encoded shop_host but has trailing unknown
    padding, provided by shopify for reasons unknown.

@NOTE: Resolution for session type overloading.

We split up the "sessions" into 4 subtypes: oauth, online, offline and install in
order to resolve confusion around session handling.  Oauth sessions are short
lived, online sessions are longer but cease when the user logs out and offline
sessions last until the shop uninstalls the application.  The install sessions are
needed for when an online-only shop needs to know if it was ever installed.
If our access scopes change we will need the owner to login again and we will
have to update the existing offline session (and access token).
"""
import logging
from dataclasses import dataclass, asdict, field
import re
import json
import random
import string
import uuid
import hmac
import hashlib
import time
from urllib.parse import urlencode

import jwt
import requests
import zope.interface
from datetime import timedelta, datetime, timezone

from .interfaces import (
    IWebShim,
    IStorageShim,
    ISessionSerializer,
    IAppInstalledHandler,
)
from .scopes import scopes_have_changed

logger = logging.getLogger(__name__)


@dataclass
class ShopAuthConfig:
    """
    Mechanism to provide configuration to ShopAuthService.
    """

    api_key: str
    api_version: str
    api_secret: str
    # If the app will be embedded in an iframe in the admin.
    embedded: bool
    # If we need to make offline calls to shopify
    # OR if we are not using the online access usage.
    need_offline_access_token: bool
    # If we want online access that matches the logged in user.
    need_online_access_token: bool
    # The shopify access scopes that our app needs, such as read_orders, write_orders, etc.
    access_scopes: tuple
    jwt_leeway_in_seconds: int = 5
    # Used to track the oauth session.
    oauth_cookie_name: str = "shopify_oauth"
    # Used to check if we broke out of the iframe or not.
    toplevel_cookie_name: str = "shopify_toplevel"
    # Used to track regular auth session, ie. after oauth process ends, online/offline.
    auth_cookie_name: str = "shopify_auth"
    # Special cookie to handle embedded case where we
    # load skeleton page.
    home_redirect_cookie_name: str = "home_redirect"


OAUTH_SESSION_TYPE = "oauth"


@dataclass
class OAuthSession:
    """
    Holds values between initial oauth authorization request and
    the subsequent response received via redirect.
    """

    # Placed in cookie and used to lookup stored session.
    id: str
    # Name of the shop the request was for.
    shop_name: str
    # Key used once to check that response from shopify originated with our request.
    nonce: str
    # Either online or offline
    requested_access_mode: str
    # The scopes our app requested access to.
    requested_access_scopes: list[str]
    # When this oauth session expires
    expires_at_utcstamp: str
    # The type of session this is, readonly.
    type: str = OAUTH_SESSION_TYPE


@dataclass
class AssociatedUser:
    """
    The user associated with the current online access token.
    """

    id: int
    first_name: str
    last_name: str
    email: str
    email_verified: bool
    account_owner: bool
    locale: str
    collaborator: bool


@dataclass
class OnlineAccessInfo:
    """
    The access info for the current online access token.
    """

    expires_in: int
    associated_user_scope: str
    associated_user: AssociatedUser
    # what is this
    session: str = ""
    # what is this
    account_number: int = 0


ONLINE_ACCESS_MODE = "online"


OFFLINE_ACCESS_MODE = "offline"


@dataclass
class OnlineSession:
    """
    Holds values surrounding the current online access token for the duration
    of a session.
    """

    id: str
    access_token: str
    shop_name: str
    # The granted scopes.
    access_scopes: list[str]
    expires_at_utcstamp: str
    online_access_info: OnlineAccessInfo
    type: str = ONLINE_ACCESS_MODE


@dataclass
class OfflineSession:
    """
    Holds values surrounding the current offline access token indefinately
    until the shop owner uninstalls the application.  This session should
    be removed when the shop owner uninstalls the application.
    """

    id: str
    access_token: str
    shop_name: str
    # The granted scopes.
    access_scopes: list[str]
    type: str = OFFLINE_ACCESS_MODE
    # This doesn't expire.
    expires_at_utcstamp: str = None


INSTALL_SESSION_TYPE = "install"


@dataclass
class InstallSession:
    """
    Tracks if an app is installed or not independent of access mode.
    """

    id: str
    shop_name: str
    # The scopes we were granted on install.
    access_scopes: list[str]
    type: str = INSTALL_SESSION_TYPE
    # This doesn't expire.
    expires_at_utcstamp: str = None


DEFAULT_SESSION_TYPE_LOOKUP = {
    OFFLINE_ACCESS_MODE: OfflineSession,
    ONLINE_ACCESS_MODE: OnlineSession,
    OAUTH_SESSION_TYPE: OAuthSession,
    INSTALL_SESSION_TYPE: InstallSession,
}


@zope.interface.implementer(ISessionSerializer)
@dataclass
class ShopSessionSerializer:
    """
    Convert different types of sessions to and from plain dictionaries.

    Intended for storing and loading sessions from a JSON blob in a db.
    """

    lookup: dict = field(default_factory=lambda: DEFAULT_SESSION_TYPE_LOOKUP.copy())

    def get_type_cls(self, session_dict):
        return self.lookup[session_dict["type"]]

    def from_dict(self, session_dict):
        if not session_dict:
            return None
        else:
            return self.get_type_cls(session_dict)(**session_dict)

    def to_dict(self, session):
        return asdict(session)


@dataclass
class ShopifyJWTPayload:
    """
    Holds the fields extracted from Shopify's JWT token.

    @SEE: https://shopify.dev/apps/auth/oauth/session-tokens#payload

    iss: The shop's admin domain.
    dest: The shop's domain. (we cann this shop_host)
    aud: The API key of the receiving app.
    sub: The user that the session token is intended for.
    exp: When the session token expires.
    nbf: When the session token activates.
    iat: When the session token was issued.
    jti: A secure random UUID.
    sid: A unique session ID per user and app.
    """

    iss: str
    dest: str
    aud: str
    sub: str
    exp: int
    nbf: int
    iat: int
    jti: str
    sid: str


DAY_IN_SECONDS = 24 * 60 * 60


MINUTE_IN_SECONDS = 60


ZERO_SECONDS = 0


@dataclass
class ShopAuthService:
    """
    Provide Shopify oauth functions as well as check for JWTs provided by Shopify's AppBridge.
    """

    config: ShopAuthConfig
    web_shim: IWebShim
    storage_shim: IStorageShim
    # Optional handler for app installs.
    app_installed_handler: IAppInstalledHandler = None
    test_graphql_query: str = """{ shop { name } }"""
    utcnow: callable = field(default=lambda: datetime.now(timezone.utc))
    read_utcstamp: callable = field(
        default=lambda utcstamp: datetime.fromisoformat(utcstamp)
    )
    write_utcstamp: callable = field(default=lambda d: d.isoformat())
    toplevel_redirect_html_content_fmt: str = """<!DOCTYPE html>
<html>
  <head>
    <script src="https://unpkg.com/@shopify/app-bridge@2"></script>
    <script>
      document.addEventListener('DOMContentLoaded', function () {
        var config = %s;
        if (window.top === window.self) {
          window.location.href = config.authUrl;
        } else {
          var AppBridge = window['app-bridge'];
          var createApp = AppBridge.default;
          var Redirect = AppBridge.actions.Redirect;
          const app = createApp({
            apiKey: config.apiKey,
            host: config.encodedShopHost,
          });
          const redirect = Redirect.create(app);
          redirect.dispatch(
            Redirect.Action.REMOTE,
            config.toplevelAuthUrl,
          );
        }
      });
    </script>
  </head>
  <body></body>
</html>"""

    def check_app_installed(self):
        """Check if the app is installed by looking up the shop install session.

        This is pretty much only used when first loading the client code,
        we won't be authenticating anything here because it doesn't seem that
        the cookie or hmac are sent on that page.  Warts on warts.

        Returns a 2-tuple of (install_session, redirect).
        """
        shop_host = self.web_shim.get_param("shop", None)
        if not shop_host:
            return None, None
        shop_name = self.extract_shop_name(shop_host)
        install_session = self.storage_shim.load_session(
            self.get_install_session_id(shop_name)
        )
        if not install_session:
            logger.info("No install session found, app is not installed.")
            return None, self.redirect_to_auth()
        elif scopes_have_changed(
            installed_scopes=install_session.access_scopes,
            expected_scopes=self.config.access_scopes,
        ):
            logger.info("Scopes have changed, redirect to re-install/update app.")
            return None, self.redirect_to_auth()
        return install_session, None

    def set_app_headers(self):
        """Set headers for serving the app.

        This should be set on embedded app skeleton page as well as all
        standalone pages.
        """
        shop_host = self.web_shim.get_param("shop")
        if self.config.embedded and shop_host:
            self.web_shim.set_header(
                "Content-Security-Policy",
                f"frame-ancestors https://{shop_host} https://admin.shopify.com;",
            )
        else:
            self.web_shim.set_header(
                "Content-Security-Policy", "frame-ancestors 'none';"
            )

    def get_utcstamp(self, after_seconds):
        return self.write_utcstamp(self.utcnow() + timedelta(seconds=after_seconds))

    def is_utcstamp_expired(self, utcstamp, use_as_utcnow=None):
        datetime_to_check = self.read_utcstamp(utcstamp)
        now = use_as_utcnow if use_as_utcnow else self.utcnow()
        return now > datetime_to_check

    def get_install_session_id(self, shop_name):
        return f"install_{shop_name}"

    def create_install_session(self, shop_name, access_scopes):
        session_id = self.get_install_session_id(shop_name)
        return InstallSession(
            id=session_id, shop_name=shop_name, access_scopes=access_scopes
        )

    def get_oauth_session_id(self):
        return f"oauth_{str(uuid.uuid4())}"

    def create_oauth_session(
        self,
        shop_name,
        nonce,
        requested_access_mode,
        requested_access_scopes,
        expires_in_seconds=MINUTE_IN_SECONDS,
    ):
        session_id = self.get_oauth_session_id()
        expires_at_utcstamp = self.get_utcstamp(after_seconds=expires_in_seconds)
        return OAuthSession(
            id=session_id,
            nonce=nonce,
            requested_access_mode=requested_access_mode,
            requested_access_scopes=requested_access_scopes,
            shop_name=shop_name,
            expires_at_utcstamp=expires_at_utcstamp,
        )

    def get_online_session_id(self, shop_name, user_id):
        return f"online_{shop_name}_{user_id}"

    def create_online_session(
        self, shop_name, access_token, access_scopes, remaining_response_params
    ):
        # Just make a copy of this before mutating it.
        remaining_response_params = remaining_response_params.copy()
        associated_user = AssociatedUser(
            **remaining_response_params.pop("associated_user")
        )
        online_access_info = OnlineAccessInfo(
            associated_user=associated_user, **remaining_response_params
        )
        session_id = self.get_online_session_id(
            shop_name, online_access_info.associated_user.id
        )
        expires_at_utcstamp = self.get_utcstamp(
            after_seconds=online_access_info.expires_in
        )
        return OnlineSession(
            id=session_id,
            access_token=access_token,
            shop_name=shop_name,
            access_scopes=access_scopes,
            expires_at_utcstamp=expires_at_utcstamp,
            online_access_info=online_access_info,
        )

    def get_offline_session_id(self, shop_name):
        return f"offline_{shop_name}"

    def create_offline_session(self, shop_name, access_token, access_scopes):
        session_id = self.get_offline_session_id(shop_name)
        return OfflineSession(
            id=session_id,
            access_token=access_token,
            shop_name=shop_name,
            access_scopes=access_scopes,
        )

    def test_access(self, auth_session):
        """Test that the current authenticated session has access."""
        return self.execute_graphql(
            auth_session.shop_name,
            self.config.api_version,
            auth_session.access_token,
            self.test_graphql_query,
        )

    def auth_toplevel(self):
        """
        Return an html page that breaks out of any iframe it is in.
        """
        # We set this cookie to let begin_auth know that we broke out.
        self.web_shim.set_cookie(
            self.config.toplevel_cookie_name,
            "1",
            signed=True,
            max_age=MINUTE_IN_SECONDS,
            samesite="lax",
            secure=True,
        )
        query_params = self.web_shim.get_params(["hmac", "timestamp", "shop", "host"])
        content = self.get_toplevel_redirect_html_content(
            self.config.api_key,
            query_params["host"],
            self.web_shim.get_auth_url(query_params),
            self.web_shim.get_auth_toplevel_url(query_params),
        )
        return self.web_shim.response_200_string(content)

    def is_session_expired(self, auth_session):
        return auth_session.expires_at_utcstamp and self.is_utcstamp_expired(
            auth_session.expires_at_utcstamp
        )

    def verify_api_access(self):
        if self.config.embedded:
            return self.check_embedded_auth_session()
        else:
            return self.check_standalone_auth_session()

    def verify_page_access(self):
        if self.config.embedded:
            return self.verify_embedded_page_access()
        else:
            return self.check_standalone_auth_session()

    def check_standalone_auth_session(self):
        """
        This should be used for pages or apis.
        """
        if self.config.embedded:
            raise AssertionError("Only use this for standalone applications.")
        session_id = self.web_shim.get_cookie(self.config.auth_cookie_name, signed=True)
        if not session_id:
            return None, self.redirect_to_auth()
        auth_session = self.storage_shim.load_session(session_id)
        if not auth_session or self.is_session_expired(auth_session):
            return None, self.redirect_to_auth()
        else:
            return auth_session, None

    def verify_embedded_page_access(self):
        """
        This should be used for loading pages embedded in shopify AND our first home page /skeleton load.

        This does not return a session.
        """
        if not self.config.embedded:
            raise AssertionError("Only use this for embedded applications.")

        install_session, error_response = self.check_app_installed()
        if error_response:
            logger.info("App is not installed")
            return None, error_response

        params = self.web_shim.get_params(["hmac", "timestamp", "shop", "host"])
        if params["hmac"]:
            error_response = self.validate_hmac()
            if error_response:
                logger.error("HMAC BAD, is not valid.")
                return None, self.redirect_to_auth()
            else:
                logger.info("HMAC OK, continue with home page")
                return install_session, None
        else:
            if (
                self.web_shim.get_cookie(
                    self.config.home_redirect_cookie_name, signed=True
                )
                == "1"
            ):
                logger.info("COOKIE OK, continue with home page")
                return install_session, None
            else:
                logger.info("COOKIE BAD, isn't 1")
                return None, self.redirect_to_auth()

    def check_embedded_auth_session(self):
        """
        This should be used for loading apis from our embedded client using JWTs.
        """
        if not self.config.embedded:
            raise AssertionError("Only use this for embedded applications.")
        auth_header = self.web_shim.get_header("Authorization")
        if not auth_header:
            return None, self.redirect_with_header()
        else:
            try:
                payload = self.extract_jwt_token(
                    auth_header,
                    self.config.api_key,
                    self.config.api_secret,
                    self.config.jwt_leeway_in_seconds,
                )
            except ValueError as e:
                return None, self.web_shim.response_bad_request(f"{e}")
            shop_host = payload.dest[len("https://") :]
            shop_name = self.extract_shop_name(shop_host)
            if self.config.need_online_access_token:
                user_id = payload.sub
                online_session = self.storage_shim.load_session(
                    self.get_online_session_id(shop_name, user_id)
                )
                if not online_session or self.is_session_expired(online_session):
                    return None, self.redirect_with_header()
                return online_session, None
            else:
                offline_session = self.storage_shim.load_session(
                    self.get_offline_session_id(shop_name)
                )
                if not offline_session:
                    return None, self.redirect_with_header()
                return offline_session, None

    def redirect_with_header(self):
        self.web_shim.set_header("X-Shopify-API-Request-Failure-Reauthorize", "1")
        # @TODO: Is this the right url ?  Does anyone really know?
        self.web_shim.set_header(
            "X-Shopify-API-Request-Failure-Reauthorize-Url",
            self.web_shim.get_auth_url(
                get_params=self.web_shim.get_params(["shop", "host"])
            ),
        )

        return self.web_shim.response_403()

    def begin_auth(self):
        """
        Start an oauth session and redirect back to shopify to request a token.
        """
        # If we have not broken out of the iframe then redirect to a page
        # that will break us from the iframe.
        if (
            not self.web_shim.get_cookie(self.config.toplevel_cookie_name, signed=True)
            == "1"
        ):
            return self.web_shim.redirect_302_url(
                self.web_shim.get_auth_toplevel_url(
                    self.web_shim.get_params(["shop", "timestamp", "hmac", "host"])
                )
            )

        shop_host = self.web_shim.get_param("shop")

        shop_name = self.extract_shop_name(shop_host)
        if not shop_name:
            return self.web_shim.response_bad_request("Shop is not properly formatted")

        if (
            self.config.need_online_access_token
            and self.config.need_offline_access_token
        ):
            # If the app needs both online and offline tokens then we have to
            # perform back-to-back oauth requests.  First we check if we already
            # have an offline token though.  We should always do the offline
            # first because that is when an app is "installed".
            offline_session = self.storage_shim.load_session(
                self.get_offline_session_id(shop_name)
            )
            if (
                not offline_session
                or not self.test_access(offline_session)
                or sorted(self.config.access_scopes)
                != sorted(offline_session.access_scopes)
            ):
                request_access_mode = OFFLINE_ACCESS_MODE
            else:
                request_access_mode = ONLINE_ACCESS_MODE
        elif self.config.need_online_access_token:
            request_access_mode = ONLINE_ACCESS_MODE
        else:
            request_access_mode = OFFLINE_ACCESS_MODE

        return self.redirect_to_authorize(shop_name, request_access_mode)

    def redirect_to_authorize(self, shop_name, request_access_mode):
        """
        Redirect back to shopify to authorize the requested access mode.

        This is split off begin_auth so that we can perform back-to-back
        authorization when we need both offline AND online tokens.
        """

        nonce = self.get_nonce()

        #
        # Create oauth session and stash id to track our grant request until `auth_callback`.
        #
        session = self.create_oauth_session(
            shop_name,
            nonce,
            requested_access_mode=request_access_mode,
            requested_access_scopes=self.config.access_scopes,
        )
        if not self.storage_shim.store_session(session):
            raise AssertionError("Failed to store session.")
        self.set_oauth_cookie(session.id, max_age=MINUTE_IN_SECONDS)

        #
        # Create and redirect to authorize url.
        #
        query = sorted(
            (
                {
                    "client_id": self.config.api_key,
                    # The scopes our app needs, like write_orders, read_orders, etc.
                    "scope": ",".join(self.config.access_scopes),
                    # This tells shopify where to send the callback with our grant code.
                    "redirect_uri": f"{self.web_shim.get_auth_callback_url()}",
                    "state": nonce,
                    # defaults, ie. '', to offline access
                    "grant_options[]": "per-user"
                    if request_access_mode == ONLINE_ACCESS_MODE
                    else "",
                }
            ).items()
        )
        query_string = urlencode(query)
        shop_host = self.build_shop_host(shop_name)
        return self.web_shim.redirect_302_url(
            f"https://{shop_host}/admin/oauth/authorize?{query_string}"
        )

    def validate_hmac(self):
        # This assumes nonce was already checked.

        if not self.check_for_replay(int(self.web_shim.get_param("timestamp", 0))):
            return self.web_shim.response_bad_request(
                "Likely replay attack, bad request"
            )
        elif not self.check_hmac_matches(
            self.calculate_hmac(
                self.config.api_secret, self.web_shim.get_params().items()
            ).encode("utf8"),
            self.web_shim.get_param("hmac").encode("utf8"),
        ):
            return self.web_shim.response_bad_request(
                "HMAC signature does not match, bad request."
            )
        return None

    def auth_callback(self):
        """
        Validate oauth callback, get access token, then redirect to proper url.

        Perform a series of validity checks between the request and the stored session.
        If they pass either create an online session or an offline session.

        If we want both online and offline then we have to run through offline first
        and then come back and do online.
        """
        #
        # Get the oauth session we started in `redirect_to_authorize`.
        #
        session_id = self.web_shim.get_cookie(
            self.config.oauth_cookie_name, signed=True
        )
        if not session_id:
            logger.debug("No oauth session id in cookie, cookie probably expired...")
            return self.redirect_to_auth()
        oauth_session = self.storage_shim.load_session(session_id)
        if not oauth_session:
            logger.debug("The oauth session is not in db, maybe uninstalled...")
            return self.redirect_to_auth()
        elif self.is_session_expired(oauth_session):
            logger.debug("The oauth session expired...")
            return self.redirect_to_auth()

        #
        # Perform validation checks, these should 400 because they are maliscious.
        #
        # @NOTE that the replay check won't happen for regular requests because
        # the oauth cookie would expire first and we redirect for that.
        #
        if oauth_session.nonce != self.web_shim.get_param("state"):
            return self.web_shim.response_bad_request("Nonce does not match.")
        error_response = self.validate_hmac()
        if error_response:
            return error_response

        #
        # Clear oauth cookie because it served its purpose and is now invalid.
        #
        self.set_oauth_cookie("", max_age=ZERO_SECONDS)

        shop_host = self.web_shim.get_param("shop")
        shop_name = self.extract_shop_name(shop_host)

        #
        # Store granted scopes and access token in requested session: online or offline.
        #
        access_token, access_scopes, remaining_params = self.request_access_token(
            shop_host,
            self.web_shim.get_param("code"),
            self.config.api_key,
            self.config.api_secret,
        )
        if oauth_session.requested_access_mode == ONLINE_ACCESS_MODE:
            #
            # Create an online session in our database but don't set a new
            # cookie. We can find the session later using the user id in
            # the JWT token coming back from the app bridge/client.  The JWT
            # is helpfully called the session token.  Also note as far as I
            # can tell the actual skeleton page is not validated and the cookie
            # does not come back when placed in the iframe and neither does the
            # JWT until requests are made.
            #
            online_session = self.create_online_session(
                shop_name, access_token, access_scopes, remaining_params
            )
            if not self.storage_shim.store_session(online_session):
                raise AssertionError("Failed to store session.")

            if not self.config.need_offline_access_token:
                # We haven't called installed hook yet because there was no
                # earlier oauth workflow for offline.
                # @NOTE: If this is a first time install then the user must have
                # all the requested scopes.
                # @NOTE: If the scopes have changed since install then the user
                #  must have all the new scopes to re-install the app otherwise it fails.
                self.on_app_installed(online_session, shop_name, access_scopes)

            if self.config.embedded:
                # Allow our page to load before going into the iframe.
                self.set_home_redirect_cookie("1", max_age=MINUTE_IN_SECONDS)
            else:
                # Always set online as the auth cookie when not in embedded.
                self.set_auth_cookie(
                    online_session.id,
                    max_age=online_session.online_access_info.expires_in,
                )
            return self.web_shim.redirect_302_url(
                self.web_shim.get_home_url(
                    get_params=self.web_shim.get_params(["shop", "host"])
                )
            )
        else:
            offline_session = self.create_offline_session(
                shop_name, access_token, access_scopes
            )
            if not self.storage_shim.store_session(offline_session):
                raise AssertionError("Failed to store session.")

            # Always just mark app as installed here since we do offline first.
            self.on_app_installed(offline_session, shop_name, access_scopes)

            if self.config.need_online_access_token:
                #
                # If we just completed the offline session but still need an online session
                # then we have to restart the authorization for this new grant.
                #
                return self.redirect_to_authorize(shop_name, ONLINE_ACCESS_MODE)
            else:
                if self.config.embedded:
                    # Allow our page to load before going into the iframe.
                    self.set_home_redirect_cookie("1", max_age=MINUTE_IN_SECONDS)
                else:
                    self.set_auth_cookie(offline_session.id, max_age=None)

                return self.web_shim.redirect_302_url(
                    self.web_shim.get_home_url(
                        get_params=self.web_shim.get_params(["shop", "host"])
                    )
                )

    def set_auth_cookie(self, session_id, max_age=None):
        """Set the cookie used for authentication in standalone apps."""
        self.web_shim.set_cookie(
            self.config.auth_cookie_name,
            session_id,
            signed=True,
            max_age=max_age,
            samesite="lax",
            secure=True,
        )

    def set_oauth_cookie(self, session_id, max_age):
        """Set the cookie used for oauth flow."""
        self.web_shim.set_cookie(
            self.config.oauth_cookie_name,
            session_id,
            signed=True,
            max_age=max_age,
            samesite="lax",
            secure=True,
        )

    def set_home_redirect_cookie(self, value, max_age):
        """
        Set the cookie to verify our redirect to embedded skeleton page
        before re-embedding back into the shopify iframe.
        """
        self.web_shim.set_cookie(
            self.config.home_redirect_cookie_name,
            value,
            signed=True,
            max_age=max_age,
            samesite="lax",
            secure=True,
        )

    def on_app_installed(self, auth_session, shop_name, access_scopes):
        install_session = self.create_install_session(shop_name, access_scopes)
        if not self.storage_shim.store_session(install_session):
            raise AssertionError("Failed to store install session")
        if self.app_installed_handler:
            # We pass ourself into the caller, this feels kind of terrible.
            # Maybe a better option would let the callee return a list of
            # hooks to install.  This would be the most flexible but sort of
            # makes everyone call us for no reason.
            # We might even want to create a separate api object that we pass in
            # that lets the callee execute graphql or rest calls but is already
            # closed (closure) around the auth session/shop_name.
            self.app_installed_handler.on_app_installed(self, auth_session, shop_name)

    def redirect_to_auth(self):
        return self.web_shim.redirect_302_url(
            self.web_shim.get_auth_url(
                self.web_shim.get_params(["shop", "timestamp", "hmac", "host"])
            )
        )

    """
    Agnostic utils
    """

    def build_shop_host(self, shop_name, myshopify_domain="myshopify.com"):
        return f"{shop_name}.{myshopify_domain}"

    def extract_shop_name(self, shop_host, myshopify_domain="myshopify.com"):
        suffix = "." + myshopify_domain
        if shop_host.endswith(suffix):
            return shop_host[: -len(suffix)]
        return None

    def get_toplevel_redirect_html_content(
        self, api_key, encoded_shop_host, auth_url, auth_toplevel_url
    ):
        """Special html/js to break out of the iframe for oauth."""
        # Dump config into html as an object by serializing config with json.
        # Use % so we don't have to espace "{" and "}".
        # Use JS case style for client-side object keys.
        config_json_str = json.dumps(
            {
                "apiKey": api_key,
                # This is the 'special' encoded host variable provided by shopify.
                "encodedShopHost": encoded_shop_host,
                "authUrl": auth_url,
                "toplevelAuthUrl": auth_toplevel_url,
            }
        )
        return self.toplevel_redirect_html_content_fmt % (config_json_str,)

    def extract_jwt_token(
        self, auth_header, api_key, api_secret, jwt_leeway_in_seconds
    ):
        """Verify JWT token sent from our app when using "session" tokens."""
        auth_re = re.compile("^Bearer (.+)$")
        result = auth_re.match(auth_header)
        token = result.groups()[0] if result else None
        if not token:
            raise ValueError("Authorization header is malformed.")
        try:
            payload_dict = jwt.decode(
                token,
                api_secret,
                algorithms=["HS256"],
                leeway=jwt_leeway_in_seconds,
                audience=api_key,
            )
        except jwt.InvalidSignatureError:
            raise ValueError("JWT decoding failed.")
        return ShopifyJWTPayload(**payload_dict)

    def check_for_replay(self, callback_timestamp, allow_seconds=DAY_IN_SECONDS):
        return callback_timestamp >= time.time() - allow_seconds

    def check_hmac_matches(self, our_hmac, hmac_to_check):
        if not hmac_to_check:
            return False
        return hmac.compare_digest(our_hmac, hmac_to_check)

    def calculate_hmac(self, api_secret, param_items):
        encoded_params = self.encode_params_for_hmac(param_items)
        # Generate the hex digest for the sorted parameters using the secret.
        return hmac.new(
            api_secret.encode("utf8"), encoded_params.encode("utf8"), hashlib.sha256
        ).hexdigest()

    def encode_params_for_hmac(self, param_items):
        """
        Encode params with special shopify rules.

        RULE #1: ("k[]", [1,2]) is converted to ("k", '["1", "2"]')
        RULE #2: safe chars are ":/" for whatever reason.
        """
        params_to_encode = []
        for (k, v) in sorted(param_items):
            if k == "hmac":
                continue
            elif k.endswith("[]"):
                k = k[:-2]
                v = ", ".join(['"{}"'.format(v_item) for v_item in v])
            params_to_encode.append((k, v))

        return urlencode(params_to_encode, safe=":/")

    def request_access_token(self, shop_host, grant_code, api_key, api_secret):
        """
        Use grant code from shopify to fetch the access token using a post request.

        This access token can be used to perform operations using the shopify api.
        """
        response = requests.post(
            f"https://{shop_host}/admin/oauth/access_token",
            data={
                "client_id": api_key,
                "client_secret": api_secret,
                "code": grant_code,
            },
        )
        if response.status_code == requests.codes.ok:
            json_payload = response.json()
            remaining_params = {
                k: v
                for k, v in json_payload.items()
                if k not in ("access_token", "scope")
            }
            # Convert access scopes into a list.
            access_scopes = [
                scope.strip()
                for scope in json_payload["scope"].split(",")
                if scope.strip()
            ]
            return (
                json_payload["access_token"],
                access_scopes,
                remaining_params,
            )
        else:
            response.raise_for_status()

    def execute_graphql(
        self,
        shop_name,
        api_version,
        access_token,
        query,
        variables=None,
        operation_name=None,
        myshopify_domain="myshopify.com",
    ):
        """
        Simple graphql running, this won't work for much actual usage
        because you need constant throttling and the rules for that are beyond
        the scope of this dimension.

        shop_name:
            The name of the shop without the myshopify.com stuff.
        api_version:
            The version of the api to send the GQL to.
        access_token:
            Token we got from oauth, either online or offline.
        query:
            The query to execute.
        variables:
            Any variables that the query needs to be interpolated.
        operation_name:
            The operation within the query to actually execute. If nothing
            is given then the entire query is just executed as is.

        return:
            Returns the response body converted from json.

        raise:
            If the response is not ok then an exception is raised via requests.
        """
        url = "https://{}.{}/admin/api/{}/graphql.json".format(
            shop_name, myshopify_domain, self.config.api_version
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": access_token,
        }
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == requests.codes.ok:
            response_body = response.json()
            return response_body
        else:
            response.raise_for_status()

    def get_nonce(self, charset=string.ascii_lowercase + string.digits, length=15):
        """Get a random system of `length` characters from given `charset`."""
        return "".join(random.SystemRandom().choice(charset) for _ in range(length))
