from dataclasses import dataclass

from pyramid.request import Request
from pyramid.httpexceptions import HTTPFound, HTTPBadRequest, HTTPForbidden, HTTPUnauthorized
import zope.interface

from ..interfaces import IWebShim


@dataclass
class PyramidWebShimConfig:
    auth_route: str
    auth_callback_route: str
    auth_toplevel_route: str
    home_route: str
    # This is used to sign cookies.
    cookie_secret: str


@zope.interface.implementer(IWebShim)
@dataclass
class PyramidWebShim:
    """Shim between shopify api and pyramid for web tasks."""

    # Used to sign json serializations, interface of webob.cookies.SignedSerializer.
    signed_serializer: object
    # Configuration params that describe how we should behave.
    config: PyramidWebShimConfig
    # The current request.
    request: Request

    def set_cookie(
        self,
        name,
        value,
        signed=True,
        httponly=None,
        samesite=None,
        secure=True,
        max_age=None,
        secure_salt=None,
    ):
        if signed:
            value = self.signed_serializer(
                self.config.cookie_secret, secure_salt
            ).dumps(value)
        self.request.response.set_cookie(
            name,
            value,
            httponly=httponly,
            samesite=samesite,
            secure=secure,
            max_age=max_age,
        )

    def get_cookie(self, name, signed=True, default=None, secure_salt=None):
        if name not in self.request.cookies:
            return default
        else:
            value = self.request.cookies[name]
            return (
                self.signed_serializer(self.config.cookie_secret, secure_salt).loads(
                    value
                )
                if signed
                else value
            )

    def _route_url(self, route_name, get_params, path_only=False, **kwargs):
        if get_params:
            # @TODO If _query is a string this is going to fail.
            kwargs.setdefault("_query", {}).update(get_params)
        if path_only:
            return self.request.route_path(route_name, **kwargs)
        else:
            return self.request.route_url(route_name, **kwargs)

    def get_home_url(self, get_params=None, path_only=False):
        return self._route_url(self.config.home_route, get_params, path_only=path_only)

    def get_auth_url(self, get_params=None, path_only=False):
        # Use shop as GET param because that is what shopify passes.
        return self._route_url(self.config.auth_route, get_params, path_only=path_only)

    def get_auth_callback_url(self, get_params=None):
        return self._route_url(self.config.auth_callback_route, get_params)

    def get_auth_toplevel_url(self, get_params=None):
        return self._route_url(self.config.auth_toplevel_route, get_params)

    def response_401(self, headers=None, **kwargs):
        if headers:
            kwargs['headers'] = headers
        return HTTPUnauthorized(**kwargs)

    def response_403(self, headers=None, **kwargs):
        if headers:
            kwargs['headers'] = headers
        return HTTPForbidden(**kwargs)

    def redirect_302_url(self, url, with_headers=True):
        """Raise or return a redirect."""
        kwargs = {}
        if with_headers:
            kwargs["headers"] = self.request.response.headers
        return HTTPFound(url, **kwargs)

    def get_header(self, name, default=None):
        return self.request.headers.get(name, default)

    def set_header(self, name, value):
        self.request.response.headers[name] = value

    def get_param(self, name, default=None):
        # @TODO: We might need to allow for getall.
        return self.request.GET.get(name, default)

    def get_params(self, param_names=None, default=None):
        if param_names:
            params = {name: self.request.GET.get(name, default) for name in param_names}
        else:
            params = self.request.GET.copy()
        return params

    def response_200_string(self, content, content_type="text/html"):
        response = self.request.response
        response.content_type = content_type
        response.text = content
        return response

    def response_bad_request(self, message):
        return HTTPBadRequest(message)

    def get_request_body(self):
        return self.request.body

    def get_request_json_body(self):
        return self.request.json_body
