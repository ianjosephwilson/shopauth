import logging
import hmac
import hashlib
import base64
from dataclasses import dataclass, field
from typing import Callable

from .util import extract_shop_name
from .interfaces import IWebShim, IWebhookHandlerRegistry


logger = logging.getLogger(__name__)


@dataclass
class HandlerRegistration:
    handler: Callable
    topic: str = None
    # higher gets called first
    priority: int = 0


@dataclass
class HandlerRegistry:
    registrations: list = field(default_factory=list)

    def add(self, webhook_handler, topic=None, priority=0):
        self.registrations.append(HandlerRegistration(webhook_handler, topic, priority))

    def matches(self, topic):
        """
        Get registered handlers that match the given topic, high priority first.
        """
        regs = filter(
            lambda reg: reg.topic == topic or not reg.topic, self.registrations
        )
        return sorted(regs, key=lambda reg: reg.priority, reverse=True)


@dataclass
class WebhookEndpointService:
    """
    Help with receiving webhooks from shopify.

    @NOTE: This doesn't handle processing webhooks in the correct order.
        ie. ProductUpdate before ProductCreate for the same product.
    @NOTE: This doesn't handle processing webhooks that are sent more than once.
        ie. ProductCreate x 2 for the same product.
    """

    web_shim: IWebShim

    registry: IWebhookHandlerRegistry

    # Allow state to be made and passed to chain of handlers called for a
    # webhook.
    handler_state_maker: Callable = field(default=dict)

    logger: object = field(default=logger)

    def compute_hmac(self, secret, data):
        digest = hmac.new(
            secret.encode("utf-8"), data, digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(digest)

    def validate_hmac(self, hmac_to_verify, secret, data):
        computed_hmac = self.compute_hmac(secret, data)
        return hmac.compare_digest(computed_hmac, hmac_to_verify)

    def process_webhook(self, api_secret_key):
        hmac_to_verify = self.web_shim.get_header("X-Shopify-Hmac-SHA256").encode(
            "utf-8"
        )
        # I guess we don't include these in the hmac.  Seems kind of odd.
        shop_host = self.web_shim.get_header("X-Shopify-Shop-Domain")
        topic = self.web_shim.get_header("X-Shopify-Topic")

        if not shop_host or not topic or not hmac_to_verify:
            return self.web_shim.response_bad_request()
        verified = self.validate_hmac(
            hmac_to_verify, api_secret_key, self.web_shim.get_request_body()
        )
        if not verified:
            return self.web_shim.response_401()

        shop_name = extract_shop_name(shop_host)
        regs = self.registry.matches(topic)
        if not regs:
            self.logger.warn(f"No handler registrations matched topic: {topic}")
        # The contents here is undocumented AFAIK, it just will look kind of like what
        # you send to shopify when registering the hook with them.
        params = self.web_shim.get_request_json_body()
        state = self.handler_state_maker()
        for reg in regs:
            reg.handler(shop_name, shop_host, topic, params, state)
        return self.web_shim.response_200_string("")
