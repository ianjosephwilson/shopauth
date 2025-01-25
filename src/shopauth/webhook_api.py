import logging
from dataclasses import dataclass, field, fields
import json

import requests


logger = logging.getLogger(__name__)


@dataclass
class Webhook:
    address: str
    api_version: str
    created_at: str
    fields: list
    format: str
    id: int
    metafield_namespaces: list
    private_metafield_namespaces: list
    topic: str
    updated_at: str
    # Whatever we couldn't match.
    cruft: dict = field(default_factory=dict)


class WebhookAPIService:
    """Helps with interacting with shopify's webhook api."""

    api_url: str = (
        "https://{shop_name}.{myshopify_domain}/admin/api/{api_version}/webhooks.json"
    )

    json_api: object = json

    GET_LIMIT_MAX: int = 250

    myshopify_domain = "myshopify.com"

    def get_api_url(self, api_version, shop_name):
        return self.api_url.format(
            api_version=api_version,
            myshopify_domain=self.myshopify_domain,
            shop_name=shop_name,
        )

    def create_webhook(
        self,
        api_version,
        shop_name,
        access_token,
        topic,
        address,
        fields=None,
    ):
        payload = {
            "webhook": {
                "topic": topic,
                "address": address,
                # Always send json.
                "format": "json",
            }
        }
        if fields:
            payload["fields"] = fields
        res = requests.post(
            self.get_api_url(api_version, shop_name),
            headers={
                "X-Shopify-Access-Token": access_token,
                "Content-Type": "application/json",
            },
            data=self.json_api.dumps(payload),
        )
        if res.status_code == 200:
            webhook = self._coerce_into_webhook(res.json())
            if webhook.cruft:
                # We save the cruft but don't crash if it exists.
                logger.warn(f"Unrecognized keys in webhook response: {','.join(webhook.cruft.keys())}")
            return webhook
        else:
            res.raise_for_status()

    def check_limit(self, api_version, limit, raise_on_error=True):
        if limit > self.GET_LIMIT_MAX:
            if raise_on_error:
                raise AssertionError(
                    f"The limit {limit} must be less than {self.GET_LIMIT_MAX}"
                )
            return False
        return True

    def get_webhooks(
        self,
        api_version,
        shop_name,
        access_token,
        created_at_max=None,
        created_at_min=None,
        fields=None,
        limit=50,
        since_id=None,
        topic=None,
        updated_at_max=None,
        updated_at_min=None,
        check_limit=True,
    ):
        if check_limit:
            self.check_limit(api_version, limit)
        params = {
            "limit": limit,
        }
        if created_at_max:
            params["created_at_max"] = created_at_max
        if created_at_min:
            params["created_at_min"] = created_at_min
        if fields:
            params["fields"] = fields
        if since_id:
            params["since_id"] = since_id
        if topic:
            params["topic"] = topic
        if updated_at_max:
            params["updated_at_max"] = updated_at_max
        if updated_at_min:
            params["updated_at_min"] = updated_at_min
        res = requests.get(
            self.get_api_url(api_version, shop_name),
            headers={"X-Shopify-Access-Token": access_token},
            params=params,
        )
        if res.status_code == 200:
            d = res.json()
            webhooks = []
            for webhook_dict in d["webhooks"]:
                webhook = self._coerce_into_webhook(webhook_dict)
                if webhook.cruft:
                    # We save the cruft but don't crash if it exists.
                    logger.warn(f"Unrecognized keys in webhook response: {','.join(webhook.cruft.keys())}")
                webhooks.append(webhook)
            return {
                "webhooks": webhooks,
            }
        else:
            res.raise_on_status()

    def _coerce_into_webhook(self, webhook_dict):
        kwargs = {}
        field_by_name = {f.name: f for f in fields(Webhook)}
        cruft = kwargs['cruft'] = {}
        for k in webhook_dict:
            if k in field_by_name:
                kwargs[k] = webhook_dict[k]
            else:
                cruft[k] = webhook_dict[k]
        return Webhook(**kwargs)
