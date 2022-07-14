from dataclasses import dataclass
import json

import requests


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
            return Webhook(**res.json())
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
            return {
                "webhooks": [Webhook(**webhook_dict) for webhook_dict in d["webhooks"]]
            }
        else:
            res.raise_on_status()
