def build_shop_host(shop_name, myshopify_domain="myshopify.com"):
    return f"{shop_name}.{myshopify_domain}"


def extract_shop_name(shop_host, myshopify_domain="myshopify.com"):
    suffix = "." + myshopify_domain
    if shop_host.endswith(suffix):
        return shop_host[: -len(suffix)]
    return None
