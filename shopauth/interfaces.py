from zope.interface import Interface


class IWebShim(Interface):
    pass


class IStorageShim(Interface):
    pass


class ISessionSerializer(Interface):
    pass


class IAppInstalledHandler(Interface):
    pass


class IWebhookAPI(Interface):
    pass


class IWebhookEndpoint(Interface):
    pass


class IWebhookHandlerRegistry(Interface):
    pass
