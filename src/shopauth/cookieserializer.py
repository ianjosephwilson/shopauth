from webob.cookies import SignedSerializer


def get_default_signed_serializer(secret, salt, hashalg="sha512", serializer=None):
    return SignedSerializer(secret, salt, hashalg, serializer=serializer)
