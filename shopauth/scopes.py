UNAUTHENTICATED_WRITE_PREFIX = "unauthenticated_write_"


UNAUTHENTICATED_READ_PREFIX = "unauthenticated_read_"


WRITE_PREFIX = "write_"


READ_PREFIX = "read_"


def get_implied_scopes(scopes):
    implied_scopes = set()
    for scope in scopes:
        if scope.startswith(UNAUTHENTICATED_WRITE_PREFIX):
            implied_scopes.add(
                UNAUTHENTICATED_READ_PREFIX
                + scope.removeprefix(UNAUTHENTICATED_WRITE_PREFIX)
            )
        elif scope.startswith(WRITE_PREFIX):
            implied_scopes.add(READ_PREFIX + scope.removeprefix(WRITE_PREFIX))
    return implied_scopes


def scopes_have_changed(installed_scopes, expected_scopes):
    # @NOTE: The app does not need to re-install if the expected scopes are
    # still a subset of the initial installed scopes.
    return (
        not set(expected_scopes)
        .union(get_implied_scopes(expected_scopes))
        .issubset(set(installed_scopes).union(get_implied_scopes(installed_scopes)))
    )
