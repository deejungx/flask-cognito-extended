import datetime
from hashlib import md5
from six import raise_from
from flask import current_app
try:
    from collections.abc import Sequence, Set
except ImportError:  # pragma: no cover
    from collections import Sequence, Set


class _Config(object):
    """
    Helper object for accessing and verifying options in this extension. This
    is meant for internal use of the application.

    Default values for the configuration options are set in the cognito_manager
    object. All of these values are read only. This is simply a loose wrapper
    with some helper functionality for flasks `app.config`.
    """

    @property
    def scope(self):
        scope = current_app.config['COGNITO_SCOPE']
        if not scope:
            raise RuntimeError('COGNITO_SCOPE must be specified to '
                               'create the auth url. ')
        return scope

    @property
    def state(self):
        try:
            state = current_app.config['COGNITO_STATE']
        except KeyError:
            return None
        return state

    @property
    def issuer(self):
        return "https://cognito-idp.{region}.amazonaws.com/{userPoolId}".format(
                            region=self.region, userPoolId=self.user_pool_id)

    @property
    def region(self):
        region = current_app.config['COGNITO_REGION']
        if not region:
            raise RuntimeError('COGNITO_REGION must be specified.')
        return region

    @property
    def public_key_uri(self):
        return ("https://cognito-idp.{region}.amazonaws.com"
                "/{userpoolid}/.well-known/jwks.json").format(
                region=self.region, userpoolid=self.user_pool_id)

    @property
    def login_uri(self):
        if self.state is not None:
            return ("{domain}/login?client_id={client_id}"
                    "&response_type=code&scope={scope}"
                    "&redirect_uri={redirect_uri}&state={state}").format(
                    domain=self.domain, client_id=self.client_id,
                    scope=self.scope, redirect_uri=self.redirect_uri,
                    state=self.state)
        return ("{domain}/login?client_id={client_id}"
                "&response_type=code&scope={scope}"
                "&redirect_uri={redirect_uri}").format(
                domain=self.domain, client_id=self.client_id,
                scope=self.scope, redirect_uri=self.redirect_uri)
    
    @property
    def logout_uri(self):
        return ("{domain}/logout?client_id={client_id}"
                "&logout_uri={signout_uri}".format(
                    domain=self.domain, client_id=self.client_id,
                    signout_uri=self.signout_uri
                ))

    @property
    def user_pool_id(self):
        pool_id = current_app.config['COGNITO_USER_POOL_ID']
        if not pool_id:
            raise RuntimeError('COGNITO_USER_POOL_ID must be specified to '
                               'locate the auth url. ')
        return pool_id

    @property
    def client_id(self):
        client_id = current_app.config['COGNITO_CLIENT_ID']
        if not client_id:
            raise RuntimeError('COGNITO_CLIENT_ID must be set to '
                               'validate the audience claim. ')
        return client_id

    @property
    def client_secret(self):
        try:
            client_secret = current_app.config['COGNITO_CLIENT_SECRET']
        except KeyError:
            return None
        return client_secret

    @property
    def domain(self):
        domain = current_app.config['COGNITO_DOMAIN']
        if not domain:
            raise RuntimeError('COGNITO_DOMAIN must be set to '
                               'redirect to create endpoint url. ')
        if not domain.startswith("https://"):
            domain = "https://{}".format(domain)
        return domain

    @property
    def redirect_uri(self):
        uri = current_app.config['COGNITO_REDIRECT_URI']
        if not uri:
            raise RuntimeError('COGNITO_REDIRECT_URI must be set to '
                               'obtain callback url. ')
        return uri
    
    @property
    def signout_uri(self):
        uri = current_app.config['COGNITO_SIGNOUT_URI']
        if not uri:
            raise RuntimeError('COGNITO_RSIGNOUT_URI must be set for '
                               'logout callback.')
        return uri

    @property
    def exempt_methods(self):
        methods = current_app.config['EXEMPT_METHODS']
        return methods if methods else {"OPTIONS"}

    @property
    def identity_claim_key(self):
        key = current_app.config['JWT_IDENTITY_CLAIM']
        return key if key else 'sub'

    @property
    def token_location(self):
        locations = current_app.config['JWT_TOKEN_LOCATION']
        if isinstance(locations, str):
            locations = (locations,)
        elif not isinstance(locations, (Sequence, Set)):
            raise RuntimeError('JWT_TOKEN_LOCATION must be a'
                               ' sequence or a set')
        elif not locations:
            raise RuntimeError('JWT_TOKEN_LOCATION must contain at least one '
                               'of "headers", "cookies", "query_string" or "json"')
        for location in locations:
            if location not in ('headers', 'cookies', 'json', 'query_string'):
                raise RuntimeError('JWT_TOKEN_LOCATION can only contain '
                                   '"headers", "cookies", "query_string" or "json"')
        return locations

    @property
    def jwt_in_cookies(self):
        return 'cookies' in self.token_location

    @property
    def jwt_in_headers(self):
        return 'headers' in self.token_location

    @property
    def jwt_in_query_string(self):
        return 'query_string' in self.token_location

    @property
    def jwt_in_json(self):
        return 'json' in self.token_location

    @property
    def error_msg_key(self):
        return current_app.config['JWT_ERROR_MESSAGE_KEY']

    @property
    def header_name(self):
        name = current_app.config['JWT_HEADER_NAME']
        if not name:
            raise RuntimeError("JWT_ACCESS_HEADER_NAME cannot be empty")
        return name

    @property
    def header_type(self):
        return current_app.config['JWT_HEADER_TYPE']

    @property
    def query_string_name(self):
        return current_app.config['JWT_QUERY_STRING_NAME']

    @property
    def access_cookie_name(self):
        return current_app.config['JWT_ACCESS_COOKIE_NAME']

    @property
    def refresh_cookie_name(self):
        return current_app.config['JWT_REFRESH_COOKIE_NAME']

    @property
    def access_cookie_path(self):
        return current_app.config['JWT_ACCESS_COOKIE_PATH']

    @property
    def refresh_cookie_path(self):
        return current_app.config['JWT_REFRESH_COOKIE_PATH']

    @property
    def cookie_secure(self):
        return current_app.config['JWT_COOKIE_SECURE']

    @property
    def cookie_domain(self):
        return current_app.config['JWT_COOKIE_DOMAIN']

    @property
    def session_cookie(self):
        return current_app.config['JWT_SESSION_COOKIE']

    @property
    def cookie_samesite(self):
        return current_app.config['JWT_COOKIE_SAMESITE']

    @property
    def json_key(self):
        return current_app.config['JWT_JSON_KEY']

    @property
    def refresh_json_key(self):
        return current_app.config['JWT_REFRESH_JSON_KEY']

    @property
    def csrf_protect(self):
        return self.jwt_in_cookies and current_app.config['JWT_COOKIE_CSRF_PROTECT']

    @property
    def csrf_request_methods(self):
        return current_app.config['JWT_CSRF_METHODS']

    @property
    def csrf_in_cookies(self):
        return current_app.config['JWT_CSRF_IN_COOKIES']

    @property
    def access_csrf_cookie_name(self):
        return current_app.config['JWT_ACCESS_CSRF_COOKIE_NAME']

    @property
    def refresh_csrf_cookie_name(self):
        return current_app.config['JWT_REFRESH_CSRF_COOKIE_NAME']

    @property
    def access_csrf_header_name(self):
        return current_app.config['JWT_ACCESS_CSRF_HEADER_NAME']

    @property
    def access_csrf_cookie_path(self):
        return current_app.config['JWT_ACCESS_CSRF_COOKIE_PATH']

    @property
    def refresh_csrf_cookie_path(self):
        return current_app.config['JWT_REFRESH_CSRF_COOKIE_PATH']

    @property
    def refresh_csrf_header_name(self):
        return current_app.config['JWT_REFRESH_CSRF_HEADER_NAME']

    @property
    def access_csrf_field_name(self):
        return current_app.config['JWT_ACCESS_CSRF_FIELD_NAME']

    @property
    def refresh_csrf_field_name(self):
        return current_app.config['JWT_REFRESH_CSRF_FIELD_NAME']

    @property
    def csrf_check_form(self):
        return current_app.config['JWT_CSRF_CHECK_FORM']

    @property
    def access_expires(self):
        delta = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        if type(delta) is int:
            delta = datetime.timedelta(seconds=delta)
        if delta is not False:
            try:
                delta + datetime.datetime.now()
            except TypeError as e:
                err = (
                    "must be able to add JWT_ACCESS_TOKEN_EXPIRES to datetime.datetime"
                )
                raise_from(RuntimeError(err), e)
        return delta

    @property
    def refresh_expires(self):
        delta = current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        if type(delta) is int:
            delta = datetime.timedelta(seconds=delta)
        if delta is not False:
            try:
                delta + datetime.datetime.now()
            except TypeError as e:
                err = (
                    "must be able to add JWT_REFRESH_TOKEN_EXPIRES to datetime.datetime"
                )
                raise_from(RuntimeError(err), e)
        return delta

    @property
    def blacklist_enabled(self):
        return current_app.config['JWT_BLACKLIST_ENABLED']

    @property
    def blacklist_checks(self):
        check_type = current_app.config['JWT_BLACKLIST_TOKEN_CHECKS']
        if isinstance(check_type, str):
            check_type = (check_type,)
        elif not isinstance(check_type, (Sequence, Set)):
            raise RuntimeError('JWT_BLACKLIST_TOKEN_CHECKS must be a sequence or a set')
        for item in check_type:
            if item not in ('access', 'refresh'):
                err = 'JWT_BLACKLIST_TOKEN_CHECKS must be "access" or "refresh"'
                raise RuntimeError(err)
        return check_type

    @property
    def blacklist_access_tokens(self):
        return 'access' in self.blacklist_checks

    @property
    def blacklist_refresh_tokens(self):
        return 'refresh' in self.blacklist_checks

    @property
    def cookie_max_age(self):
        # Returns the appropiate value for max_age for flask set_cookies. If
        # session cookie is true, return None, otherwise return a number of
        # seconds 1 year in the future
        return None if self.session_cookie else 31540000  # 1 year

    @property
    def audience(self):
        return self.client_id


cognito_config = _Config()
