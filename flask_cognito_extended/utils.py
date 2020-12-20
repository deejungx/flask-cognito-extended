from werkzeug.local import LocalProxy
from jose import jwt
import json
import requests
from datetime import datetime, timedelta
import email.utils as eut
from flask import current_app, redirect
from flask_cognito_extended.tokens import decode_jwt
from flask_cognito_extended.config import cognito_config
from flask_cognito_extended.exceptions import (
    WrongTokenError, RevokedTokenError, AuthorizationExchangeError,
    UserInfoError)
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

# Proxy to access the current user
current_user = LocalProxy(lambda: get_current_user())


def get_user_info(access_token):
    """
    Calls the userInfo endpoint on Cognito.
    Returns a dictionary containing user info.

    :param access_token: encoded access token
    :return: Dictionary containing user info
    """
    user_url = "{}/oauth2/userInfo".format(cognito_config.domain)
    headers = {"Authorization": "Bearer {}".format(access_token)}
    try:
        response = requests.post(user_url, headers=headers)
        response_json = response.json()
    except requests.exceptions.RequestException as e:
        raise UserInfoError(str(e)) from e
    return response_json


def exchange_code_for_token(code):
    """
    Exchanges authorization code for tokens using the Cogntio TOKEN endpoint.
    This includes the encoded id, access and refresh tokens.

    :param code: The authorization code obtained from user login/sign-up
                 confimation.
    :return: Dictionary containing encoded access_token, refresh_token
             and id_token
    """
    url = '{domain}/oauth2/token'.format(domain=cognito_config.domain)
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    data = {'grant_type': 'authorization_code',
            'client_id': cognito_config.client_id,
            'redirect_uri': cognito_config.redirect_uri,
            'code': code
            }
    try:
        response = requests.post(url=url, headers=headers, data=data)
        tokens = json.loads(response.text)
    except requests.exceptions.HTTPError as e:
        raise AuthorizationExchangeError(str(e)) from e
    # check token expiry
    published_time = datetime(*eut.parsedate(response.headers['Date'])[:6])
    expiry = tokens.pop('expires_in')
    expiry_time = published_time + timedelta(int(expiry))
    if datetime.now() > expiry_time:
        raise AuthorizationExchangeError("Request is expired")
    # check token type bearer
    token_type = tokens.pop('token_type')
    if token_type != 'Bearer':
        raise AuthorizationExchangeError("Invalid token type")
    return tokens


def get_encoded_access_token():
    """
    The encoded access token obtained from exchanging the code
    is accessed from this endpoint. If no token string is found,
    an empty string is returned instead.
    """
    return getattr(ctx_stack.top, 'encoded_access_token', "")


def get_encoded_refresh_token():
    """
    The encoded refresh token obtained from exchanging the code
    is accessed from this endpoint. If no token string is found,
    an empty string is returned instead.
    """
    return getattr(ctx_stack.top, 'encoded_refresh_token', "")


def get_encoded_id_token():
    """
    The encoded id token obtained from exchanging the code
    is accessed from this endpoint. If no token string is found,
    an empty string is returned instead.
    """
    return getattr(ctx_stack.top, 'encoded_id_token', "")


def get_raw_jwt():
    """
    In a protected endpoint, this will return the python dictionary which has
    all of the claims of the JWT that is accessing the endpoint. If no
    JWT is currently present, an empty dict is returned instead.
    """
    return getattr(ctx_stack.top, 'jwt', {})


def get_raw_jwt_header():
    """
    In a protected endpoint, this will return the python dictionary which has
    the JWT headers values. If no
    JWT is currently present, an empty dict is returned instead.
    """
    return getattr(ctx_stack.top, 'jwt_header', {})


def get_jwt_identity():
    """
    In a protected endpoint, this will return the identity of the JWT that is
    accessing this endpoint. If no JWT is present,`None` is returned instead.
    """
    return get_raw_jwt().get(cognito_config.identity_claim_key, None)


def get_current_user():
    """
    In a protected endpoint, this will return the user object for the JWT that
    is accessing this endpoint. This is only present if the
    :meth:`~flask_jwt_extended.CognitoManager.user_loader_callback_loader` is
    being used. If the user loader callback is not being used, this will
    return `None`.
    """
    return getattr(ctx_stack.top, 'jwt_user', None)


def get_jti(encoded_token):
    """
    Returns the JTI (unique identifier) of an encoded JWT

    :param encoded_token: The encoded JWT to get the JTI from.
    """
    return decode_token(encoded_token).get('jti')


def get_logout_uri():
    """
    Returns the logout uri string that can be used to redirect the
    user to logout.

    return: String containing logout uri
    """
    return cognito_config.logout_uri


def decode_token(encoded_token, csrf_value=None, allow_expired=False):
    """
    Returns the decoded token (python dict) from an encoded JWT. This does all
    the checks to insure that the decoded token is valid before returning it.

    :param encoded_token: The encoded JWT to decode into a python dict.
    :param csrf_value: Expected CSRF double submit value (optional)
    :param allow_expired: Options to ignore exp claim validation in token
    :return: Dictionary containing contents of the JWT
    """
    cognito_manager = _get_cognito_manager()
    secret = cognito_manager._decode_key_callback(cognito_config.public_key_uri)['keys']

    return decode_jwt(
        encoded_token=encoded_token,
        secret=secret,
        identity_claim_key=cognito_config.identity_claim_key,
        csrf_value=csrf_value,
        audience=cognito_config.audience,
        issuer=cognito_config.issuer,
        allow_expired=allow_expired
    )


def _get_cognito_manager():
    try:
        return current_app.extensions['flask-cognito-extended']
    except KeyError:  # pragma: no cover
        raise RuntimeError("You must initialize a CognitoManager with this flask "
                           "application before using this method")


def has_user_loader():
    cognito_manager = _get_cognito_manager()
    return cognito_manager._user_loader_callback is not None


def has_authorization_state():
    return cognito_config.state is not None


def user_loader(*args, **kwargs):
    cognito_manager = _get_cognito_manager()
    return cognito_manager._user_loader_callback(*args, **kwargs)


def has_token_in_blacklist_callback():
    cognito_manager = _get_cognito_manager()
    return cognito_manager._token_in_blacklist_callback is not None


def token_in_blacklist(*args, **kwargs):
    cognito_manager = _get_cognito_manager()
    return cognito_manager._token_in_blacklist_callback(*args, **kwargs)


def verify_token_type(decoded_token, expected_type):
    if decoded_token['token_use'] != expected_type:
        raise WrongTokenError('Only {} tokens are allowed'.format(expected_type))


def verify_token_not_blacklisted(decoded_token, request_type):
    if not cognito_config.blacklist_enabled:
        return
    if not has_token_in_blacklist_callback():
        raise RuntimeError("A token_in_blacklist_callback must be provided via "
                           "the '@token_in_blacklist_loader' if "
                           "JWT_BLACKLIST_ENABLED is True")
    if cognito_config.blacklist_access_tokens and request_type == 'access':
        if token_in_blacklist(decoded_token):
            raise RevokedTokenError('Token has been revoked')
    if cognito_config.blacklist_refresh_tokens and request_type == 'refresh':
        if token_in_blacklist(decoded_token):
            raise RevokedTokenError('Token has been revoked')


def get_csrf_token(encoded_token):
    """
    Returns the CSRF double submit token from an encoded JWT.

    :param encoded_token: The encoded JWT
    :return: The CSRF double submit token
    """
    token = decode_token(encoded_token)
    return token['csrf']


def set_access_cookies(response, encoded_access_token, max_age=None):
    """
    Takes a flask response object, and an encoded access token, and configures
    the response to set in the access token in a cookie. If `JWT_CSRF_IN_COOKIES`
    is `True` (see :ref:`Configuration Options`), this will also set the CSRF
    double submit values in a separate cookie.

    :param response: The Flask response object to set the access cookies in.
    :param encoded_access_token: The encoded access token to set in the cookies.
    :param max_age: The max age of the cookie. If this is None, it will use the
                    `JWT_SESSION_COOKIE` option (see :ref:`Configuration Options`).
                    Otherwise, it will use this as the cookies `max-age` and the
                    JWT_SESSION_COOKIE option will be ignored.  Values should be
                    the number of seconds (as an integer).
    """
    if not cognito_config.jwt_in_cookies:
        raise RuntimeWarning("set_access_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    # Set the access JWT in the cookie
    response.set_cookie(cognito_config.access_cookie_name,
                        value=encoded_access_token,
                        max_age=max_age or cognito_config.cookie_max_age,
                        secure=cognito_config.cookie_secure,
                        httponly=True,
                        domain=cognito_config.cookie_domain,
                        path=cognito_config.access_cookie_path,
                        samesite=cognito_config.cookie_samesite)

    # If enabled, set the csrf double submit access cookie
    if cognito_config.csrf_protect and cognito_config.csrf_in_cookies:
        response.set_cookie(cognito_config.access_csrf_cookie_name,
                            value=get_csrf_token(encoded_access_token),
                            max_age=max_age or cognito_config.cookie_max_age,
                            secure=cognito_config.cookie_secure,
                            httponly=False,
                            domain=cognito_config.cookie_domain,
                            path=cognito_config.access_csrf_cookie_path,
                            samesite=cognito_config.cookie_samesite)


def set_refresh_cookies(response, encoded_refresh_token, max_age=None):
    """
    Takes a flask response object, and an encoded refresh token, and configures
    the response to set in the refresh token in a cookie. If `JWT_CSRF_IN_COOKIES`
    is `True` (see :ref:`Configuration Options`), this will also set the CSRF
    double submit values in a separate cookie.

    :param response: The Flask response object to set the refresh cookies in.
    :param encoded_refresh_token: The encoded refresh token to set in the cookies.
    :param max_age: The max age of the cookie. If this is None, it will use the
                    `JWT_SESSION_COOKIE` option (see :ref:`Configuration Options`).
                    Otherwise, it will use this as the cookies `max-age` and the
                    JWT_SESSION_COOKIE option will be ignored.  Values should be
                    the number of seconds (as an integer).
    """
    if not cognito_config.jwt_in_cookies:
        raise RuntimeWarning("set_refresh_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    # Set the refresh JWT in the cookie
    response.set_cookie(cognito_config.refresh_cookie_name,
                        value=encoded_refresh_token,
                        max_age=max_age or cognito_config.cookie_max_age,
                        secure=cognito_config.cookie_secure,
                        httponly=True,
                        domain=cognito_config.cookie_domain,
                        path=cognito_config.refresh_cookie_path,
                        samesite=cognito_config.cookie_samesite)

    # If enabled, set the csrf double submit refresh cookie
    if cognito_config.csrf_protect and cognito_config.csrf_in_cookies:
        response.set_cookie(cognito_config.refresh_csrf_cookie_name,
                            value=get_csrf_token(encoded_refresh_token),
                            max_age=max_age or cognito_config.cookie_max_age,
                            secure=cognito_config.cookie_secure,
                            httponly=False,
                            domain=cognito_config.cookie_domain,
                            path=cognito_config.refresh_csrf_cookie_path,
                            samesite=cognito_config.cookie_samesite)


def unset_jwt_cookies(response):
    """
    Takes a flask response object, and configures it to unset (delete) JWTs
    stored in cookies.

    :param response: The Flask response object to delete the JWT cookies in.
    """
    unset_access_cookies(response)
    unset_refresh_cookies(response)


def unset_access_cookies(response):
    """
    takes a flask response object, and configures it to unset (delete) the
    access token from the response cookies. if `jwt_csrf_in_cookies`
    (see :ref:`configuration options`) is `true`, this will also remove the
    access csrf double submit value from the response cookies as well.

    :param response: the flask response object to delete the jwt cookies in.
    """
    if not cognito_config.jwt_in_cookies:
        raise RuntimeWarning("unset_access_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    response.set_cookie(cognito_config.access_cookie_name,
                        value='',
                        expires=0,
                        secure=cognito_config.cookie_secure,
                        httponly=True,
                        domain=cognito_config.cookie_domain,
                        path=cognito_config.access_cookie_path,
                        samesite=cognito_config.cookie_samesite)

    if cognito_config.csrf_protect and cognito_config.csrf_in_cookies:
        response.set_cookie(cognito_config.access_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=cognito_config.cookie_secure,
                            httponly=False,
                            domain=cognito_config.cookie_domain,
                            path=cognito_config.access_csrf_cookie_path,
                            samesite=cognito_config.cookie_samesite)


def unset_refresh_cookies(response):
    """
    takes a flask response object, and configures it to unset (delete) the
    refresh token from the response cookies. if `jwt_csrf_in_cookies`
    (see :ref:`configuration options`) is `true`, this will also remove the
    refresh csrf double submit value from the response cookies as well.

    :param response: the flask response object to delete the jwt cookies in.
    """
    if not cognito_config.jwt_in_cookies:
        raise RuntimeWarning("unset_refresh_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    response.set_cookie(cognito_config.refresh_cookie_name,
                        value='',
                        expires=0,
                        secure=cognito_config.cookie_secure,
                        httponly=True,
                        domain=cognito_config.cookie_domain,
                        path=cognito_config.refresh_cookie_path,
                        samesite=cognito_config.cookie_samesite)

    if cognito_config.csrf_protect and cognito_config.csrf_in_cookies:
        response.set_cookie(cognito_config.refresh_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=cognito_config.cookie_secure,
                            httponly=False,
                            domain=cognito_config.cookie_domain,
                            path=cognito_config.refresh_csrf_cookie_path,
                            samesite=cognito_config.cookie_samesite)


def get_unverified_jwt_headers(encoded_token):
    """
    Returns the Headers of an encoded JWT without verifying the actual signature of JWT.
     Note: The signature is not verified so the header parameters
     should not be fully trusted until signature verification is complete

    :param encoded_token: The encoded JWT to get the Header from.
    :return: JWT header parameters as python dict()
    """
    return jwt.get_unverified_header(encoded_token)


def get_unverified_jwt_claims(encoded_token):
    """
    Returns the Headers of an encoded JWT without verifying the actual signature of JWT.
     Note: The signature is not verified so the header parameters
     should not be fully trusted until signature verification is complete

    :param encoded_token: The encoded JWT to get the Header from.
    :return: JWT header parameters as python dict()
    """
    return jwt.get_unverified_claims(encoded_token)
