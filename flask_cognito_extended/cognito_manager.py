from warnings import warn
import datetime

from jwt import (
    ExpiredSignatureError, InvalidTokenError, InvalidAudienceError,
    InvalidIssuerError, DecodeError)

from flask_cognito_extended.exceptions import (
    JWTDecodeError, NoAuthorizationError, InvalidHeaderError, UserInfoError,
    WrongTokenError, RevokedTokenError, CSRFError, UserLoadError,
    AuthorizationExchangeError, FlaskCognitoException)

from flask_cognito_extended.default_callbacks import (
    default_expired_token_callback, default_invalid_token_callback,
    default_unauthorized_callback, default_revoked_token_callback,
    default_user_loader_error_callback, default_authorization_failed_callback,
    default_decode_key_callback, default_user_endpoint_error_callback,
    default_general_error_callback)

try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

from flask_cognito_extended.utils import get_jwt_identity


class CognitoManager(object):
    """
    An object used to hold JWT settings and callback functions for the
    Flask-JWT-Extended extension.

    Instances of :class:`CognitoManager` are *not* bound to specific apps, so
    you can create one in the main body of your code and then bind it
    to your app in a factory function.
    """

    def __init__(self, app=None):
        """
        Create the CognitoManager instance. You can either pass a flask application
        in directly here to register this extension with the flask app, or
        call init_app after creating this object (in a factory pattern).

        :param app: A flask application
        """
        # Register the default error handler callback methods. These can be
        # overridden with the appropriate loader decorators
        self._expired_token_callback = default_expired_token_callback
        self._invalid_token_callback = default_invalid_token_callback
        self._unauthorized_callback = default_unauthorized_callback
        self._revoked_token_callback = default_revoked_token_callback
        self._user_loader_callback = None
        self._user_loader_error_callback = default_user_loader_error_callback
        self._token_in_blacklist_callback = None
        self._decode_key_callback = default_decode_key_callback
        self._authorization_failed_callback = default_authorization_failed_callback
        self._user_endpoint_failed_callback = default_user_endpoint_error_callback
        self._general_error_callback = default_general_error_callback

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Register this extension with the flask app.
        :param app: A flask application
        """
        # Save this so we can use it later in the extension
        if not hasattr(app, 'extensions'):   # pragma: no cover
            app.extensions = {}
        app.extensions['flask-cognito-extended'] = self

        # Set all the default configurations for this extension
        self._set_default_configuration_options(app)
        self._set_error_handler_callbacks(app)

    def _set_error_handler_callbacks(self, app):
        """
        Sets the error handler callbacks used by this extension
        """
        @app.errorhandler(NoAuthorizationError)
        def handle_auth_error(e):
            return self._unauthorized_callback(str(e))

        @app.errorhandler(CSRFError)
        def handle_csrf_error(e):
            return self._unauthorized_callback(str(e))

        @app.errorhandler(ExpiredSignatureError)
        def handle_expired_error(e):
            try:
                token = ctx_stack.top.expired_jwt
                return self._expired_token_callback(token)
            except TypeError:
                msg = (
                    "jwt.expired_token_loader callback now takes the expired token "
                    "as an additional parameter. Example: expired_callback(token)"
                )
                warn(msg, DeprecationWarning)
                return self._expired_token_callback()

        @app.errorhandler(InvalidHeaderError)
        def handle_invalid_header_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(DecodeError)
        def handle_decode_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(InvalidTokenError)
        def handle_invalid_token_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(JWTDecodeError)
        def handle_jwt_decode_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(WrongTokenError)
        def handle_wrong_token_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(InvalidAudienceError)
        def handle_invalid_audience_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(InvalidIssuerError)
        def handle_invalid_issuer_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(RevokedTokenError)
        def handle_revoked_token_error(e):
            return self._revoked_token_callback()

        @app.errorhandler(UserLoadError)
        def handler_user_load_error(e):
            # The identity is already saved before this exception was raised,
            # otherwise a different exception would be raised, which is why we
            # can safely call get_jwt_identity() here
            identity = get_jwt_identity()
            return self._user_loader_error_callback(identity)

        @app.errorhandler(AuthorizationExchangeError)
        def handle_invalid_authorization_exchange(e):
            return self._authorization_failed_callback(str(e))

        @app.errorhandler(UserInfoError)
        def handle_user_info_error(e):
            return self._user_endpoint_failed_callback(str(e))

        @app.errorhandler(FlaskCognitoException)
        def handle_general_error(e):
            return self._general_error_callback(str(e))

    @staticmethod
    def _set_default_configuration_options(app):
        """
        Sets the default configuration options used by this extension
        """

        # Where to look for the JWT. Available options are cookies or headers
        app.config.setdefault('EXEMPT_METHODS', {"OPTIONS",})

        # Where to look for the JWT. Available options are cookies or headers
        app.config.setdefault('JWT_TOKEN_LOCATION', ('headers',))

        # Options for JWTs when the TOKEN_LOCATION is headers
        app.config.setdefault('JWT_HEADER_NAME', 'Authorization')
        app.config.setdefault('JWT_HEADER_TYPE', 'Bearer')

        # Options for JWTs then the TOKEN_LOCATION is query_string
        app.config.setdefault('JWT_QUERY_STRING_NAME', 'jwt')

        # Option for JWTs when the TOKEN_LOCATION is cookies
        app.config.setdefault('JWT_ACCESS_COOKIE_NAME', 'access_token_cookie')
        app.config.setdefault('JWT_REFRESH_COOKIE_NAME', 'refresh_token_cookie')
        app.config.setdefault('JWT_ACCESS_COOKIE_PATH', '/')
        app.config.setdefault('JWT_REFRESH_COOKIE_PATH', '/')
        app.config.setdefault('JWT_COOKIE_SECURE', False)
        app.config.setdefault('JWT_COOKIE_DOMAIN', None)
        app.config.setdefault('JWT_SESSION_COOKIE', True)
        app.config.setdefault('JWT_COOKIE_SAMESITE', None)

        # Option for JWTs when the TOKEN_LOCATION is json
        app.config.setdefault('JWT_JSON_KEY', 'access_token')
        app.config.setdefault('JWT_REFRESH_JSON_KEY', 'refresh_token')

        # Options for using double submit csrf protection
        app.config.setdefault('JWT_COOKIE_CSRF_PROTECT', False)
        app.config.setdefault('JWT_CSRF_METHODS', ['POST', 'PUT', 'PATCH', 'DELETE'])
        app.config.setdefault('JWT_ACCESS_CSRF_HEADER_NAME', 'X-CSRF-TOKEN')
        app.config.setdefault('JWT_REFRESH_CSRF_HEADER_NAME', 'X-CSRF-TOKEN')
        app.config.setdefault('JWT_CSRF_IN_COOKIES', False)
        app.config.setdefault('JWT_ACCESS_CSRF_COOKIE_NAME', 'csrf_access_token')
        app.config.setdefault('JWT_REFRESH_CSRF_COOKIE_NAME', 'csrf_refresh_token')
        app.config.setdefault('JWT_ACCESS_CSRF_COOKIE_PATH', '/')
        app.config.setdefault('JWT_REFRESH_CSRF_COOKIE_PATH', '/')
        app.config.setdefault('JWT_CSRF_CHECK_FORM', False)
        app.config.setdefault('JWT_ACCESS_CSRF_FIELD_NAME', 'csrf_token')
        app.config.setdefault('JWT_REFRESH_CSRF_FIELD_NAME', 'csrf_token')

        # How long an a token will live before they expire.
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES',
                                datetime.timedelta(minutes=60))
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES',
                                datetime.timedelta(days=30))

        # Options for blacklisting/revoking tokens
        app.config.setdefault('JWT_BLACKLIST_ENABLED', False)
        app.config.setdefault('JWT_BLACKLIST_TOKEN_CHECKS', ('access', 'refresh'))

        app.config.setdefault('JWT_IDENTITY_CLAIM', 'sub')

        app.config.setdefault('JWT_ERROR_MESSAGE_KEY', 'msg')

    def expired_token_loader(self, callback):
        """
        This decorator sets the callback function that will be called if an
        expired JWT attempts to access a protected endpoint. The default
        implementation will return a 401 status code with the JSON:

        {"msg": "Token has expired"}

        *HINT*: The callback must be a function that takes **one** argument,
        which is a dictionary containing the data for the expired token, and
        and returns a *Flask response*.
        """
        self._expired_token_callback = callback
        return callback

    def invalid_token_loader(self, callback):
        """
        This decorator sets the callback function that will be called if an
        invalid JWT attempts to access a protected endpoint. The default
        implementation will return a 422 status code with the JSON:

        {"msg": "<error description>"}

        *HINT*: The callback must be a function that takes only **one** argument,
        which is a string which contains the reason why a token is invalid,
        and returns a *Flask response*.
        """
        self._invalid_token_callback = callback
        return callback

    def unauthorized_loader(self, callback):
        """
        This decorator sets the callback function that will be called if an
        no JWT can be found when attempting to access a protected endpoint.
        The default implementation will return a 401 status code with the JSON:

        {"msg": "<error description>"}

        *HINT*: The callback must be a function that takes only **one** argument,
        which is a string which contains the reason why a JWT could not be found, and
        returns a *Flask response*.
        """
        self._unauthorized_callback = callback
        return callback

    def revoked_token_loader(self, callback):
        """
        This decorator sets the callback function that will be called if a
        revoked token attempts to access a protected endpoint. The default
        implementation will return a 401 status code with the JSON:

        {"msg": "Token has been revoked"}

        *HINT*: The callback must be a function that takes **no** arguments,
        and returns a *Flask response*.
        """
        self._revoked_token_callback = callback
        return callback

    def user_loader_callback_loader(self, callback):
        """
        This decorator sets the callback function that will be called to
        automatically load an object when a protected endpoint is accessed.
        By default this is not used.

        *HINT*: The callback must take **one** argument which is the identity JWT
        accessing the protected endpoint, and it must return any object (which can
        then be accessed via the :attr:`~flask_jwt_extended.current_user` LocalProxy
        in the protected endpoint), or `None` in the case of a user not being
        able to be loaded for any reason. If this callback function returns
        `None`, the :meth:`~flask_jwt_extended.CognitoManager.user_loader_error_loader`
        will be called.
        """
        self._user_loader_callback = callback
        return callback

    def user_loader_error_loader(self, callback):
        """
        This decorator sets the callback function that will be called if `None`
        is returned from the
        :meth:`~flask_jwt_extended.CognitoManager.user_loader_callback_loader`
        callback function. The default implementation will return
        a 401 status code with the JSON:

        {"msg": "Error loading the user <identity>"}

        *HINT*: The callback must be a function that takes **one** argument,
        which is the identity of the user who failed to load, and must return
        a *Flask response*.
        """
        self._user_loader_error_callback = callback
        return callback

    def token_in_blacklist_loader(self, callback):
        """
        This decorator sets the callback function that will be called when
        a protected endpoint is accessed and will check if the JWT has been
        been revoked. By default, this callback is not used.

        *HINT*: The callback must be a function that takes **one** argument,
        which is the decoded JWT (python dictionary), and returns *`True`* if
        the token has been blacklisted (or is otherwise considered revoked),
        or *`False`* otherwise.
        """
        self._token_in_blacklist_callback = callback
        return callback

    def decode_key_loader(self, callback):
        """
        This decorator sets the callback function for getting the JWT decode key and
        can be used to dynamically choose the appropriate decode key based on token
        contents.

        The default implementation returns the public key provided by Cognito
        at the endpoint:

        https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json

        *HINT*: The callback function should be a function that takes
        **two** arguments, which are the unverified claims and headers of the jwt
        (dictionaries). The function must return a *string* which is the decode key
        in PEM format to verify the token.
        """
        self._decode_key_callback = callback
        return callback
