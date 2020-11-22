class CognitoJwtException(Exception):
    """
    Base except which all flask_jwt_extended errors extend
    """
    pass


class JWTDecodeError(CognitoJwtException):
    """
    An error decoding a JWT
    """
    pass


class InvalidHeaderError(CognitoJwtException):
    """
    An error getting header information from a request
    """
    pass


class NoAuthorizationError(CognitoJwtException):
    """
    An error raised when no authorization token was found in a
    protected endpoint
    """
    pass


class CSRFError(CognitoJwtException):
    """
    An error with CSRF protection
    """
    pass


class WrongTokenError(CognitoJwtException):
    """
    Error raised when attempting to use a refresh token to access an endpoint
    or vice versa
    """
    pass


class RevokedTokenError(CognitoJwtException):
    """
    Error raised when a revoked token attempt to access a protected endpoint
    """
    pass


class UserLoadError(CognitoJwtException):
    """
    Error raised when a user_loader callback function returns None, indicating
    that it cannot or will not load a user for the given identity.
    """
    pass


class AuthorizationExchangeError(CognitoJwtException):
    """
    An error raised when tokens could not be obtained
    in exchange for the authorization code
    """
    pass


class UserInfoError(CognitoJwtException):
    """
    An error raised when tokens could not be obtained
    in exchange for the authorization code
    """
    pass


class FlaskCognitoException(CognitoJwtException):
    """
    An error raised when tokens could not be obtained
    in exchange for the authorization code
    """
    pass
