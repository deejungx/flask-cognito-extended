"""
These are the default methods implementations that are used in this extension.
All of these can be updated on an app by app basis using the CognitoManager
loader decorators. For further information, check out the following links:

"""
from flask import jsonify
import requests
import json

from flask_cognito_extended.exceptions import FlaskCognitoException
from flask_cognito_extended.config import cognito_config


def default_expired_token_callback(expired_token):
    """
    By default, if an expired token attempts to access a protected endpoint,
    we return a generic error message with a 401 status
    """
    return jsonify({cognito_config.error_msg_key: 'Token has expired'}), 401


def default_invalid_token_callback(error_string):
    """
    By default, if an invalid token attempts to access a protected endpoint, we
    return the error string for why it is not valid with a 422 status code

    :param error_string: String indicating why the token is invalid
    """
    return jsonify({cognito_config.error_msg_key: error_string}), 422


def default_unauthorized_callback(error_string):
    """
    By default, if a protected endpoint is accessed without a JWT,
    we return the error string indicating why this is unauthorized,
    with a 401 status code.

    :param error_string: String indicating why this request is unauthorized
    """
    return jsonify({cognito_config.error_msg_key: error_string}), 401


def default_revoked_token_callback():
    """
    By default, if a revoked token is used to access a protected endpoint, we
    return a general error message with a 401 status code
    """
    return jsonify({cognito_config.error_msg_key: 'Token has been'
                                                  ' revoked'}), 401


def default_user_loader_error_callback(identity):
    """
    By default, if a user_loader callback is defined and the callback
    function returns None, we return a general error message with a 401
    status code
    """
    result = {cognito_config.error_msg_key: "Error loading the"
                                            " user {}".format(identity)}
    return jsonify(result), 401


def default_decode_key_callback(public_uri):
    """
    The default implementation returns the public key provided by Cognito
    at the endpoint:
    https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
    """
    try:
        response = requests.get(public_uri)
        key = json.loads(response.text)
    except requests.exceptions.RequestException as e:
        raise FlaskCognitoException(str(e)) from e
    return key


def default_authorization_failed_callback(error_string):
    """
    By default, if a authorization code exchange fails, we will return
    the message passed by cognito with a 401 status code
    """
    return jsonify({cognito_config.error_msg_key: error_string}), 401


def default_user_endpoint_error_callback(error_string):
    """
    By default, if a user info endpoint fails, we will return
    the message passed by cognito with a 401 status code
    """
    return jsonify({cognito_config.error_msg_key: error_string}), 401


def default_general_error_callback(error_string):
    """
    By default, if a user info endpoint fails, we will return
    the message passed by cognito with a 401 status code
    """
    return jsonify({cognito_config.error_msg_key: error_string}), 401
