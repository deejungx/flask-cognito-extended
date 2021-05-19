import time
from jose import jwk, jwt
from jose.utils import base64url_decode
from werkzeug.security import safe_str_cmp
from flask_cognito_extended.exceptions import CSRFError, JWTDecodeError
from jwt import ExpiredSignatureError
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack


def decode_jwt(encoded_token, secret, identity_claim_key,
               csrf_value=None, audience=None, allow_expired=False,
               issuer=None):
    """
    Decodes an encoded JWT

    :param encoded_token: The encoded JWT string to decode
    :param secret: Secret key used to decode the JWT
    :param identity_claim_key: expected key that contains the identity
    :param csrf_value: Expected double submit csrf value
    :param audience: expected audience in the JWT
    :param issuer: expected issuer in the JWT
    :param allow_expired: Options to ignore exp claim validation in token
    :return: Dictionary containing contents of the JWT
    """
    token = encoded_token
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(secret)):
        if kid == secret[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        raise JWTDecodeError("Invalid key attribute: kid")
    # construct the public key
    public_key = jwk.construct(secret[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        raise JWTDecodeError("Signature verification failed")
    # since we passed the verification, we can now safely
    # use the unverified claims
    data = jwt.get_unverified_claims(token)
    if identity_claim_key not in data:
        raise JWTDecodeError("Missing claim: {}".format(identity_claim_key))
    if not allow_expired and time.time() > data['exp']:
        ctx_stack.top.expired_jwt = token
        raise ExpiredSignatureError("Token has expired")
    # check iss
    if 'iss' not in data:
        data['iss'] = None
    if data['iss'] != issuer:
        raise JWTDecodeError("Missing or invalid issuer")
    # check aud if id_token
    if data['token_use'] == 'id':
        if 'aud' not in data:
            data['aud'] = None
        if data['aud'] != audience:
            raise JWTDecodeError("Missing or invalid audience")
    # check clientid if access_token
    if data['token_use'] == 'access':
        if 'client_id' not in data:
            data['client_id'] = None
        if data['client_id'] != audience:
            raise JWTDecodeError("Missing or invalid audience")
    # check csrf
    if csrf_value:
        if 'csrf' not in data:
            raise JWTDecodeError("Missing claim: csrf")
        if not safe_str_cmp(data['csrf'], csrf_value):
            raise CSRFError("CSRF double submit tokens do not match")
    return data
