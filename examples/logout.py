from flask_cognito_extended.utils import get_raw_jwt, unset_access_cookies
from flask import Flask, jsonify, redirect
from flask.helpers import make_response
from flask_cognito_extended import (
    CognitoManager, login_handler,
    callback_handler, get_jwt_identity,
    set_access_cookies, get_encoded_access_token,
    jwt_required, get_logout_uri
)

app = Flask(__name__)

# Setup the flask-cognito-extended extention
app.config['COGNITO_SCOPE'] = "aws.cognito.signin.user.admin+email+openid+profile"
app.config['COGNITO_REGION'] = "us-east-1"
app.config['COGNITO_USER_POOL_ID'] = "us-east-1_xxxxxxx"
app.config['COGNITO_CLIENT_ID'] = "xxxxxxxxxxxxxxxxxxxxxxxxxx"
app.config['COGNITO_DOMAIN'] = "https://yourdomainhere.com"
app.config['COGNITO_REDIRECT_URI'] = "https://yourdomainhere/callback"
app.config['COGNITO_SIGNOUT_URI'] = "https://yourdomainhere/logout-redirect"
app.config['JWT_TOKEN_LOCATION'] = ('headers', 'cookies')
app.config['COGNITO_STATE'] = 'somerandomstring'

cognito = CognitoManager(app)


"""
A storage engine to save revoked tokens. In production if
speed is the primary concern, redis is a good bet. If data
persistence is more important for you, postgres is another
great option. In this example, we will be using an in memory
store, just to show you how this might work.
"""
blacklist = set()


"""
For this example, we are just checking if the tokens jti
(unique identifier) is in the blacklist set. This could
be made more complex, for example storing all tokens
into the blacklist with a revoked status when created,
and returning the revoked status in this call. This
would allow you to have a list of all created tokens,
and to consider tokens that aren't in the blacklist
(aka tokens you didn't create) as revoked. These are
just two options, and this can be tailored to whatever
your application needs.
"""
@cognito.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


# Your login endpoint
@app.route('/login', methods=['GET'])
@login_handler
def login():
    return jsonify(msg="User already signed in."), 200


# Your callback/redirect endpoint after successful login
@app.route('/callback', methods=['GET'])
@callback_handler
def callback():
    current_user = get_jwt_identity()
    access_token = get_encoded_access_token()
    res = make_response(jsonify(logged_in_as=current_user))
    set_access_cookies(response=res, encoded_access_token=access_token)
    return res


"""
Calls the LOGOUT endpoint.
According to the documentation, this endpoint signs the user out.
It clears out the existing session and redirects back to the client.
However, this does not expire the access and id tokens.
We will revoke them manually by adding it to blacklist and
removing the access token from cookie.

Read more:
https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
https://github.com/aws-amplify/amplify-js/issues/3435
"""
@app.route('/logout', methods=['GET'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return redirect(get_logout_uri())

"""
Redirect endpoint from logging out from cognito.
Unsets the access token from cookies
"""
@app.route('/logout-redirect', methods=['GET'])
def logout_redirect():
    res = make_response(jsonify(msg="You have logged out."))
    unset_access_cookies(response=res)
    return res

# logged out users cannot access this endpoint
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'msg': 'hi there!'})


if __name__ == '__main__':
    app.run()