# Flask-Cognito-Extended

[![Build Status](https://travis-ci.com/deejungx/flask-cognito-extended.svg?branch=master)](https://travis-ci.com/deejungx/flask-cognito-extended)
[![codecov](https://codecov.io/gh/deejungx/flask-cognito-extended/branch/master/graph/badge.svg?token=U1N05DKQ1E)](https://codecov.io/gh/deejungx/flask-cognito-extended)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Flask-Cognito-Extended is a Flask implementation of Amazon Cognito. This extension helps quickly implement authentication and authorization solutions based on Amazon's Cognito. It contains helpful functions and properties to handle token based authentication flows.

```bash
pip install Flask-Cognito-Extended
```

### Usage

```python
from flask import Flask, jsonify
from flask_cognito_extended import (
    CognitoManager, login_handler,
    callback_handler, get_jwt_identity
)

app = Flask(__name__)

# Setup the flask-cognito-extended extention
app.config['COGNITO_SCOPE'] = "aws.cognito.signin.user.admin+email+openid+profile"
app.config['COGNITO_REGION'] = "us-east-1"
app.config['COGNITO_USER_POOL_ID'] = "us-east-1_xxxxxxx"
app.config['COGNITO_CLIENT_ID'] = "xxxxxxxxxxxxxxxxxxxxxxxxxx"
app.config['COGNITO_DOMAIN'] = "https://yourdomainhere.com"
app.config['COGNITO_REDIRECT_URI'] = "https://yourdomainhere/callback"

cognito = CognitoManager(app)

# Use @login_handler decorator on your login route
@app.route('/login', methods=['GET'])
@login_handler
def login():
    return jsonify(msg="User already signed in."), 200


# Use @callback_handler decorator on your callback route
@app.route('/callback', methods=['GET'])
@callback_handler
def callback():
    # fetch the unique 'sub' property of the User
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)
```

### Development Setup

Using pipenv
```bash
pipenv install --dev 
```
Using virtualenv
```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### Contributing

1. Fork repo- https://github.com/deejungx/flask-cognito-extended/fork
2. Create your feature branch - `git checkout -b feature/foo`
3. Commit your changes - `git commit -am "Added foo"`
4. Push to the branch - `git push origin feature/foo`
5. Create a new pull request

