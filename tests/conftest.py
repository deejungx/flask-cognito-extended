import pytest
from flask import Flask
from flask_cognito_extended import CognitoManager

@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    CognitoManager(app)
    return app
