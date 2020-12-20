from flask_cognito_extended.config import cognito_config
from datetime import timedelta
import pytest
from hashlib import md5

def test_default_configs(app):
    """
    Given an app instance
    When a new app instance is created
    Then check the default config properties
    """
    with app.test_request_context():
        assert cognito_config.exempt_methods == {"OPTIONS",}
        assert cognito_config.token_location == ('headers',)
        assert cognito_config.jwt_in_query_string is False
        assert cognito_config.jwt_in_cookies is False
        assert cognito_config.jwt_in_json is False
        assert cognito_config.jwt_in_headers is True

        assert cognito_config.header_name == 'Authorization'
        assert cognito_config.header_type == 'Bearer'

        assert cognito_config.query_string_name == 'jwt'

        assert cognito_config.access_cookie_name == 'access_token_cookie'
        assert cognito_config.refresh_cookie_name == 'refresh_token_cookie'
        assert cognito_config.access_cookie_path == '/'
        assert cognito_config.refresh_cookie_path == '/'
        assert cognito_config.cookie_secure is False
        assert cognito_config.cookie_domain is None
        assert cognito_config.session_cookie is True
        assert cognito_config.cookie_samesite is None

        assert cognito_config.json_key == 'access_token'
        assert cognito_config.refresh_json_key == 'refresh_token'

        assert cognito_config.csrf_protect is False
        assert cognito_config.csrf_request_methods == ['POST', 'PUT', 'PATCH', 'DELETE']
        assert cognito_config.csrf_in_cookies is False
        assert cognito_config.access_csrf_cookie_name == 'csrf_access_token'
        assert cognito_config.refresh_csrf_cookie_name == 'csrf_refresh_token'
        assert cognito_config.access_csrf_cookie_path == '/'
        assert cognito_config.refresh_csrf_cookie_path == '/'
        assert cognito_config.access_csrf_header_name == 'X-CSRF-TOKEN'
        assert cognito_config.refresh_csrf_header_name == 'X-CSRF-TOKEN'
        assert cognito_config.csrf_check_form is False
        assert cognito_config.access_csrf_field_name == 'csrf_token'
        assert cognito_config.refresh_csrf_field_name == 'csrf_token'
        
        assert cognito_config.access_expires == timedelta(minutes=60)
        assert cognito_config.refresh_expires == timedelta(days=30)
        
        assert cognito_config.blacklist_enabled is False
        assert cognito_config.blacklist_checks == ('access', 'refresh')
        assert cognito_config.blacklist_access_tokens is True
        assert cognito_config.blacklist_refresh_tokens is True
        
        assert cognito_config.cookie_max_age is None

        assert cognito_config.identity_claim_key == 'sub'

        assert cognito_config.error_msg_key == 'msg'

def test_tokens_never_expire(app):
    with app.test_request_context():
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = False
        
        assert cognito_config.access_expires is False
        assert cognito_config.refresh_expires is False

def test_tokens_with_int_values(app):
    with app.test_request_context():
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 300
        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 432000
        
        assert cognito_config.access_expires == timedelta(minutes=5)
        assert cognito_config.refresh_expires == timedelta(days=5)

def test_invalid_config_options(app):
    with app.test_request_context():
        app.config['JWT_TOKEN_LOCATION'] = []
        with pytest.raises(RuntimeError):
            cognito_config.token_location

        app.config['JWT_TOKEN_LOCATION'] = 'cheese'
        with pytest.raises(RuntimeError):
            cognito_config.token_location

        app.config['JWT_TOKEN_LOCATION'] = 1
        with pytest.raises(RuntimeError):
            cognito_config.token_location

        app.config['JWT_TOKEN_LOCATION'] = {'location': 'headers'}
        with pytest.raises(RuntimeError):
            cognito_config.token_location

        app.config['JWT_TOKEN_LOCATION'] = range(99)
        with pytest.raises(RuntimeError):
            cognito_config.token_location

        app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies', 'banana']
        with pytest.raises(RuntimeError):
            cognito_config.token_location

        app.config['JWT_HEADER_NAME'] = ''
        with pytest.raises(RuntimeError):
            cognito_config.header_name

        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 'banana'
        with pytest.raises(RuntimeError):
            cognito_config.access_expires

        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 'banana'
        with pytest.raises(RuntimeError):
            cognito_config.refresh_expires

        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = True
        with pytest.raises(RuntimeError):
            cognito_config.access_expires

        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = True
        with pytest.raises(RuntimeError):
            cognito_config.refresh_expires

        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'banana'
        with pytest.raises(RuntimeError):
            cognito_config.blacklist_checks

        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 1
        with pytest.raises(RuntimeError):
            cognito_config.blacklist_checks

        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = {'token_type': 'access'}
        with pytest.raises(RuntimeError):
            cognito_config.blacklist_checks

        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = range(99)
        with pytest.raises(RuntimeError):
            cognito_config.blacklist_checks

        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'banana']
        with pytest.raises(RuntimeError):
            cognito_config.blacklist_checks
        
        app.config['COGNITO_REDIRECT_URI'] = ''
        with pytest.raises(RuntimeError):
            cognito_config.redirect_uri

        app.config['COGNITO_DOMAIN'] = ''
        with pytest.raises(RuntimeError):
            cognito_config.domain
        
        app.config['COGNITO_CLIENT_ID'] = ''
        with pytest.raises(RuntimeError):
            cognito_config.client_id
        
        app.config['COGNITO_USER_POOL_ID'] = ''
        with pytest.raises(RuntimeError):
            cognito_config.user_pool_id

        app.config['COGNITO_REGION'] = ''
        with pytest.raises(RuntimeError):
            cognito_config.region
        
        app.config['COGNITO_SCOPE'] = ''
        with pytest.raises(RuntimeError):
            cognito_config.scope

def test_jwt_token_locations_config(app):
    with app.test_request_context():
        allowed_locations = ('headers', 'cookies', 'query_string', 'json')
        allowed_data_structures = (tuple, list, frozenset, set)

        for location in allowed_locations:
            app.config['JWT_TOKEN_LOCATION'] = location
            assert cognito_config.token_location == (location,)

        for locations in (
            data_structure((location,))
            for data_structure in allowed_data_structures
            for location in allowed_locations
        ):
            app.config['JWT_TOKEN_LOCATION'] = locations
            assert cognito_config.token_location == locations

        for locations in (
            data_structure(allowed_locations[:i])
            for data_structure in allowed_data_structures
            for i in range(1, len(allowed_locations))
        ):
            app.config['JWT_TOKEN_LOCATION'] = locations
            assert cognito_config.token_location == locations

def test_jwt_blacklist_token_checks_config(app):
    with app.test_request_context():
        allowed_token_types = ('access', 'refresh')
        allowed_data_structures = (tuple, list, frozenset, set)

        for token_type in allowed_token_types:
            app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = token_type
            assert cognito_config.blacklist_checks == (token_type,)

        for token_types in (
            data_structure((token_type,))
            for data_structure in allowed_data_structures
            for token_type in allowed_token_types
        ):
            app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = token_types
            assert cognito_config.blacklist_checks == token_types

        for token_types in (
            data_structure(allowed_token_types[:i])
            for data_structure in allowed_data_structures
            for i in range(1, len(allowed_token_types))
        ):
            app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = token_types
            assert cognito_config.blacklist_checks == token_types

def test_csrf_protect_config(app):
    with app.test_request_context():
        app.config['JWT_TOKEN_LOCATION'] = ['headers']
        app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        assert cognito_config.csrf_protect is False

        app.config['JWT_TOKEN_LOCATION'] = ['cookies']
        app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        assert cognito_config.csrf_protect is True

        app.config['JWT_TOKEN_LOCATION'] = ['cookies']
        app.config['JWT_COOKIE_CSRF_PROTECT'] = False
        assert cognito_config.csrf_protect is False

def test_cognito_config(app):
    with app.test_request_context():
        app.config['COGNITO_SCOPE'] = "aws.cognito.signin.user.admin+email+openid+profile"
        app.config['COGNITO_REGION'] = "us-east-1"
        app.config['COGNITO_USER_POOL_ID'] = "us-east-1_Bg4lP27"
        app.config['COGNITO_CLIENT_ID'] = "ik23vg4532v1i4v234viy2uvdi823vhyv"
        app.config['COGNITO_REDIRECT_URI'] = "https://flaskcognito/callback"
        app.config['COGNITO_STATE'] = 'viubd1v42i34ugiu23v4u2'

        assert cognito_config.scope == "aws.cognito.signin.user.admin+email+openid+profile"
        assert cognito_config.region == "us-east-1"
        assert cognito_config.user_pool_id == "us-east-1_Bg4lP27"
        assert cognito_config.client_id == "ik23vg4532v1i4v234viy2uvdi823vhyv"
        assert cognito_config.redirect_uri == "https://flaskcognito/callback"
        assert cognito_config.state == 'viubd1v42i34ugiu23v4u2'

        app.config['COGNITO_DOMAIN'] = "https://flaskcognito.com"
        assert cognito_config.domain == "https://flaskcognito.com"
        
        app.config['COGNITO_DOMAIN'] = "flaskcognito.com"
        assert cognito_config.domain == "https://flaskcognito.com"

        assert cognito_config.login_uri == ("https://flaskcognito.com/login?client_id="
                                            "ik23vg4532v1i4v234viy2uvdi823vhyv&response_type"
                                            "=code&scope=aws.cognito.signin.user.admin+email"
                                            "+openid+profile&redirect_uri=https://"
                                            "flaskcognito/callback&state={}").format(
                                                                cognito_config.state)
