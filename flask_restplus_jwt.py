from functools import wraps

from flask import current_app, jsonify
from flask_jwt_simple import JWTManager, jwt_required as simple_jwt_required, get_jwt
from flask_jwt_simple.exceptions import NoAuthorizationError
from jwt.exceptions import InvalidTokenError


class JWTRestplusManager(JWTManager):
    """
    Extends the JWTManager in Flask_JWT_Simple to include the Flask-Restplus API instance.
    Includes api error handlers for errors raised by Flask_JWT_Simple

    """

    def __init__(self, api, app=None):
        '''
        :param api: Instance of a flask_restplus Api that has been associated with app
        :param app: Instance of flask application or blueprint
        '''
        self.api = api
        super(self.__class__, self).__init__(app)

        # https://github.com/vimalloc/flask-jwt-extended/issues/86
        self._set_error_handler_callbacks(api)

        # As a result of https://github.com/noirbizarre/flask-restplus/issues/421 we must register
        # the invalid token error handler for each sub-class of jwt.exceptions.InvalidTokenError
        def handle_invalid_token_error(e):
            return self._invalid_token_callback(str(e))

        for subclass in InvalidTokenError.__subclasses__():
            (api.errorhandler(subclass))(handle_invalid_token_error)

        # Override default error callbacks
        self.expired_token_loader(expired_token_callback)
        self.invalid_token_loader(invalid_token_callback)
        self.unauthorized_loader(unauthorized_callback)


# Slightly tweaked version of the default callback from flask_jwt_simple.default_callbacks
def expired_token_callback():
    return jsonify({'error_message': 'Token has expired'}), 401

# Slightly tweaked version of the default callback from flask_jwt_simple.default_callbacks
def invalid_token_callback(error_string):
    return jsonify({'error_message': error_string}), 422

# Slightly tweaked version of the default callback from flask_jwt_simple.default_callbacks
def unauthorized_callback(error_string):
    return jsonify({'error_message': error_string}), 401

def jwt_required(fn):
    """
    Wrapper for the flask_jwt_simple.jwt_required decorator
    :param fn: Flask Restplus resource view function
    :return: function
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        return simple_jwt_required(fn)(*args, **kwargs)

    return wrapper


def jwt_role_required(allowed_roles):
    """
    Decorator for Flask Restplu resource view function which authenticates the authorization token and
    authories the token by matching the role against the role found in the JWT token.
    Requires the use of JWT_ROLE_CLAIM config variable. This is a function which takes the decoded token and
    returns the role. In order to authorize, the string returned by that function should match role.
    :param str role:
    :return: function
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            response = simple_jwt_required(fn)(*args, **kwargs)
            token = get_jwt()
            roles_in_token = current_app.config['JWT_ROLE_CLAIM'](token)
            if [role for role in roles_in_token if role in allowed_roles]:
                return response
            else:
                raise NoAuthorizationError('Does not have required role')
        return wrapper
    return decorator






