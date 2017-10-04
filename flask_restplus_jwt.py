from functools import wraps

from flask import current_app
from flask_jwt_simple import JWTManager, jwt_required as simple_jwt_required, get_jwt
from flask_jwt_simple.exceptions import NoAuthorizationError, InvalidHeaderError

from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidAudienceError



class JWTRestplusManager(JWTManager):
    """
    Extends the JWTManager in Flask_JWT_Simple to include the Flask-Restplus API instance.
    Includes api error handlers for errors raised by Flask_JWT_Simple
    """

    def __init__(self, api=None, app=None):
        self.api = api
        super(self.__class__, self).__init__(app)

        @api.errorhandler(ExpiredSignatureError) #Status 401
        @api.errorhandler(NoAuthorizationError) #Status 401
        @api.errorhandler(InvalidHeaderError)  # Status 401
        @api.errorhandler(DecodeError) # Returns status 422
        @api.errorhandler(InvalidAudienceError) # Status 422
        def handler_invalid_token(error):
            return {'message': error.message}

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


def jwt_role_required(role):
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
            try:
                if current_app.config['JWT_ROLE_CLAIM'](token) == role:
                    return response
                else:
                    raise NoAuthorizationError('Does not have required role')
            except KeyError:
                raise NoAuthorizationError('Does not have required role')
        return wrapper
    return decorator






