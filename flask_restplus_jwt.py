from functools import wraps

from flask import current_app
from flask_jwt_simple import JWTManager, jwt_required as simple_jwt_required, get_jwt
from flask_jwt_simple.exceptions import NoAuthorizationError, InvalidHeaderError

from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidAudienceError



class JWTRestplusManager(JWTManager):

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

    @wraps(fn)
    def wrapper(*args, **kwargs):
        return simple_jwt_required(fn)(*args, **kwargs)

    return wrapper


def jwt_role_required(role):

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






