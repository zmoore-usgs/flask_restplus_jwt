from functools import wraps

from flask_jwt_simple import JWTManager
from flask_jwt_simple.exceptions import NoAuthorizationError

from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidAudienceError



class JWTRestplusManager(JWTManager):

    def __init__(self, api=None, app=None):
        self.api = api
        super(self.__class__, self).__init__(app)

        @api.errorhandler(ExpiredSignatureError) #Status 401
        @api.errorhandler(NoAuthorizationError) #Status 401
        @api.errorhandler(DecodeError) # Returns status 422
        @api.errorhandler(InvalidAudienceError) # Status 422
        def handler_invalid_token(error):
            return {'message': error.message}

def jwt_required(fn, enable):

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if enable:
            return jwt_required(fn)(*args, **kwargs)
        else:
            return fn(*args, **kwargs)
    return wrapper






