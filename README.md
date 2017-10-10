# flask_restplus_jwt
Extension of Flask-JWT-Simple suitable for use with Flask-Restplus

[![Build Status](https://travis-ci.org/USGS-CIDA/flask_restplus_jwt.svg?branch=master)](https://travis-ci.org/USGS-CIDA/flask_restplus_jwt)
[![Coverage Status](https://coveralls.io/repos/github/USGS-CIDA/flask_restplus_jwt/badge.svg?branch=master)](https://coveralls.io/github/USGS-CIDA/flask_restplus_jwt?branch=master)

The Flask-JWT-Simple documentation should be consulted for configuration information: http://flask-jwt-simple.readthedocs.io/en/latest/
In addition to the configuration parameters used in Flask-JWT-Simple, this extension adds
JWT_ROLE_CLAIM. This should be a function which takes a python dictionary representing the 
decoded token and returns the role string.

Below is an simple example of how to use the extension.

```python
from flask import Flask

from flask_restplus import Api, Resource
from flask_restplus_jwt import JWTRestplusManager, jwt_required, jwt_role_required

application = Flask(__name__)

application.config['JWT_SECRET_KEY'] = 'secret'
# You can also use the JWT_PUBLIC_KEY and set the appropriate JWT_ALGORITHM for the key.
# If needed you can set the expected audience claim with JWT_DECODE_AUDIENCE

def get_role (dict):
    return dict['role']
# JWT_ROLE_CLAIM is used by the flask_restplus_jwt extension to define the function which
# will retrieve the role from the decoded jwt token when using the jwt_role_required decorator.
application.config['JWT_ROLE_CLAIM'] = get_role 

api = Api(application,
          doc='/api')


# Setup the Flask-JWT-Simple extension
jwt = JWTRestplusManager(api, application)


@api.route('/endpoint')
class TestEndpoint(Resource):

    @api.header('Authorization', 'JWT token', required=True)
    @jwt_required
    def get(self):
        return "Successful"

@api.route('/role_endpoint')
class TestRoleProtectedEndPoint(Resource):

    @api.header('Authorization', 'JWT token', required=True)
    @jwt_role_required('admin')
    def get(self):
        return 'Successful'

```
