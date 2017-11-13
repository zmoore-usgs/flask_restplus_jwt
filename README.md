# flask_restplus_jwt
Extension of Flask-JWT-Simple suitable for use with Flask-Restplus

[![Build Status](https://travis-ci.org/USGS-CIDA/flask_restplus_jwt.svg?branch=master)](https://travis-ci.org/USGS-CIDA/flask_restplus_jwt)
[![Coverage Status](https://coveralls.io/repos/github/USGS-CIDA/flask_restplus_jwt/badge.svg?branch=master)](https://coveralls.io/github/USGS-CIDA/flask_restplus_jwt?branch=master)

The Flask-JWT-Simple documentation should be consulted for configuration information: http://flask-jwt-simple.readthedocs.io/en/latest/
In addition to the configuration parameters used in Flask-JWT-Simple, this extension adds
JWT_ROLE_CLAIM. This should be a function which takes a python dictionary representing the 
decoded token and returns the role string.

You can add this module as a requirement to your requirements.txt as follows:
```
git+https://github.com/USGS-CIDA/flask_restplus_jwt
```

This above will not work if building an artifact that includes flask_restplus_jwt. In that cause, download the file, 
flask_resplus_jwt.py into your project. You will need to make sure that you have all of the requirements in requirements.txt.
Please note that in either case, you may need to include the dependency for cryptography 
(see https://pyjwt.readthedocs.io/en/latest/installation.html#cryptographic-dependencies-optional)

Below is an simple example of how to use the extension.

```python
from flask import Flask

from flask_restplus import Api, Resource
from flask_restplus_jwt import JWTRestplusManager, jwt_required, jwt_role_required

application = Flask(__name__)

application.config['JWT_SECRET_KEY'] = 'secret_key'
# You can also use the JWT_PUBLIC_KEY and set the appropriate JWT_ALGORITHM for the key.
# If needed you can set the expected audience claim with JWT_DECODE_AUDIENCE

def get_role (dict):
    return dict['role']
# JWT_ROLE_CLAIM is used by the flask_restplus_jwt extension to define the function which
# will retrieve the role from the decoded jwt token when using the jwt_role_required decorator.
application.config['JWT_ROLE_CLAIM'] = get_role

# This will add the Authorize button to the swagger docs
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

api = Api(application,
          doc='/api',
          security='apikey', authorizations=authorizations)


# Setup the Flask-JWT-Simple extension
jwt = JWTRestplusManager(api, application)


@api.route('/endpoint')
class TestEndpoint(Resource):

    @api.response(401, 'Not authorized')
    @api.response(422, 'Invalid authorization token')
    @jwt_required
    def get(self):
        return "Successful"

@api.route('/role_endpoint')
class TestRoleProtectedEndPoint(Resource):

    @api.response(401, 'Not authorized')
    @api.response(422, 'Invalid authorization token')
    @jwt_role_required('admin')
    def get(self):
        return 'Successful'


if __name__ == '__main__':
    application.run()
```
