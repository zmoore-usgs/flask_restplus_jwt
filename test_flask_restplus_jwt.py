
from unittest import TestCase

from flask import Flask
from flask_restplus import Api, Resource

import jwt

from flask_restplus_jwt import JWTRestplusManager, jwt_required, jwt_role_required

class JWTRequiredTest(TestCase):

    def setUp(self):
        self.application = Flask(__name__)
        self.application.config['JWT_SECRET_KEY'] = 'good_secret'

        self.application.testing = True
        self.api = Api(self.application)
        self.jwt_manager = JWTRestplusManager(self.api, self.application)

        @self.api.route('/endpoint')
        class TestEndpoint(Resource):

            @jwt_required
            def get(self):
                return 'Successful'


        self.app_client = self.application.test_client()

    def test_no_auth_header(self):
        response = self.app_client.get('/endpoint')
        self.assertEqual(response.status_code, 401)

    def test_no_token(self):
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization' : 'Bearer'})
        self.assertEqual(response.status_code, 422)

    def test_good_token(self):
        good_token = jwt.encode({'some': 'payload'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization' : 'Bearer {0}'.format(good_token.decode('utf-8'))}
                                       )
        self.assertEqual(response.status_code, 200)

    def test_bad_token(self):
        bad_token = jwt.encode({'some': 'payload'}, 'bad_secret')
        response = self.app_client.get('/endpoint',
                                      headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                      )
        self.assertEqual(response.status_code, 422)


class JWTRoleRequiredTest(TestCase):

    def setUp(self):
        self.application = Flask(__name__)
        self.application.config['JWT_SECRET_KEY'] = 'good_secret'

        def get_roles(dict):
            return dict.get('roles', [])
        self.application.config['JWT_ROLE_CLAIM'] = get_roles

        self.application.testing = True
        self.api = Api(self.application)
        self.jwt_manager = JWTRestplusManager(self.api, self.application)

        @self.api.route('/endpoint')
        class TestEndpoint(Resource):

            @jwt_role_required(['admin', 'superuser'])
            def get(self):
                return 'Successful'


        self.app_client = self.application.test_client()

    def test_no_auth_header(self):
        response = self.app_client.get('/endpoint')
        self.assertEqual(response.status_code, 401)

    def test_no_token(self):
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization': 'Bearer'})
        self.assertEqual(response.status_code, 422)

    def test_no_role(self):
        good_token = jwt.encode({'some': 'payload'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization': 'Bearer {0}'.format(good_token.decode('utf-8'))}
                                       )
        self.assertEqual(response.status_code, 401)


    def test_good_role(self):
        good_token = jwt.encode({'some': 'payload', 'roles': ['admin', 'dbadmin', 'worker']}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization': 'Bearer {0}'.format(good_token.decode('utf-8'))}
                                       )
        self.assertEqual(response.status_code, 200)

    def test_bad_role(self):
        token = jwt.encode({'some': 'payload', 'roles': ['dbadmin', 'student']}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization': 'Bearer {0}'.format(token.decode('utf-8'))}
                                       )
        self.assertEqual(response.status_code, 401)






