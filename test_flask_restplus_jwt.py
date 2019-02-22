
from unittest import TestCase

from flask import Flask, jsonify
from flask_restplus import Api, Resource
from flask_restplus_jwt import JWTRestplusManager, jwt_required, jwt_role_required

from calendar import timegm
from datetime import datetime

import jwt
import json


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


class JWTErrorHandlingTest(TestCase):
    
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
        self.assertEqual({'error_message': 'Missing Authorization Header'}, json.loads(response.data))

    def test_no_token(self):
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization' : 'Bearer'}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Bad Authorization header. Expected value \'Bearer <JWT>\''}, json.loads(response.data))

    def test_bad_header(self):
        response = self.app_client.get('/endpoint',
                                       headers={'Authorization' : 't'}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Bad Authorization header. Expected value \'Bearer <JWT>\''}, json.loads(response.data))

    def test_bad_token(self):
        bad_token = jwt.encode({'some': 'payload'}, 'bad_secret')
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Signature verification failed'}, json.loads(response.data))

    def test_expired_token(self):
        bad_token = jwt.encode({'some': 'payload', 'exp': '20180101', 'iat': '20181231'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 401)
        self.assertEqual({'error_message': 'Token has expired'}, json.loads(response.data))

    def test_not_yet_token(self):
        not_before = timegm(datetime.utcnow().utctimetuple())*2
        bad_token = jwt.encode({'some': 'payload', 'iat': '20181231', 'nbf': not_before}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'The token is not yet valid (nbf)'}, json.loads(response.data))

    def test_invalid_issued_at(self):
        bad_token = jwt.encode({'some': 'payload', 'iat': 'test'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Issued At claim (iat) must be an integer.'}, json.loads(response.data))

    def test_invalid_not_before(self):
        bad_token = jwt.encode({'some': 'payload', 'nbf': 'test'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Not Before claim (nbf) must be an integer.'}, json.loads(response.data))

    def test_invalid_expires(self):
        bad_token = jwt.encode({'some': 'payload', 'exp': 'test'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Expiration Time claim (exp) must be an integer.'}, json.loads(response.data))

    def test_invalid_audience(self):
        self.application.config['JWT_DECODE_AUDIENCE'] = 'valid'
        bad_token = jwt.encode({'some': 'payload', 'aud': 'invalid'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Invalid audience'}, json.loads(response.data))

    def test_missing_claim(self):
        self.application.config['JWT_DECODE_AUDIENCE'] = 'valid'
        bad_token = jwt.encode({'some': 'payload'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization': 'Bearer {0}'.format(bad_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 422)
        self.assertEqual({'error_message': 'Token is missing the "aud" claim'}, json.loads(response.data))

    def test_good_token(self):
        good_token = jwt.encode({'some': 'payload'}, self.application.config['JWT_SECRET_KEY'])
        response = self.app_client.get('/endpoint',
                                        headers={'Authorization' : 'Bearer {0}'.format(good_token.decode('utf-8'))}
                                    )
        self.assertEqual(response.status_code, 200)