# test_app.py
import unittest
import json
from project1 import app


class TestJWTGeneration(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_generate_token_valid(self):                # Checks that a valid jwt token generation attempt returns a 200 http status code -- Could use further testing for actual token
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
    
    def test_generate_token_expired(self):              # Checks that an expired jwt token generation attempt returns a 401 http status code-- Could use further testing for actual token
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 401)

    def test_jwk_ret(self):
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
    


if __name__ == '__main__':
    unittest.main()