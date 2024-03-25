# test_app.py
import unittest
from unittest import mock
import json
from project2 import app, create_connection, create_table, insert_keys, delete_all_rows



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

class Test_insert_rows(unittest.TestCase):
    def setUp(self):                                # Set up a temporary SQLite database for testing
        self.db_file = ":memory:"
        self.conn = create_connection(self.db_file)
        create_table(self.conn)

    def tearDown(self):                             # Close the database connection and perform cleanup
        self.conn.close()

    def test_insert_and_retrieve_keys(self):        # Test insertion and retrieval of keys in the database
        key1 = b'private_key_1'
        kid1 = insert_keys(self.conn, (1111, key1, 1234567890))
        cursor = self.conn.cursor()
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM keys WHERE kid=?", (kid1,))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], kid1)
        self.assertEqual(row[1], key1)

    def test_delete_all_rows(self):
        # Test deletion of all rows from the keys table
        key = b'private_key'

        # Insert a key into the database
        kid = insert_keys(self.conn, (1111, key, 1234567890))

        # Delete all rows from the table
        delete_all_rows(self.conn)

        # Try to retrieve the key, it should not exist
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM keys WHERE kid=?", (kid,))
        row = cursor.fetchone()
        self.assertIsNone(row)

if __name__ == '__main__':
    unittest.main()
