import django.test
from rest_framework_jwt import utils
from rest_framework_jwt.settings import api_settings

import auth.jwt.utils
import auth.tests.fixtures as fixtures


class TestUtils(django.test.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TestUtils, cls).setUpClass()

        cls.__model_user = fixtures.load_auth_users()

    def test_jwt_decode(self):
        """Decode a JWT token: SECRET KEY.
        """
        # Given a payload
        payload = utils.jwt_payload_handler(self.__model_user)

        # when I embed in a JWT
        token = utils.jwt_encode_handler(payload)

        # then the JWT should decode successfully
        received = auth.jwt.utils.jwt_decode_handler(token)
        expected = payload
        msg = 'SECRET KEY signed JWT did not decode correctly'
        self.assertEqual(received, expected, msg)

    def test_jwt_decode_verify_exp(self):
        """Decode a JWT token; SECRET KEY and expiry.
        """
        # Given that the expiry JWT token flag is not set
        api_settings.JWT_VERIFY_EXPIRATION = False

        # and an "expired" JWT
        payload = utils.jwt_payload_handler(self.__model_user)
        payload['exp'] = 1

        # when I embed the payload into a JWT
        token = utils.jwt_encode_handler(payload)

        # then the JWT should decode successfully
        received = auth.jwt.utils.jwt_decode_handler(token)
        expected = payload
        msg = 'SECRET KEY signed (expired) JWT did not decode correctly'
        self.assertEqual(received, expected, msg)

        # Clean up.
        api_settings.JWT_VERIFY_EXPIRATION = True
