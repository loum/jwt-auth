import mock as mock
import django.test
import os
from rest_framework_jwt import utils
from rest_framework_jwt.settings import api_settings
import jwt.exceptions
import cryptography.hazmat.backends.openssl.rsa as rsa

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
        token = auth.jwt.utils.jwt_encode_handler(payload)

        # then the JWT should decode successfully
        received = auth.jwt.utils.jwt_decode_handler(token)
        expected = payload
        msg = 'SECRET KEY signed JWT did not decode correctly'
        self.assertEqual(received, expected, msg)

    def test_jwt_decode_asymmetric(self):
        """Decode a JWT token: certificate based.
        """
        # Given a payload
        payload = utils.jwt_payload_handler(self.__model_user)

        # when I embed in a JWT
        old_secret_key = api_settings.JWT_SECRET_KEY.get('SECRET_KEY')
        old_jwt_algorithm = api_settings.JWT_ALGORITHM
        api_settings.JWT_ALGORITHM = 'RS256'
        with open(os.path.join('auth',
                               'tests',
                               'files',
                               'rsakey.pem')) as _fh:
            api_settings.JWT_SECRET_KEY['SECRET_KEY'] = _fh.read().strip()
        token = auth.jwt.utils.jwt_encode_handler(payload)
        api_settings.JWT_SECRET_KEY['SECRET_KEY'] = old_secret_key
        api_settings.JWT_ALGORITHM = old_jwt_algorithm

        # then the JWT should decode successfully
        old_public_keys = api_settings.JWT_SECRET_KEY.get('PUBLIC_KEY')
        old_verify = api_settings.JWT_VERIFY_EXPIRATION
        api_settings.JWT_VERIFY_EXPIRATION = False
        api_settings.JWT_SECRET_KEY['PUBLIC_KEY'] = 'auth.jwt.utils.source_certs'
        received = auth.jwt.utils.jwt_decode_handler(token)
        expected = payload
        msg = 'Asymmetric signed JWT did not decode correctly'
        self.assertEqual(received, expected, msg)

        # Clean up.
        api_settings.JWT_SECRET_KEY['PUBLIC_KEY'] = old_public_keys
        api_settings.JWT_VERIFY_EXPIRATION = old_verify

    def test_jwt_decode_incorrectly_signed_payload(self):
        """Decode a JWT token: incorrectly signed payload.
        """
        # Given a payload
        payload = utils.jwt_payload_handler(self.__model_user)

        # when I embed in a JWT with a different SECRET KEY
        old_secret = api_settings.JWT_SECRET_KEY
        api_settings.JWT_SECRET_KEY = 'banana'
        token = auth.jwt.utils.jwt_encode_handler(payload)
        api_settings.JWT_SECRET_KEY = old_secret

        # then the JWT should not decode
        self.assertRaisesRegex(jwt.exceptions.DecodeError,
                               'Signature verification failed',
                               auth.jwt.utils.jwt_decode_handler,
                               token)

    def test_jwt_decode_verify_exp(self):
        """Decode a JWT token; SECRET KEY and expiry.
        """
        # Given that the expiry JWT token flag is not set
        api_settings.JWT_VERIFY_EXPIRATION = False

        # and an "expired" JWT
        payload = utils.jwt_payload_handler(self.__model_user)
        payload['exp'] = 1

        # when I embed the payload into a JWT
        token = auth.jwt.utils.jwt_encode_handler(payload)

        # then the JWT should decode successfully
        received = auth.jwt.utils.jwt_decode_handler(token)
        expected = payload
        msg = 'SECRET KEY signed (expired) JWT did not decode correctly'
        self.assertEqual(received, expected, msg)

        # Clean up.
        api_settings.JWT_VERIFY_EXPIRATION = True

    def test_source_certs(self):
        """Source list of certs.
        """
        # Given a file based cert file
        file_certs = [
            os.path.join('auth', 'tests', 'files', 'rsacert.pem'),
        ]

        # when I attempt to source all configured certs
        kwargs = {
            'file_certs': file_certs,
            'federation_meta_uri': None,
        }
        received = auth.jwt.utils.source_certs(**kwargs)

        # then I should receive a list of certs
        msg = 'Certs list error'
        self.assertEqual(len(received), 1, msg)

    @mock.patch('auth.jwt.utils.get_federation_metadata')
    def test_source_certs_federation_meta(self, mock_fed_meta):
        """Source list of certs: Federation Metadata.
        """
        # Given an Azure AD Federation Metadata URI
        uri = 'https://login.microsoftonline.com/federationmetadata.xml'

        # when I attempt to source all configured certs
        kwargs = {
            'file_certs': None,
            'federation_meta_uri': uri,
        }
        fed_meta_filename = os.path.join('auth',
                                         'tests',
                                         'files',
                                         'federation_metadata.raw')
        with open(fed_meta_filename, 'rb') as _fh:
            fed_meta = _fh.read().strip()
        mock_fed_meta.return_value = fed_meta
        received = auth.jwt.utils.source_certs(**kwargs)

        # then I should receive a list of certs
        msg = 'Certs list error (Azure Federation Metadata)'
        self.assertEqual(len(received), 2, msg)

    @mock.patch('auth.jwt.utils.get_federation_metadata')
    def test_source_certs_all_sources(self, mock_fed_meta):
        """Source list of certs: Federation Metadata and file based certs.
        """
        # Given an Azure AD Federation Metadata URI
        uri = 'https://login.microsoftonline.com/federationmetadata.xml'

        # and a list of file based cert files
        file_certs = [
            os.path.join('auth', 'tests', 'files', 'rsacert.pem'),
        ]

        # when I attempt to source all configured certs
        kwargs = {
            'file_certs': file_certs,
            'federation_meta_uri': uri,
        }
        fed_meta_filename = os.path.join('auth',
                                         'tests',
                                         'files',
                                         'federation_metadata.raw')
        with open(fed_meta_filename, 'rb') as _fh:
            fed_meta = _fh.read().strip()
        mock_fed_meta.return_value = fed_meta
        received = auth.jwt.utils.source_certs(**kwargs)

        # then I should receive a list of certs
        msg = 'Certs list error (all certs)'
        self.assertEqual(len(received), 3, msg)

    def test_get_federation_metadata_certs(self):
        """Get an Azure AD Federation Metadata data
        """
        # Given an Azure AD Federation Metadata URI
        uri = 'https://login.microsoftonline.com/federationmetadata.xml'

        # when I source the Federation Metadata certs
        fed_meta_filename = os.path.join('auth',
                                         'tests',
                                         'files',
                                         'federation_metadata.raw')
        with open(fed_meta_filename, 'rb') as _fh:
            fed_meta = _fh.read().decode('utf-8')
        certs = auth.jwt.utils.get_federation_metadata_certs(fed_meta)
        received = [isinstance(x, rsa._RSAPublicKey) for x in certs]

        # I should receive a list with 2 _RSAPublicKey elements
        expected = [True, True]
        msg = 'Azure certs not of form _RSAPublicKey'
        self.assertListEqual(received, [True, True], msg)
