import django.test
import json
import rest_framework

import auth.tests.fixtures as fixtures


class TestViews(django.test.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TestViews, cls).setUpClass()

        fixtures.load_auth_users()

    def setUp(self):
        self.client = django.test.Client()

    def test_obtain_auth_via_post_missing_user(self):
        """URL route to enable obtaining a token via a POST: missing user.
        """
        # Given a Django user name and password
        kwargs = {
            'username': 'no_user',
            'password': 'no_password',
        }

        # when I POST to obtain a token
        url = '/api-token-auth/'
        response = self.client.post(url, kwargs)

        # Then I should receive a 400_BAD_REQUEST error message
        received = response.status_code
        expected = rest_framework.status.HTTP_400_BAD_REQUEST
        msg = 'URL route to obtain token incorrect status code'
        self.assertEqual(received, expected, msg)

        # and an alert response message
        response_str = response.content.decode('utf-8')
        received = json.loads(response_str)
        expected = ['Unable to login with provided credentials.']
        msg = 'URL route to obtain token incorrect content'
        self.assertListEqual(received.get('non_field_errors'),
                             expected,
                             msg)

    def test_obtain_auth_via_post(self):
        """URL route to enable obtaining a token via a POST.
        """
        # Given a Django user name and password
        kwargs = {
            'username': 'lupco',
            'password': 'lupco'
        }

        # then when I attempt to login
        received = self.client.login(username='lupco', password='lupco')

        # I should receive success
        msg = 'User login error'
        self.assertTrue(received, msg)

        # when I POST to obtain a token
        url = '/api-token-auth/'
        response = self.client.post(url, kwargs)

        # then I should receive a 200_OK response code
        received = response.status_code
        expected = rest_framework.status.HTTP_200_OK
        msg = 'URL route to obtain token incorrect status code'
        self.assertEqual(received, expected, msg)

        # and an alert response message
        response_str = response.content.decode('utf-8')
        received = json.loads(response_str)
        msg = 'URL route to obtain token did not produce token'
        self.assertIsNotNone(received.get('token'), msg)

    def test_verify_auth_via_post(self):
        """URL route to enable obtaining a token via a POST.
        """
        # Given a HS256 cryptographically signed JWT
        kwargs = {
            'username': 'lupco',
            'password': 'lupco'
        }
        url = '/api-token-auth/'
        response = self.client.post(url, kwargs)
        jwt_token_str = response.content.decode('utf-8')
        jwt_token = json.loads(jwt_token_str)

        # when I POST to verify the token
        url = '/api-token-verify/'
        headers = {'Content-Type': 'application/json'}
        response = self.client.post(url, data=jwt_token, **headers)

        # then I should receive a 200_OK response code
        received = response.status_code
        expected = rest_framework.status.HTTP_200_OK
        msg = 'URL route to verify token incorrect status code'
        self.assertEqual(received, expected, msg)

        # and the content (token) should also match
        received = response.content.decode('utf-8')
        expected = jwt_token_str
        msg = 'URL route to verify token incorrect content'
        self.assertEqual(received, expected, msg)

    def test_protected_url(self):
        """Call to the protected URL.
        """
        # Given a HS256 cryptographically signed JWT
        kwargs = {
            'username': 'lupco',
            'password': 'lupco'
        }
        url = '/api-token-auth/'
        response = self.client.post(url, kwargs)
        jwt_token_str = response.content.decode('utf-8')
        jwt_token = json.loads(jwt_token_str)

        # when I GET to the protected URL
        auth_headers = {
            'HTTP_AUTHORIZATION':
                'JWT {}'.format(jwt_token.get('token')),
        }
        url = '/protected-url'
        response = self.client.get(url, data=None, **auth_headers)

        # then I should receive a 200_OK response code
        received = response.status_code
        expected = rest_framework.status.HTTP_200_OK
        msg = 'URL route to protected-url incorrect status code'
        self.assertEqual(received, expected, msg)

        # and the content should also match
        received = response.content.decode('utf-8')
        expected = '{"message":"This is a protected URL"}'
        msg = 'URL route to protected URL content error'
        self.assertEqual(received, expected, msg)

    def tearDown(self):
        self.client = None
