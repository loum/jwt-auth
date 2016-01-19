import re
import sys
import jwt
import xml.etree.ElementTree
from importlib import import_module
from rest_framework_jwt.settings import api_settings
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import urllib.request
import datetime

import auth.settings


def jwt_decode_handler(token):
    """Override the :func:`pyjwt.jwt.utils.jwt_decode_handler` function
    as of v 1.4.0 it only supports SECRET_KEY encoding/decoding.  See
    `PyJWT enhancement
    <https://github.com/GetBlimp/django-rest-framework-jwt/issues/136>`_
    for more information.

    """
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }

    kwargs = {
        'key': None,
        'verify': api_settings.JWT_VERIFY,
        'algorithms': [api_settings.JWT_ALGORITHM, 'RS256'],
        'options': options,
        'leeway': api_settings.JWT_LEEWAY,
        'audience': api_settings.JWT_AUDIENCE,
        'issuer': api_settings.JWT_ISSUER,
    }

    for loop_counter in range(2):
        if auth.settings.KEY_CACHE.get('last_update') is None:
            if isinstance(api_settings.JWT_SECRET_KEY, dict):
                keys = build_keys()
            else:
                keys = [api_settings.JWT_SECRET_KEY]
            auth.settings.KEY_CACHE['keys'].extend(keys)
            auth.settings.KEY_CACHE['last_update'] = datetime.datetime.now()

        # Note: order is important here as our symmetric signed JWTs
        # do not have a "aud" claim.
        decoded = None
        secret_token_check = True
        old_aud = api_settings.JWT_AUDIENCE
        for key in auth.settings.KEY_CACHE.get('keys'):
            if secret_token_check:
                secret_token_check = False
                kwargs['audience'] = None

            kwargs['key'] = key
            try:
                decoded = jwt.decode(token, **kwargs)
                break
            except (ValueError,
                    TypeError,
                    jwt.exceptions.DecodeError,
                    jwt.exceptions.MissingRequiredClaimError) as err:
                kwargs['audience'] = old_aud
                continue

        if loop_counter == 0 and decoded is None:
            last_update = auth.settings.KEY_CACHE['last_update']
            now = datetime.datetime.now()
            gap = now - last_update
            mins, secs = divmod(gap.days * 86400 + gap.seconds, 60)
            seconds_passed = mins * 60 + secs

            # Force refresh cache.
            if seconds_passed > auth.settings.KEY_CACHE['expiry_seconds']:
                auth.settings.KEY_CACHE['last_update'] = None
        else:
            break

    if decoded == None:
        raise jwt.exceptions.DecodeError('Signature verification failed')

    return decoded


def build_keys():
    """Cater for the overridden scenario where
    :attr:`auth.settings.JWT_AUTH['JWT_SECRET_KEY'] is a
    dictionary that supports both ``SECRET_KEY`` and
    ``PUBLIC_KEY`` for combined symmetric and asymmetric signing.
    For example::

        JWT_AUTH = {
            ...
            'JWT_SECRET_KEY': {
                'SECRET_KEY': SECRET_KEY,
                'PUBLIC_KEY': 'auth.jwt.utils.source_certs',
            },
        }

    In this case, both ``SECRET_KEY`` and ``PUBLIC_KEY`` values
    will be combined into a single list.

    """
    keys = [api_settings.JWT_SECRET_KEY['SECRET_KEY']]

    public_keys = []
    public_key_source = api_settings.JWT_SECRET_KEY.get('PUBLIC_KEY')
    if public_key_source is not None:
        public_key_source_parts = public_key_source.rsplit('.', 1)
        if globals().get(public_key_source_parts[1]):
            public_keys = getattr(sys.modules[__name__],
                                  public_key_source_parts[1])
        else:
            public_keys = getattr(import_module(public_key_source_parts[0]),
                                  public_key_source_parts[1])
        cert_kwargs = {
            'file_certs': auth.settings.CERT_FILES,
            'federation_meta_uri':
                auth.settings.AZURE_AD['FEDERATION_METADATA'],
        }
        keys.extend(public_keys(**cert_kwargs))

    return keys


def jwt_encode_handler(payload):
    key = None
    if isinstance(api_settings.JWT_SECRET_KEY, dict):
        key = api_settings.JWT_SECRET_KEY['SECRET_KEY']
    else:
        key = api_settings.JWT_SECRET_KEY
    return jwt.encode(
        payload,
        key,
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def source_certs(file_certs=None, federation_meta_uri=None):
    """Get all certificates associated with asymmetrical JWT verification.

    Certs can come from two locations:
    - local file system (self-signed certificates)
    - URI based (Azure Federation Metadata)

    """
    certs = []

    if file_certs is None:
        file_certs = []

    for file_cert in file_certs:
        with open(file_cert) as _fh:
            cert_str = _fh.read().strip()
        cert_obj = load_pem_x509_certificate(cert_str.encode('UTF-8'),
                                             default_backend())

        if cert_obj is not None:
            certs.append(cert_obj.public_key())

    if federation_meta_uri is not None:
        azure_certs = []
        data = get_federation_metadata(federation_meta_uri)
        if data is not None:
            azure_certs = get_federation_metadata_certs(data)
            if len(azure_certs):
                certs.extend(azure_certs)

    return certs


def jwt_get_username_from_payload_handler(payload):
    """Override :func:`rest_framework_jwt.utils` function as username
    for Azure AD is formatted differently in payload ("appid")

    """
    username = None
    if payload.get('username') is not None:
        username = payload.get('username')
    else:
        username = payload.get('appid')[:30]

    return username


def get_federation_metadata(uri):
    """Obtain Azure AD Federation Metadata from URI.

    """
    data = None

    response = urllib.request.urlopen(uri)
    if response.status == 200:
        data = response.read()

    return data


def get_federation_metadata_certs(data):
    """Extract the Federation Metadata certs and return as list.

    """
    root = xml.etree.ElementTree.fromstring(data)
    match = ('./metadata:RoleDescriptor/'
             'metadata:KeyDescriptor/'
             'dig_sig:KeyInfo/'
             'dig_sig:X509Data/'
             'dig_sig:X509Certificate')
    ns = {
        'metadata': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'dig_sig': 'http://www.w3.org/2000/09/xmldsig#',
    }
    cert_elements = root.findall(match, ns)
    cert_strings = [construct_cert(x) for x in cert_elements]

    certs = []
    for cert_str in cert_strings:
        cert_obj = load_pem_x509_certificate(cert_str.encode('UTF-8'),
                                             default_backend())
        certs.append(cert_obj.public_key())

    return certs


def construct_cert(x):
    begin_token = '-----BEGIN CERTIFICATE-----'
    end_token = '-----END CERTIFICATE-----'

    cert_text = re.sub('(.{64})', '\\1\n', x.text, 0, re.DOTALL)

    return '{}\n{}\n{}'.format(begin_token, cert_text, end_token)
