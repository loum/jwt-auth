import jwt
from rest_framework_jwt.settings import api_settings


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

    if isinstance(api_settings.JWT_SECRET_KEY, dict):
        keys = [
            api_settings.JWT_SECRET_KEY['SECRET_KEY'],
            api_settings.JWT_SECRET_KEY['PUBLIC_KEY']
        ]
    else:
        keys = [api_settings.JWT_SECRET_KEY]

    try:
        for key in keys:
            kwargs['key'] = key
            try:
                decoded = jwt.decode(token, **kwargs)
            except ValueError:
                continue
            break
    except jwt.exceptions.DecodeError:
        decoded = None

    return decoded

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
