from setuptools import setup

VERSION = '0.0.0'

DEPENDENCIES = [
    'Django==1.8.4',
    'cryptography==1.0.1',
    'django-dynamic-fixture==1.8.5',
    'django-nose',
    'djangorestframework==3.2.3',
    'djangorestframework-jwt==1.7.2',
]


kwargs = {
    'name': 'jwt-auth',
    'version': VERSION,
    'description': 'JWT Authorisation',
    'author': 'Lou Markovski',
    'author_email': 'lou.markovski@gmail.com',
    'url': '',
    'install_requires': DEPENDENCIES,
}
setup(**kwargs)
