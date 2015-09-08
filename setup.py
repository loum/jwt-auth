from setuptools import setup

VERSION = '0.0.0'

DEPENDENCIES = [
    'Django==1.8.2',
    'django-dynamic-fixture==1.8.4',
    'django-nose',
    'djangorestframework==3.1.2',
    'djangorestframework-jwt==1.2.0',
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
