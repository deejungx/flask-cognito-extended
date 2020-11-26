"""
Flask-Cognito-Extended
-------------

Flask-Cognito-Extended is a Flask implementation of Amazon Cognito.
"""
import io
import re
from setuptools import setup

with io.open('flask_cognito_extended/__init__.py', encoding='utf-8') as f:
    version = re.search(r"__version__ = '(.+)'", f.read()).group(1)

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name='Flask-Cognito-Extended',
    version=version,
    url='https://github.com/deejungx/flask-cognito-extended',
    license='MIT',
    author='Dipesh Jung Pandey',
    author_email='dipzz1394@gmail.com',
    description='Extended Cognito integration with Flask',
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=['flask', 'amazon cognito', 'json web token'],
    packages=['flask_cognito_extended'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'Flask>=1.0,<2.0',
        'python-jose[cryptography]>=3.1.0',
        'PyJWT>=1.7,<2.0',
        'requests>=2.9.1,<3.0.0'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Version Control :: Git',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
    ]
)