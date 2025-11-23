from setuptools import setup

setup(
    name='pryzma',
    version='6.1',
    py_modules=['Pryzma'],
    entry_points={
        'console_scripts': [
            'pryzma=Pryzma:main',
        ],
    },
    install_requires=[
        'keystone-engine',
        'requests',
    ],
)
