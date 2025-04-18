from setuptools import setup

setup(
    name='pryzma',
    version='5.7',
    py_modules=['Pryzma'],
    entry_points={
        'console_scripts': [
            'pryzma=Pryzma:main',
        ],
    },
    install_requires=[
        'keystone-engine',
        'unicorn',
        'requests',
    ],
)
