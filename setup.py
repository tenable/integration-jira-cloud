from setuptools import setup, find_packages
import os

long_description = '''
Tenable -> Jira Cloud Bridge
For usage documentation, please refer to the github repository at
https://github.com/tenable/integrations-jira-cloud
'''

setup(
    name='tenable-jira-cloud',
    version='1.1.19',
    description='Tenable -> Jira Cloud Bridge',
    author='Tenable, Inc.',
    long_description=long_description,
    author_email='smcgrath@tenable.com',
    url='https://github.com/tenable/integrations-jira-cloud',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: System :: Networking',
        'Topic :: Other/Nonlisted Topic',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='tenable tenable_io ibm jira',
    packages=find_packages(exclude=['tests']),
    install_requires=[
        'pytenable>=1.2.3',
        'restfly>=1.1.0',
        'arrow>=0.13.0',
        'Click>=7.0',
        'pyyaml>=5.1.2'
    ],
    entry_points={
        'console_scripts': [
            'tenable-jira=tenable_jira.cli:cli',
        ],
    },
)