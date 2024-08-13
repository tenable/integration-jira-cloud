import pytest
from tenb2jira.validator import validate, Configuration


def test_validator(example_config):
    assert validate(example_config) == []


def test_validator_optionals(example_config):
    example_config['tenable']['vpr_score'] = 6.1
    example_config['jira']['screens'] = [1, 2]
    assert validate(example_config) == []

def test_validator_error(example_config):
    del(example_config['tenable']['platform'])
    assert validate(example_config) == [{
        'input': example_config['tenable'],
        'loc': ('tenable', 'platform'),
        'msg': 'Field required',
        'type': 'missing',
        'url': 'https://errors.pydantic.dev/2.7/v/missing'
    }]
