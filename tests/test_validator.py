import pytest

from tenb2jira.validator import Configuration, validate


def test_validator(example_config):
    assert validate(example_config) == []


def test_validator_optionals(example_config):
    example_config["tenable"]["vpr_score"] = 6.1
    example_config["jira"]["screens"] = [1, 2]
    assert validate(example_config) == []


def test_validator_error(example_config):
    del example_config["tenable"]["platform"]
    errs = validate(example_config)
    assert isinstance(errs, list) and len(errs) == 1
    err = errs[0]
    assert err["input"] == example_config["tenable"]
    assert err["loc"] == ("tenable", "platform")
    assert err["msg"] == "Field required"
    assert err["type"] == "missing"
