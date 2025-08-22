from typing import Generator

import arrow
import pytest
import responses
from responses.matchers import json_params_matcher
from tenable.io import TenableIO
from tenable.sc import TenableSC

from tenb2jira.tenable.tenable import Tenable


@pytest.fixture
def tvm_config():
    return {
        "tenable": {
            "platform": "tvm",
            "vuln_age": 30,
            "severities": ["medium", "high", "critical"],
            "tvm_chunk_size": 1000,
            "tsc_page_size": 1000,
            "access_key": "abcdef",
            "secret_key": "12345",
            "url": "https://nourl",
        }
    }


@pytest.fixture
def tsc_config():
    return {
        "tenable": {
            "platform": "tsc",
            "vuln_age": 30,
            "severities": ["medium", "high", "critical"],
            "tvm_chunk_size": 1000,
            "tsc_query_id": 1,
            "tsc_page_size": 1000,
            "access_key": "abcdef",
            "secret_key": "12345",
            "url": "https://nourl",
            "last_run": 12345,
        }
    }


@pytest.fixture
def tvm(tvm_config):
    return Tenable(tvm_config)


@pytest.fixture
@responses.activate
def tsc(tsc_config):
    responses.get(
        "https://nourl/rest/system", json={"response": {}, "error_code": None}
    )
    return Tenable(tsc_config)


def test_tvm_config(tvm):
    assert tvm.platform == "tvm"
    assert isinstance(tvm.tvm, TenableIO)
    assert tvm.age == 30
    assert tvm.severity == ["medium", "high", "critical"]
    assert tvm.chunk_size == 1000
    assert tvm.timestamp == int(arrow.now().shift(days=-30).floor("day").timestamp())


def test_tsc_config(tsc):
    assert tsc.platform == "tsc"
    assert isinstance(tsc.tsc, TenableSC)
    assert tsc.age == 30
    assert tsc.severity == ["medium", "high", "critical"]
    assert tsc.page_size == 1000
    assert tsc.timestamp == 12345
    assert tsc.query_id == 1


@responses.activate
def test_get_asset_cleanup(tsc, tvm):
    responses.post("https://nourl/assets/export", json={"export_uuid": 0})
    assert isinstance(tvm.get_asset_cleanup(), Generator)
    assert tsc.get_asset_cleanup() == []


@responses.activate
def test_get_generator(tvm, tsc):
    responses.post("https://nourl/assets/export", json={"export_uuid": 0})
    responses.post("https://nourl/vulns/export", json={"export_uuid": 0})
    assert isinstance(tvm.get_generator(arrow.now()), Generator)

    responses.get(
        "https://nourl/rest/query/1?fields=filters",
        json={"response": {"query": {"filters": []}}, "error_code": None},
    )
    responses.post(
        "https://nourl/rest/analysis", json={"response": {}, "error_code": None}
    )
    assert isinstance(tsc.get_generator(arrow.now()), Generator)


@responses.activate
def test_get_tvm_generator(tvm):
    last_run = int(arrow.now().shift(days=-30).floor("day").timestamp())
    responses.post("https://nourl/assets/export", json={"export_uuid": 0})
    responses.post(
        "https://nourl/vulns/export",
        json={"export_uuid": 0},
        match=[
            json_params_matcher(
                {
                    "filters": {
                        "since": last_run,
                        "severity": ["medium", "high", "critical"],
                        "state": ["OPEN", "REOPENED", "FIXED"],
                        "vpr_score": {"gte": 6.1},
                    },
                    "include_unlicensed": True,
                    "num_assets": 1000,
                }
            )
        ],
    )
    tvm.vpr_score = 6.1
    assert isinstance(tvm.get_tvm_generator(), Generator)


@responses.activate
def test_get_tsc_generator(tsc, tsc_finding):
    now = int(arrow.now().timestamp())
    responses.get(
        "https://nourl/rest/query/1?fields=filters",
        json={"response": {"query": {"filters": []}}, "error_code": None},
    )
    responses.post(
        "https://nourl/rest/analysis",
        json={"response": {"results": [tsc_finding]}, "error_code": None},
        match=[
            json_params_matcher(
                {
                    "sourceType": "cumulative",
                    "type": "vuln",
                    "query": {
                        "type": "vuln",
                        "tool": "vulndetails",
                        "startOffset": 0,
                        "endOffset": 1000,
                        "filters": [
                            {
                                "filterName": "severity",
                                "operator": "=",
                                "value": "2,3,4",
                            },
                            {
                                "filterName": "vprScore",
                                "operator": "=",
                                "value": "6.1-10",
                            },
                            {
                                "filterName": "lastSeen",
                                "operator": "=",
                                "value": f"{tsc.timestamp}-{now}",
                            },
                            {
                                "filterName": "wasVuln",
                                "operator": "=",
                                "value": "excludeWas",
                            },
                        ],
                    },
                }
            )
        ],
    )
    tsc.vpr_score = 6.1
    generator = tsc.get_tsc_generator(now)
    assert isinstance(generator, Generator)
    next(generator)
