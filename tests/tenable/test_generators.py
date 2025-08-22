from uuid import UUID

import arrow
import pytest
import responses
from tenable.io import TenableIO
from tenable.io.exports.iterator import ExportsIterator
from tenable.sc.analysis import AnalysisResultsIterator

from tenb2jira.tenable.generators import (
    tsc_merged_data,
    tvm_asset_cleanup,
    tvm_merged_data,
)


def test_tvm_asset_cleanup(tvm_assets):
    asset_iter = ExportsIterator(None)
    asset_iter.page = tvm_assets
    asset_generator = tvm_asset_cleanup(asset_iter)
    asset = next(asset_generator)
    assert asset == tvm_assets[0]


@responses.activate
def test_tvm_merged_data(tvm_generator):
    responses.get(
        "https://cloud.tenable.com/assets/export/0/status",
        json={"status": "FINISHED", "available_chunks": []},
    )
    pmoddate = arrow.get("2020-04-27T00:00:00Z")
    test_uuid = UUID("dd13a88d-2fbf-3d2a-930f-38fdc850f86d")
    finding = next(tvm_generator)
    assert finding["asset.uuid"] == "7f68f334-17ba-4ba0-b057-b77ddd783e60"
    assert finding["asset.tags"] == ["Location:Illinois", "Test_Value:Something"]
    assert finding["integration_finding_id"] == test_uuid
    assert finding["integration_pid_updated"] == pmoddate
    assert finding["asset.test"] == "value"


@responses.activate
def test_tvm_merged_data_accepted(tvm_assets, tvm_finding):
    pmoddate = arrow.get("2020-04-27T00:00:00Z")
    test_uuid = UUID("dd13a88d-2fbf-3d2a-930f-38fdc850f86d")
    responses.get(
        "https://cloud.tenable.com/assets/export/0/status",
        json={"status": "FINISHED", "available_chunks": []},
    )
    tvm = TenableIO(access_key="None", secret_key="None")
    asset_iter = ExportsIterator(tvm)
    asset_iter.uuid = 0
    asset_iter.type = "assets"
    asset_iter.page = tvm_assets
    asset_iter.version = None
    tvm_finding["severity_modification_type"] = "ACCEPTED"
    finding_iter = ExportsIterator(tvm)
    finding_iter.version = None
    finding_iter.page = [tvm_finding for _ in range(100)]
    tvm_generator = tvm_merged_data(
        assets_iter=asset_iter,
        vulns_iter=finding_iter,
        close_accepted=True,
    )
    finding = next(tvm_generator)
    assert finding["state"] == "FIXED"
    assert finding["asset.uuid"] == "7f68f334-17ba-4ba0-b057-b77ddd783e60"
    assert finding["integration_finding_id"] == test_uuid
    assert finding["integration_pid_updated"] == pmoddate


def test_tsc_merged_data(tsc_finding):
    test_uuid = UUID("d90cdab5-b745-3e7e-9268-aa0f445ed924")
    fuuid = UUID("bd371510-001f-3c13-86f4-20883ef0cd09")
    findings = AnalysisResultsIterator(None)
    findings.page = [tsc_finding for _ in range(100)]
    findings._query = {"sourceType": "cumulative"}
    tsc_generator = tsc_merged_data(findings)
    finding = next(tsc_generator)
    assert finding["asset.uuid"] == test_uuid
    assert finding["integration_finding_id"] == fuuid
    assert finding["integration_state"] == "open"

    tsc_finding["hasBeenMitigated"] = "1"
    findings = AnalysisResultsIterator(None)
    findings.page = [tsc_finding for _ in range(100)]
    findings._query = {"sourceType": "cumulative"}
    tsc_generator = tsc_merged_data(findings)
    finding = next(tsc_generator)
    assert finding["integration_state"] == "reopened"

    findings = AnalysisResultsIterator(None)
    findings._query = {"sourceType": "patched"}
    findings.page = [tsc_finding for _ in range(100)]
    tsc_generator = tsc_merged_data(findings)
    finding = next(tsc_generator)
    assert finding["integration_state"] == "fixed"

    tsc_finding["acceptRisk"] = "1"
    findings = AnalysisResultsIterator(None)
    findings.page = [tsc_finding for _ in range(100)]
    findings._query = {"sourceType": "cumulative"}
    tsc_generator = tsc_merged_data(findings)
    finding = next(tsc_generator)
    assert finding["integration_state"] == "fixed"


def test_tsc_merged_data_empty_dates(tsc_finding):
    tsc_finding["pluginModDate"] = ""
    findings = AnalysisResultsIterator(None)
    findings._query = {"sourceType": "cumulative"}
    findings.page = [tsc_finding for _ in range(100)]
    tsc_generator = tsc_merged_data(findings)
    finding = next(tsc_generator)
    assert finding["integration_pid_updated"] == arrow.get(0)
