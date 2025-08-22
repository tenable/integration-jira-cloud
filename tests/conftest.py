import pytest
import responses
import tomlkit
from tenable.io import TenableIO
from tenable.io.exports.iterator import ExportsIterator
from tenable.sc.analysis import AnalysisResultsIterator

from tenb2jira.tenable.generators import (
    tsc_merged_data,
    tvm_merged_data,
)


@pytest.fixture
def example_config():
    with open("tests/test_config.toml", "r", encoding="utf-8") as fobj:
        conf = tomlkit.load(fobj)
    return conf


@pytest.fixture
def tvm_assets():
    return [
        {
            "id": "7f68f334-17ba-4ba0-b057-b77ddd783e60",
            "tags": [
                {
                    "key": "Location",
                    "value": "Illinois",
                },
                {"key": "Test Value", "value": "Something"},
            ],
            "ipv4s": ["192.168.0.1", "192.168.0.2"],
            "ipv6s": [
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            ],
            "test": "value",
        }
    ]


@pytest.fixture
def tvm_finding():
    return {
        "asset": {
            "device_type": "undetermined",
            "fqdn": "hostname.fqdn",
            "hostname": "hostname",
            "uuid": "7f68f334-17ba-4ba0-b057-b77ddd783e60",
            "ipv4": "192.168.0.1",
            "network_id": "00000000-0000-0000-0000-000000000000",
            "tracked": True,
        },
        "output": "output",
        "plugin": {
            "id": 51192,
            "name": "SSL Certificate Cannot Be Trusted",
            "modification_date": "2020-04-27T00:00:00Z",
            "publication_date": "2010-12-15T00:00:00Z",
            "risk_factor": "medium",
            "description": "description",
            "see_also": [
                "https://www.itu.int/rec/T-REC-X.509/en",
                "https://en.wikipedia.org/wiki/X.509",
            ],
            "solution": "solution",
            "synopsis": "synopsis",
            "cvss3_base_score": 6.5,
            "cvss3_temporal_score": 5.9,
            "cvss_base_score": 6.4,
            "cvss_temporal_score": 5.0,
            "family": "General",
            "cve": [
                "CVE-2024-4367",
                "CVE-2024-4764",
                "CVE-2024-4765",
                "CVE-2024-4766",
                "CVE-2024-4767",
                "CVE-2024-4768",
                "CVE-2024-4769",
                "CVE-2024-4770",
                "CVE-2024-4771",
                "CVE-2024-4772",
                "CVE-2024-4773",
                "CVE-2024-4774",
                "CVE-2024-4775",
                "CVE-2024-4776",
                "CVE-2024-4777",
                "CVE-2024-4778",
            ],
            "vpr": {"score": 9.2},
        },
        "port": {"port": 1443, "protocol": "TCP", "service": "www"},
        "severity": "medium",
        "severity_id": 2,
        "severity_default_id": 2,
        "severity_modification_type": "NONE",
        "first_found": "2024-03-15T17:19:03.936Z",
        "last_found": "2024-04-16T17:34:40.250Z",
        "state": "OPEN",
        "indexed": "2024-04-16T17:36:12.336258Z",
        "source": "NESSUS",
    }


@pytest.fixture
def tsc_finding():
    return {
        "pluginID": "123560",
        "severity": {"id": "3", "name": "High"},
        "hasBeenMitigated": "0",
        "acceptRisk": "0",
        "recastRisk": "0",
        "ip": "10.238.64.10",
        "uuid": "116411f4-083c-42c7-beaf-5b4a046811d0",
        "port": "0",
        "protocol": "TCP",
        "pluginName": "CentOS 7 : libssh2 (CESA-2019:0679)",
        "firstSeen": "1708664620",
        "lastSeen": "1712207126",
        "solution": "Update the affected libssh2 packages.",
        "seeAlso": "http://www.nessus.org/u?c85ae041",
        "riskFactor": "High",
        "baseScore": "9.3",
        "temporalScore": "6.9",
        "cvssVector": "AV:N/AC:M/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:C",
        "cvssV3BaseScore": "8.8",
        "cvssV3TemporalScore": "7.7",
        "cvssV3Vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
        "vulnPubDate": "1553169600",
        "patchPubDate": "1554120000",
        "pluginPubDate": "1554206400",
        "pluginModDate": "1580126400",
        "checkType": "local",
        "pluginText": "test output",
        "version": "1.4",
        "cve": "CVE-2019-3855,CVE-2019-3856,CVE-2019-3857,CVE-2019-3863",
        "bid": "",
        "xref": "RHSA #2019:0679",
        "seolDate": "-1",
        "dnsName": "target-cent7.incus",
        "macAddress": "00:16:3e:5d:7a:71",
        "netbiosName": "",
        "ips": "10.238.64.10",
        "recastRiskRuleComment": "",
        "acceptRiskRuleComment": "",
        "hostUniqueness": "repositoryID,ip,dnsName",
        "hostUUID": "",
        "assetExposureScore": "563",
        "vulnUniqueness": "repositoryID,ip,port,protocol,pluginID",
        "vulnUUID": "",
        "uniqueness": "repositoryID,ip,dnsName",
        "pluginInfo": "123560 (0/6) CentOS 7 : libssh2 (CESA-2019:0679)",
        "repository": {"id": 1, "name": "Main"},
    }


@pytest.fixture
def tvm_generator(tvm_assets, tvm_finding):
    tvm = TenableIO(access_key="None", secret_key="None")
    asset_iter = ExportsIterator(tvm)
    asset_iter.uuid = 0
    asset_iter.type = "assets"
    asset_iter.page = tvm_assets
    asset_iter.version = None
    finding_iter = ExportsIterator(tvm)
    finding_iter.version = None
    finding_iter.page = [tvm_finding for _ in range(100)]
    return tvm_merged_data(
        assets_iter=asset_iter,
        vulns_iter=finding_iter,
        asset_fields=["test"],
    )


@pytest.fixture
def tsc_generator(tsc_finding):
    findings = AnalysisResultsIterator(None)
    findings.page = [tsc_finding for _ in range(100)]
    findings._query = {"sourceType": "cumulative"}
    return tsc_merged_data(findings)
