from typing import Generator
import arrow
from tenable.io import TenableIO
from tenable.sc import TenableSC

from .generators import tvm_merged_data, tsc_merged_data, tvm_asset_cleanup
from tenb2jira.version import version


class Tenable:
    tvm: (TenableIO | None) = None
    tsc: (TenableSC | None) = None
    config: dict
    platform: str
    timestamp: int
    age: int
    severity: list[str]
    chunk_size: int = 1000
    page_size: int = 1000
    query_id: (int | None) = None
    last_run: (int | None) = None

    def __init__(self, config: dict):
        self.config = config
        self.platform = config['tenable']['platform']
        self.timestamp = self.config['tenable'].get('last_run')
        self.age = self.config['tenable']['vuln_age']
        self.severity = self.config['tenable']['severities']
        self.chunk_size = self.config['tenable']['tvm_chunk_size']
        self.page_size = self.config['tenable']['tsc_page_size']
        self.query_id = self.config['tenable'].get('tsc_query_id')

        if not self.timestamp:
            self.timestamp = int(arrow.now()
                                      .shift(days=-self.age)
                                      .floor('day')
                                      .timestamp())
        if self.platform == 'tvm':
            self.tvm = TenableIO(url=config['tenable']['url'],
                                 access_key=config['tenable']['access_key'],
                                 secret_key=config['tenable']['secret_key'],
                                 vendor='Tenable',
                                 product='JiraCloud',
                                 build=version
                                 )
        elif config['tenable']['platform'] == 'tsc':
            self.tsc = TenableSC(url=config['tenable']['url'],
                                 access_key=config['tenable']['access_key'],
                                 secret_key=config['tenable']['secret_key'],
                                 vendor='Tenable',
                                 product='JiraCloud',
                                 build=version
                                 )

    def get_generator(self) -> Generator:
        self.last_run = arrow.now().timestamp()
        if self.platform == 'tvm':
            assets = self.tvm.exports.assets(updated_at=self.timestamp,
                                             chunk_size=self.chunk_size
                                             )
            vulns = self.tvm.exports.vulns(since=self.timestamp,
                                           severity=self.severity,
                                           state=['open', 'reopened', 'fixed'],
                                           include_unlicensed=True,
                                           num_assets=self.chunk_size
                                           )
            return tvm_merged_data(assets, vulns)
        if self.platform == 'tsc':
            sevmap = {
                'info': '0',
                'low': '1',
                'medium': '2',
                'high': '3',
                'critical': '4'
            }
            tsc_ts = f'{self.timestamp}-{self.last_run}'
            sevfilter = ','.join([sevmap[s] for s in self.severity])
            cumulative = self.tsc.analysis.vulns(('severity', '=', sevfilter),
                                                 ('lastSeen', '=', tsc_ts),
                                                 source='cumulative',
                                                 query_id=self.query_id,
                                                 limit=self.page_size
                                                 )
            patched = self.tsc.analysis.vulns(('severity', '=', sevfilter),
                                              ('lastMitigated', '=', tsc_ts),
                                              source='patched',
                                              query_id=self.query_id,
                                              limit=self.page_size
                                              )
            return tsc_merged_data(cumulative, patched)

    def get_asset_cleanup(self) -> Generator:
        if self.platform == 'tvm':
            dassets = self.tvm.exports.assets(deleted_at=self.timestamp,
                                              chunk_size=self.chunk_size
                                              )
            tassets = self.tvm.exports.assets(terminated_at=self.timestamp,
                                              chunk_size=self.chunk_size
                                              )
            return tvm_asset_cleanup(dassets, tassets)
        if self.platform == 'tsc':
            return []


