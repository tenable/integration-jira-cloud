from copy import copy
from typing import Generator, Any
import arrow
from tenable.io import TenableIO
from tenable.sc import TenableSC

from .generators import tvm_merged_data, tsc_merged_data, tvm_asset_cleanup
from tenb2jira.version import version


class Tenable:
    tvm: TenableIO
    tsc: TenableSC
    config: dict
    platform: str
    timestamp: int
    age: int
    close_accepted: bool
    severity: list[str]
    chunk_size: int = 1000
    page_size: int = 1000
    vpr_score: (float | None) = None
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
        self.close_accepted = self.config['tenable'].get('fix_accepted_risks',
                                                         True
                                                         )
        self.vpr_score = self.config['tenable'].get('vpr_score')

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

    def get_tvm_generator(self) -> Generator[Any, Any, Any]:
        """
        Initiates the TVM exports and returns the TVM Generator.
        """
        self.last_run = int(arrow.now().timestamp())
        assets = self.tvm.exports.assets(updated_at=self.timestamp,
                                         chunk_size=self.chunk_size
                                         )
        kwargs = {
            'since': self.timestamp,
            'severity': self.severity,
            'state': ['open', 'reopened', 'fixed'],
            'include_unlicensed': True,
            'num_assets': self.chunk_size,
        }
        if self.vpr_score:
            kwargs['vpr_score'] = {'gte': self.vpr_score}
        vulns = self.tvm.exports.vulns(**kwargs)
        return tvm_merged_data(assets,
                               vulns,
                               close_accepted=self.close_accepted,
                               )

    def get_tsc_generator(self, start_time: int) -> Generator[Any, Any, Any]:
        """
        Queries the Analysis API and returns the TSC Generator.
        """

        # The severity map to link the string severities to the integer values
        # that TSC expects.
        sevmap = {
            'info': '0',
            'low': '1',
            'medium': '2',
            'high': '3',
            'critical': '4'
        }

        # Construct the TSC timestamp offsets.
        tsc_ts = f'{self.timestamp}-{start_time}'

        # The base parameters to pass to the API.
        params = {
            'source': 'cumulative',
            'limit': self.page_size
        }

        # The initial filters to pass to the API.
        filters = [
            ('severity', '=', ','.join([sevmap[s] for s in self.severity])),
        ]

        # If the VPR score is set, then we will construct that filter as well.
        if self.vpr_score:
            filters.append(('vprScore', '=', f'{self.vpr_score}-10'))

        # If the query ID is set, then we will pass that parameter.
        if self.query_id:
            params['query_id'] = self.query_id


        # Fetch the cumulative results iterator.
        f = copy(filters)
        f.append(('lastSeen', '=', tsc_ts))
        cumulative = self.tsc.analysis.vulns(*f, **params)

        # Fetch the patched results iterator.
        params['source'] = 'patched'
        f = copy(filters)
        f.append(('lastMitigated', '=', tsc_ts))
        patched = self.tsc.analysis.vulns(*f, **params)
        return tsc_merged_data(cumulative,
                               patched,
                               close_accepted=self.close_accepted,
                               )

    def get_generator(self,
                      start_time: arrow.Arrow
                      ) -> Generator[Any, Any, Any]:
        """
        Retreives the appropriate generator based on the configured platform.
        """
        if self.platform == 'tvm':
            return self.get_tvm_generator()
        return self.get_tsc_generator(int(start_time.timestamp()))

    def get_asset_cleanup(self) -> (Generator[Any, Any, Any] | list):
        if self.platform == 'tvm':
            dassets = self.tvm.exports.assets(deleted_at=self.timestamp,
                                              chunk_size=self.chunk_size
                                              )
            tassets = self.tvm.exports.assets(terminated_at=self.timestamp,
                                              chunk_size=self.chunk_size
                                              )
            return tvm_asset_cleanup(dassets, tassets)
        return []
