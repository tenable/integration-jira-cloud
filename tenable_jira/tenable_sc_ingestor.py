import arrow
import time
from tenable.sc.analysis import AnalysisResultsIterator
from .utils import flatten
from .base_ingestor import BaseIngestor


class TenableSCIngestor(BaseIngestor):
    def __init__(self, log, api, jira, issue_types, fields, project, issue_default_fields, t_query_id, t_page_size):
        self._log = log
        self._api = api
        self._t_query_id = t_query_id
        self._t_page_size = t_page_size
        super().__init__(project, issue_types, fields, issue_default_fields, jira, log)

    fid = 'tsc_field'

    def ingest(self, observed_since):
        vulns = self._api.analysis.vulns(
            ('last_seen', '=', '{}-{}'.format(
                observed_since, int(time.time()))),
            query_id=self._t_query_id,
            limit=self._t_page_size,
            tool='vulndetails')
        self.create_issues(vulns)

        vulns = self._api.analysis.vulns(
            ('last_seen', '=', '{}-{}'.format(
                observed_since, int(time.time()))),
            query_id=self._t_query_id,
            limit=self._t_page_size,
            source='patched',
            tool='vulndetails')
        self.close_issues(vulns)

    def create_issues(self, vulns):
        '''
        Runs through the iterator and attempts to create the tasks and subtasks
        based on the parameters specified in the config file.
        '''
        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        # TODO: confirm this logic is necessary
        if not isinstance(vulns, AnalysisResultsIterator):
            raise Exception(
                'No IssueType defined for the vuln task {}.'.format(vulns))

        # start to process our way through the vulnerability iterator.
        for vulnitem in vulns:
            v = flatten(vulnitem)
            self._process_open_vuln(v, self.fid)

    def close_issues(self, vulns):
        '''
        Runs through the iterator and attempts to create the tasks and subtasks
        based on the parameters specified in the config file.
        '''
        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        # TODO: confirm this logic is necessary
        if not isinstance(vulns, AnalysisResultsIterator):
            raise Exception(
                'No IssueType defined for the vuln task {}.'.format(vulns))

        # start to process our way through the vulnerability iterator.
        for vulnitem in vulns:
            v = flatten(vulnitem)
            self._process_closed_vuln(v, self.fid)
