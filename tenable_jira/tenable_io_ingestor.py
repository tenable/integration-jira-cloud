import arrow
from tenable.io.exports import ExportsIterator
from .utils import flatten
from .base_ingestor import BaseIngestor


class TenableIOIngestor(BaseIngestor):
    def __init__(self, log, api, jira, issue_types, fields, project, issue_default_fields, t_severities, t_chunk_size):
        self._log = log
        self._api = api
        self._t_severities = t_severities
        self._t_chunk_size = t_chunk_size
        super().__init__(project, issue_types, fields, issue_default_fields, jira, log)

    fid = 'tio_field'

    def ingest(self, observed_since):
        vulns = self._api.exports.vulns(
            last_found=observed_since,
            severity=self._t_severities,
            num_assets=self._t_chunk_size)
        self.create_issues(vulns)

        closed = self._api.exports.vulns(
            last_fixed=observed_since,
            state=['fixed'],
            severity=self._t_severities,
            num_assets=self._t_chunk_size)
        self.close_issues(closed)

    def create_issues(self, vulns):
        '''
        Runs through the iterator and attempts to create the tasks and subtasks
        based on the parameters specified in the config file.
        '''
        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        # TODO: confirm this logic is necessary
        if not isinstance(vulns, ExportsIterator):
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
        if not isinstance(vulns, ExportsIterator):
            raise Exception(
                'No IssueType defined for the vuln task {}.'.format(vulns))

        # start to process our way through the vulnerability iterator.
        for vulnitem in vulns:
            v = flatten(vulnitem)
            self._process_closed_vuln(v, self.fid)
