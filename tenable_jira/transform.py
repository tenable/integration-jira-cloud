import logging, time, arrow, json
from hashlib import md5
from pkg_resources import resource_string as embedded
from .utils import flatten
from tenable.io import TenableIO
from tenable.sc import TenableSC
from tenable.io.exports import ExportsIterator
from tenable.sc.analysis import AnalysisResultsIterator
from .tenable_io_ingestor import TenableIOIngestor
from .tenable_sc_ingestor import TenableSCIngestor

class Tio2Jira:
    def __init__(self, src, jira, config):
        # Create the logging facility
        self._jira = jira
        self._src = src
        self._log = logging.getLogger('{}.{}'.format(
            self.__module__, self.__class__.__name__))
        self.config = config
        # perform the basic creation actions and store the results.
        self._project = self._jira.projects.upsert(**config['project'])
        self._fields = self._jira.fields.upsert(config['fields'])
        self._issue_types = self._jira.issue_types.upsert(config['issue_types'])
        self.screen_builder()


    def screen_builder(self):
        '''
        Builds the Field->Screen mapping as is necessary based off the
        configuration.  This code makes some shaky assumptions, as the API
        doesn't seem to provide a direct linkage between the project and the
        screen.  Ideally for more complex deployments a jira_id should be
        specified with the screen ids that we want to be managing.
        '''
        if not ('no_create' in self.config['screen']):
            sids = list()
            if 'jira_ids' not in self.config['screen']:
                # if there was no screen ID specified, then we will attempt to
                # discover it by the default naming convention that Jira uses
                # to create the screens.  This format has been observed as:
                #
                # VULN: Task Management Edit/View Issue Screen
                names = list()
                for name in self.config['screen']['name']:
                    names.append('{}: {}'.format(
                        self.config['project']['key'], name))
                for item in self._jira.screens.list():
                    if item['name'] in names:
                        sids.append(item['id'])
            else:
                # if a jira_id was specified for the screen, then ignore the
                # above shenanigans and just use the ID.
                sids = self.config['screen']['jira_ids']

            for sid in sids:
                tabs = self._jira.screens.screen_tabs(sid)
                for tabname in self.config['screen']['tabs']:
                    name = tabname
                    tid = None

                    # for the default tab, we will actually use the tabname of
                    # "Field Tab" instead of "default".
                    if tabname == 'default':
                        name = 'Field Tab'

                    # look the the tab listing and set the tid to the id integer
                    # if it exists.
                    for t in tabs:
                        if t['name'] == name:
                            tid = t['id']

                    # if no tid was specified, then create the tab and store
                    # the id.
                    if not tid:
                        tid = self._jira.screens.create_tab(
                            sid, name=name)['id']

                    # now we will attempt to verify that the appropriate fields
                    # exist on this tab.  If they don't, then we will add them
                    # to the tab.
                    #
                    # NOTE: this code is a bit of a nested mess.  should likely
                    #       consider refactoring this later.
                    tabfields = self._jira.screens.screen_tab_fields(sid, tid)
                    for fieldname in self.config['screen']['tabs'][tabname]:
                        for f in self._fields:
                            if fieldname == f['jira_field']:
                                tabnames = [t['name'] for t in tabfields]
                                if fieldname not in tabnames:
                                    self._jira.screens.add_screen_tab_field(
                                        sid, tid, f['jira_id'])


    def ingest(self, observed_since):
        '''
        Perform the vuln ingestion and trnasformation.

        Args:
            observed_since (int):
                Unix Timestamp detailing the threshold for vuln age.
        '''
        # if the source instance is a Tenable.io object, then we will initiate
        # the appropriate export calls.
        if isinstance(self._src, TenableIO):
            ingestor = TenableIOIngestor(self._log, self._src, self._jira, self._issue_types, self._fields, self._project,
                                         self.config['issue_default_fields'], self.config['tenable']['tio_severities'], self.config['tenable']['tio_chunk_size'])
            ingestor.ingest(observed_since)

        # if the source instance is a Tenable.sc object, then we will make the
        # appropriate analysis calls using the query id specified.
        if isinstance(self._src, TenableSC):
            ingestor = TenableSCIngestor(self._log, self._src, self._jira, self._issue_types, self._fields, self._project,
                                         self.config['issue_default_fields'], self.config['tenable']['tsc_query_id'], self.config['tenable']['tsc_page_size'])
            ingestor.ingest(observed_since)
