import logging, time, arrow, json
from hashlib import md5
from pkg_resources import resource_string as embedded
from .utils import flatten
from tenable.io import TenableIO
from tenable.sc import TenableSC
from tenable.io.exports import ExportsIterator
from tenable.sc.analysis import AnalysisResultsIterator

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

    @property
    def task(self):
        '''
        Returns the task
        '''
        for i in self._issue_types:
            if i['type'] == 'standard':
                return i

    @property
    def subtask(self):
        '''
        Returns the subtask if defined.
        '''
        for i in self._issue_types:
            if i['type'] == 'subtask':
                return i

    def _gen_issue_skel(self):
        '''
        Generates a basic issue skeleton
        '''
        return {
            'project': {'key': self._project['key']},
            'issuetype': {'id': self.task['jira_id']},
        }

    def _gen_subissue_skel(self):
        '''
        Generates a basic subissue skeleton
        '''
        platid = None
        if isinstance(self._src, TenableSC):
            platform = 'Tenable.sc'
        elif isinstance(self._src, TenableIO):
            platform = 'Tenable.io'
        else:
            platform = 'Unknown Tenable Platform'
        for f in self._fields:
            if f.get('is_platform_id'):
                platid = f.get('jira_id')
        return {
            'project': {'key': self._project['key']},
            'issuetype': {'id': self.subtask['jira_id'] if self.subtask else None},
            platid: platform,
        }

    def _gen_doc_format(self, vuln, fid, fdef):
        '''
        Converts the YAML field definition into the processed result.
        '''
        # if the definition is a list, then we are dealing with a document
        # structure and should build the appropriate dict structure.
        if isinstance(fdef, list):
            content = list()
            for item in fdef:
                # The heading is derrived from the name attribute
                content.append({
                    'type': 'heading',
                    'attrs': {'level': 1},
                    'content': [{
                        'type': 'text',
                        'text': item['name']
                }]})

                # The paragraph is derrived from the appropriate
                # field parameter.  If the string formatting fails
                # from a KeyError, then replace the output with
                # an empty paragraph.
                try:
                    content.append({
                        'type': 'paragraph',
                        'content': [{
                            'type': 'text',
                            'text': item[fid].format(vuln=vuln)
                    }]})
                except KeyError:
                    content.append({
                        'type': 'paragraph',
                        'content': [{
                            'type': 'text',
                            'text': 'No Output'
                    }]})
            return {
                'version': 1,
                'type': 'doc',
                'content': content
            }

        # if the definition is a dictionary, then this is a simple single-field
        # response and we should simple return back the processed string.
        elif isinstance(fdef, dict):
            return fdef[fid].format(vuln=vuln)

    def _process_vuln(self, vuln, fid):
        '''
        Processes a singular vulnerability and adds/updates the appropriate
        Jira issues.
        '''
        issue = self._gen_issue_skel()
        subissue = self._gen_subissue_skel()
        jql = [
            'project = "{}"'.format(self._project['key']),
            'issuetype = "{}"'.format(self.task['name']),
            'status not in (Closed, Done, Resolved)'
        ]
        sjql = [
            'project = "{}"'.format(self._project['key']),
            'issuetype = "{}"'.format(self.subtask['name']),
            'status not in (Closed, Done, Resolved)'
        ]

        for f in self._fields:
            # determine the JQL operator that we may need to use.
            if f['type'] == 'labels':
                oper = '='
            else:
                oper = '~'

            value = vuln.get(f.get(fid))
            processed = None

            if value:
                # for text-type fields, only sent the field if there is some
                # sort of data in it and recast the field as a string.
                if f['type'] in ['readonlyfield', 'textarea']:
                    processed = str(value)

                # for labels, just pass on the field as-is
                elif f['type'] in ['labels']:
                    if isinstance(value, str):
                        if fid == 'tsc_field':
                            processed = value.split(',')
                        else:
                            processed = [value,]
                    else:
                        processed = value

                # For datetime fields, validate that the field actually had
                # a value and then convert it into the appropriate format.
                elif f['type'] in ['datetime']:

                    try:
                        processed = arrow.get(value).format(
                            'YYYY-MM-DDTHH:mm:ss.SSSZ')
                    except arrow.parser.ParserError:
                        processed = arrow.get(int(value)).format(
                            'YYYY-MM-DDTHH:mm:ss.SSSZ')

                # For anything else, just pass through
                else:
                    processed = value

                if self.task['name'] in f['issue_type']:
                    issue[f['jira_id']] = processed
                if self.subtask['name'] in f['issue_type']:
                    subissue[f['jira_id']] = processed

            # Handle any JQL conversions that need to be done in order to make
            # the JQL statement valid.
            if isinstance(processed, list):
                if len(processed) > 1:
                    oper = "in"
                    svalue = '({})'.format(
                        ','.join(["{}".format(x) for x in processed]))
                else:
                    svalue = processed[0]
            elif not processed:
                oper = "is"
                svalue = "EMPTY"
            else:
                svalue = '"{}"'.format(processed)

            # construct the JQL statement
            jql_statement = '"{}" {} {}'.format(f['jira_field'], oper, svalue)

            # Add the JQL statement as necessary to the appropriate JQL queries.
            if f['jira_field'] in self.task['search']:
                jql.append(jql_statement)
            if f['jira_field'] in self.subtask['search']:
                sjql.append(jql_statement)

        # Now to process the default fields.
        for field in self.config['issue_default_fields']:
            fdef = self.config['issue_default_fields'][field]
            if self.task['name'] in fdef:
                issue[field] = self._gen_doc_format(
                    vuln, fid, fdef[self.task['name']])
            if self.subtask['name'] in fdef:
                subissue[field] = self._gen_doc_format(
                    vuln, fid, fdef[self.subtask['name']])
        return issue, subissue, jql, sjql

    def _close_issue(self, issue):
        '''
        Perform the close action for an issue.
        '''
        done = None
        transitions = self._jira.issues.get_transitions(issue['id'])
        for t in transitions['transitions']:
            if t['name'] in self.config['closed_transitions']:
                done = t['id']
        if done:
            self._log.info('CLOSING {} {}'.format(
                issue['key'], issue['fields']['summary']))
            self._jira.issues.transition(issue['id'],
                transition={'id': done})
        else:
            self._log.error(' '.join([
                'CANNOT CLOSE {}.'.format(issue['id']),
                'No valid transition found.',
                'Available transitions are {}'.format(', '.join(
                    ['{}:{}'.format(i['id'], i['name']) for i in transitions]))
            ]))

    def _process_open_vuln(self, vuln, fid):
        '''
        perform the necessary actions for opening/updating tasks and sub-tasks.
        '''
        # Pass off the processing of the issue and subissue to _process_vuln
        issue, subissue, jql, sjql = self._process_vuln(vuln, fid)

        # perform the upsert of the issue and store the response as i.
        i = self._jira.issues.upsert(fields=issue, jql=' and '.join(jql))

        if self.subtask:
            subissue['parent'] = {'key': i['key']}
            self._jira.issues.upsert(fields=subissue, jql=' and '.join(sjql))

    def _process_closed_vuln(self, vuln, fid):
        '''
        Run through closing tasks and sub-tasks as necessary.
        '''
        # Pass off the processing of the issue and subissue to _process_vuln
        issue, subissue, jql, sjql = self._process_vuln(vuln, fid)

        # for subtasks, we will simply search to verify that they're still in
        # an open state and then close any issues that are returned.
        if self.subtask:
            issues = self._jira.issues.search(' and '.join(sjql))
            if issues['total'] > 0:
                for i in issues['issues']:
                    self._close_issue(i)

        # parent issues are treated differently.  If all of the subitems are
        # closed, only then will we close the parent items.
        parents = self._jira.issues.search(' and '.join(jql))
        if parents['total'] > 0:
            for p in parents['issues']:
                # Here we will get the subtasks, and then iterate through their
                # statuses to ensure that all of them are in a closed state.  If
                # any of the issues are still open in any form, then we will
                # flip the "perform_close" flag to False.
                subs = p['fields']['subtasks']
                perform_close = True
                for s in [i['fields']['status']['name'] for i in subs]:
                    if s not in self.config['closed_transitions']:
                        perform_close = False

                # If the perform_close flag is still True, then we will proceed
                # with closing the parent issue.
                if perform_close:
                    self._close_issue(p)

    def create_issues(self, vulns):
        '''
        Runs through the iterator and attempts to create the tasks and subtasks
        based on the parameters specified in the config file.
        '''
        # We need to determine is we need to use the tio_field param or the
        # tsc_field param.  We will use the iterator's ObjectType as a reliable
        # method to determine what to use.
        if isinstance(vulns, ExportsIterator):
            fid = 'tio_field'
        elif isinstance(vulns, AnalysisResultsIterator):
            fid = 'tsc_field'

        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        if not fid:
            raise Exception(
                'No IssueType defined for the vuln task {}.'.format(vulns))

        # start to process our way through the vulnerability iterator.
        for vulnitem in vulns:
            v = flatten(vulnitem)
            self._process_open_vuln(v, fid)

    def close_issues(self, vulns):
        '''
        Runs through the iterator and attempts to create the tasks and subtasks
        based on the parameters specified in the config file.
        '''
        # We need to determine is we need to use the tio_field param or the
        # tsc_field param.  We will use the iterator's ObjectType as a reliable
        # method to determine what to use.
        if isinstance(vulns, ExportsIterator):
            fid = 'tio_field'
        elif isinstance(vulns, AnalysisResultsIterator):
            fid = 'tsc_field'

        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        if not fid:
            raise Exception(
                'No IssueType defined for the vuln task {}.'.format(vulns))

        # start to process our way through the vulnerability iterator.
        for vulnitem in vulns:
            v = flatten(vulnitem)
            self._process_closed_vuln(v, fid)

    def ingest(self, observed_since):
        '''
        Perform the vuln ingestion and transformation.

        Args:
            observed_since (int):
                Unix Timestamp detailing the threshold for vuln age.
        '''
        # if the source instance is a Tenable.io object, then we will initiate
        # the appropriate export calls.
        if isinstance(self._src, TenableIO):
            # generate a an export for the open and reopened vulns that match
            # the criticality rating described.  Then pass the export iterator
            # to the create_issues method.
            vulns = self._src.exports.vulns(
                last_found=observed_since,
                severity=self.config['tenable']['tio_severities'],
                num_assets=self.config['tenable'].get('chunk_size', 1000))
            self.create_issues(vulns)

            # generate a an export for the fixed vulns that match the
            # criticality rating described.  Then pass the export iterator to
            # the close_issues method.
            closed = self._src.exports.vulns(
                last_fixed=observed_since,
                state=['fixed'],
                severity=self.config['tenable']['tio_severities'],
                num_assets=self.config['tenable'].get('chunk_size', 1000))
            self.close_issues(closed)

        # if the source instance is a Tenable.sc object, then we will make the
        # appropriate analysis calls using the query id specified.
        if isinstance(self._src, TenableSC):
            # using the query specified, overload the tool and the last_seen
            # filter to pull data from the appropriate timeframe.
            vulns = self._src.analysis.vulns(
                ('lastSeen', '=', '{}-{}'.format(
                    observed_since, int(time.time()))),
                query_id=self.config['tenable'].get('query_id'),
                limit=self.config['tenable'].get('page_size', 1000),
                tool='vulndetails')
            self.create_issues(vulns)

            # using the query specified, overload the tool and the last_seen
            # filter to pull data from the appropriate timeframe.
            vulns = self._src.analysis.vulns(
                ('lastMitigated', '=', '{}-{}'.format(
                    observed_since, int(time.time()))),
                query_id=self.config['tenable'].get('query_id'),
                limit=self.config['tenable'].get('page_size', 1000),
                source='patched',
                tool='vulndetails')
            self.close_issues(vulns)
