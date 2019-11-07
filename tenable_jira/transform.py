import logging
from hashlib import md5
from pkg_resources import resource_string as embedded
from .utils import flatten
from restfly.utils import dictmerge
from tenable.io.exports import ExportsIterator
from tenable.sc.analysis import AnalysisResultsIterator

class Tio2Jira:
    '''Custom Field mapping'''
    def __init__(self, config):
        # Create the logging facility
        self._log = logging.getLogger('{}.{}'.format(
            self.__module__, self.__class__.__name__))
        self.config = config

        # perform the basic creation actions and store the results.
        self._project = self._jira.projects.upsert(config['project'])
        self._fields = self._jira.fields.upsert(config['fields'])
        self._issue_types = self._jira.fields.upsert(config['issue_types'])

    def create_issues(self, vulns):
        '''
        Runs through the iterator and attempts to create the tasks and subtasks
        based on the parameters specified in the config file.
        '''

        # First we need to define the task and subtask.  We will iterate through
        # the config data and retain the last specified task and subtask.
        task = None
        subtask = None
        fid = None

        for item in self._issue_types:
            if item['type'] == 'task':
                task = item
            elif item['type'] == 'subtask':
                subtask = item

        # We need to determine is we need to use the tio_field param or the
        # tsc_field param.  We will use the iterator's ObjectType as a reliable
        # method to determine what to use.
        if isinstance(vulns, ExportsIterator):
            fid = 'tio_field'
        elif isinstance(vulns, AnalysisResultsIterator):
            fid = 'tsc_field'

        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        if not task:
            raise Exception('No IssueType defined for the vuln task.')

        # start to process our way through the vulnerability iterator.
        for vulnitem in vulns:
            v = flatten(vulnitem)
            issue = dict(
                project={'key': self._project},
                issuetype={'id': task['jira_id']})
            ijql = list()
            subissue = dict(
                project={'key': self._project},
                issuetype={'id': subtask['jira_id'] if subtask else None})
            sjql = list()

            # For each field that was defined within the configuration, if the
            # field id exists for the field, then populate the issue and
            # subissue as defined within the field issue_type config.
            for f in self._fields:

                # checks to see if the field is part of the task issuetype, and
                # processes appropriately.
                if fid in f and task['name'] in f['issue_type']:
                    issue[f['jira_id']] = v.get(f[fid])

                    # if the field name is specified as part of the search for
                    # a task, then we will need to add it to the issue jql
                    # statements.
                    if f['jira_field'] in task['search']:
                        ijql.append('"{}" = "{}"'.format(
                            f['jira_field'], v.get(f[fid])))

                # checks to see if the field is part of the subtask issuetype,
                # and processes appropriately.
                if fid in f and subtask and subtask['name'] in f['issue_type']:
                    subissue[f['jira_id']] = v.get(f[fid])

                    # if the field name is specified as part of the search for
                    # a subtask, then we will need to add it to the subissue jql
                    # statements.
                    if f['jira_field'] in subtask['search']:
                        sjql.append('"{}" = "{}"'.format(
                            f['jira_field'], v.get(f[fid])))

            # perform the upsert of the issue and store the response as i.
            i = self._jira.issues.upsert(fields=issue, jql=' and '.join(ijql))

            # if a subissue exists, then add in the parent key and perform the
            # same upsert action as we did with the issue.
            if subissue:
                subissue['parent'] = {'key': i['key']}
                self._jira.issues.upsert(
                    fields=subissue, jql=' and '.join(sjql))

