import arrow


class BaseIngestor:
    def __init__(self, project, issue_types, fields, issue_default_fields, jira, log):
        self._jira = jira
        self._project = project
        self._issue_types = issue_types
        self._fields = fields
        self._issue_default_fields = issue_default_fields
        self._log = log

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
                    if s not in ['Closed', 'Done', 'Resolved']:
                        perform_close = False

                # If the perform_close flag is still True, then we will proceed
                # with closing the parent issue.
                if perform_close:
                    self._close_issue(p)

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
                        processed = [value, ]
                    else:
                        processed = value

                # For datetime fields, validate that the field actually had
                # a value and then convert it into the appropriate format.
                elif f['type'] in ['datetime']:
                    processed = arrow.get(value).format(
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
        for field in self._issue_default_fields:
            fdef = field[field]
            if self.task['name'] in fdef:
                issue[field] = self._gen_doc_format(
                    vuln, fid, fdef[self.task['name']])
            if self.subtask['name'] in fdef:
                subissue[field] = self._gen_doc_format(
                    vuln, fid, fdef[self.subtask['name']])
        return issue, subissue, jql, sjql

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
        return {
            'project': {'key': self._project['key']},
            'issuetype': {'id': self.subtask['jira_id'] if self.subtask else None},
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

    def _close_issue(self, issue):
        '''
        Perform the close action for an issue.
        '''
        done = None
        transitions = self._jira.issues.get_transitions(issue['id'])
        for t in transitions['transitions']:
            if t['name'] in ['Closed', 'Done', 'Resolved']:
                done = t['id']
        self._log.info('CLOSING {} {}'.format(
            issue['key'], issue['fields']['summary']))
        self._jira.issues.transition(issue['id'],
                                     transition={'id': done})
