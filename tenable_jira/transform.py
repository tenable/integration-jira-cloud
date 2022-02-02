import logging, time, arrow, json, sys
from hashlib import md5
from pkg_resources import resource_string as embedded
from restfly.utils import trunc
from restfly.errors import BadRequestError
from .utils import flatten
from tenable.io import TenableIO
from tenable.sc import TenableSC
from tenable.io.exports.iterator import ExportsIterator
from tenable.sc.analysis import AnalysisResultsIterator


class Tio2Jira:
    _asset_cache = dict()
    _termed_assets = list()
    task = None
    subtask = None

    def __init__(self, src, jira, config, update_jira_status_to_tenable=False, fetch_pending_artifacts=False):
        # Create the logging facility
        self._jira = jira
        self._src = src
        self._log = logging.getLogger('{}.{}'.format(
            self.__module__, self.__class__.__name__))
        self.config = config
        self.new_vuln = list()
        self.jira_field_name_mapping = dict()
        self.update_jira_status_to_tenable = update_jira_status_to_tenable
        self.fetch_pending_artifacts = fetch_pending_artifacts
        # perform the basic creation actions and store the results.
        self._project = self._jira.projects.upsert(**config['project'])
        self._fields = self._jira.fields.upsert(config['fields'])
        project = self._jira.projects.details(config['project']['key'])
        itypes = self._jira.issue_types.list_by_project(self._project['id'])
        for itype in config['issue_types']:

            # if the search is platform-specific and there was no overriding search
            # context presented, then we will overload the search context with the
            # default platform-specific one.
            if 'search' not in itype and 'platform' in itype:
                itype['search'] = itype['platform'][config['tenable']['platform']]

            # if the issue type is "standard" then look at the issuetypes cached and
            # look for the normal task issue type, then generate the task data dict
            # with that jira_id.
            if itype['type'] == 'standard':
                for item in itypes:
                    if not item['subtask']:
                        self.task = {
                            'name': itype['name'],
                            'jira_id': int(item['id']),
                            'type': itype['type'],
                            'search': itype['search']
                        }

            # if the issue type is "subtask" then look at the issuetypes cached and
            # look for the sub-task issue type, then generate the task data dict
            # with that jira_id.
            elif itype['type'] == 'subtask':
                for item in itypes:
                    if item['subtask']:
                        self.subtask = {
                            'name': itype['name'],
                            'jira_id': int(item['id']),
                            'type': itype['type'],
                            'search': itype['search']
                        }
        self._log.debug('Issuetypes standard={}, subtask={}'.format(self.task, self.subtask))

        # Deprecating this process as JIRA now reports the IssueTypes as part
        # of the project details call.
        #self._issue_types = self._jira.issue_types.upsert(config['issue_types'])
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
            if 'jira_ids' not in self.config['screen'] and len(sids) < 1:
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

            self._log.info('Using JIRA Screens {}'.format(sids))

            for sid in sids:
                tabs = self._jira.screens.screen_tabs(sid)
                for tabname in self.config['screen']['tabs']:
                    name = tabname
                    tid = None

                    # for the default tab, we will actually use the tabname of
                    # "Field Tab" instead of "default".
                    if tabname == 'default':
                        name = 'Field Tab'

                    # look the the tab listing and set the tid to the id
                    # integer if it exists.
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
                                if fieldname not in self.jira_field_name_mapping.keys():
                                    self.jira_field_name_mapping[fieldname]=f['jira_id']
                                if fieldname not in tabnames:
                                    self._log.info(
                                        'Adding {} to Screen {}:{}'.format(
                                            fieldname, sid, tid))
                                    self._jira.screens.add_screen_tab_field(
                                        sid, tid, f['jira_id'])
                                else:
                                    self._log.info(
                                        '{} already exists in {}:{}'.format(
                                            fieldname, sid, tid))

    def _gen_issue_skel(self):
        '''
        Generates a basic issue skeleton
        '''
        return {
            'project': {'key': self._project['key']},
            'issuetype': {'id': self.task['jira_id']},
        }

    def _get_platform(self):
        '''
        Returns the custom field name and the platform.
        '''
        platid = None
        platform = None
        if isinstance(self._src, TenableSC):
            platform = 'Tenable.sc'
        elif isinstance(self._src, TenableIO):
            platform = 'Tenable.io'
        else:
            platform = 'Unknown Tenable Platform'
        for f in self._fields:
            if f.get('is_platform_id'):
                platid = f.get('jira_id')
        return platid, platform

    def _gen_subissue_skel(self):
        '''
        Generates a basic subissue skeleton
        '''
        platid, platform = self._get_platform()
        return {
            'project': {'key': self._project['key']},
            'issuetype': {'id': self.subtask['jira_id'] if self.subtask else None},
            platid: platform,
        }

    def _gen_doc_format(self, vuln, fid, fdef):
        '''
        Converts the YAML field definition into the processed result.
        '''
        tconf = self.config.get('truncation', dict())
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
                    }]
                })

                # The paragraph is derived from the appropriate
                # field parameter.  If the string formatting fails
                # from a KeyError, then replace the output with
                # an empty paragraph.
                try:
                    content.append({
                        'type': 'paragraph',
                        'content': [{
                            'type': 'text',
                            'text': trunc(
                                item[fid].format(vuln=vuln),
                                tconf.get('limit', 10000),
                                tconf.get('suffix', '...')
                            )
                        }]
                    })
                except KeyError:
                    content.append({
                        'type': 'paragraph',
                        'content': [
                            {
                                'type': 'text',
                                'text': 'No Output'
                            }
                        ]
                    })
            return {
                'version': 1,
                'type': 'doc',
                'content': content
            }

        # if the definition is a dictionary, then this is a simple single-field
        # response and we should simple return back the processed string.
        elif isinstance(fdef, dict):
            return trunc(fdef[fid].format(vuln=vuln), limit=255)

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
        sevprio = self.config['tenable'].get('severity_prioritization')

        for f in self._fields:
            # determine the JQL operator that we may need to use.
            if f['type'] == 'labels':
                oper = '='
            else:
                oper = '~'

            if f.get('static_value'):
                value = f.get('static_value')
            elif f.get('is_platform_id'):
                _, value = self._get_platform()
            elif f.get('is_tio_tags') and fid == 'tio_field':
                value = vuln.get('asset.tags')
            else:
                value = vuln.get(f.get(fid))

            # Here we will be setting the severity priority for the task and
            # subtask.
            if sevprio and f['jira_field'] == 'Finding Severity':
                subissue['priority'] = {
                    'id': str(sevprio.get(value.lower(), 4))
                }
                self._log.debug(f'Setting Finding Sev to {value.lower()}')
            if sevprio and f['jira_field'] == 'Vulnerability Severity':
                issue['priority'] = {
                    'id': str(sevprio.get(value.lower(), 4))
                }
                self._log.debug(f'Setting Vuln Sev to {value.lower()}')

            processed = None

            if value:
                # for text-type fields, only sent the field if there is some
                # sort of data in it and recast the field as a string.
                if f['type'] in ['readonlyfield', 'textarea']:
                    processed = str(value)
                    if f['type'] in ['readonlyfield']:
                        processed = trunc(processed, 255)

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
        cur_trans = issue['fields']['status']['name']
        if cur_trans in self.config['closed_transitions']:
            self._log.debug('skipping {}: already closed'.format(issue['key']))
            return

        done = None
        transitions = self._jira.issues.get_transitions(issue['key'])

        for t in transitions['transitions']:
            if t['name'] in self.config['closed_transitions']:
                done = t['id']
                self._log.debug('Using transition {}'.format(t))
        if done != None:
            self._log.info('CLOSING {} {}'.format(
                issue['key'], issue['fields']['summary']))
            self._jira.issues.transition(issue['id'],
                transition={'id': done})
        else:
            if 'Reopen' in [t['name'] for t in transitions['transitions']]:
                self._log.info('{} is already in a CLOSED state'.format(
                    str(issue['key'])))
            else:
                self._log.error(
                    'CANNOT CLOSE {} as no transitions were found. {}'.format(
                        str(issue['key']),
                        json.dumps(transitions['transitions'])
                ))

    def _process_open_vuln(self, vuln, fid):
        '''
        perform the necessary actions for opening/updating tasks and sub-tasks.
        '''
        # Pass off the processing of the issue and subissue to _process_vuln
        issue, subissue, jql, sjql = self._process_vuln(vuln, fid)
        if self.config.get('dry_run', False):
            self._log.debug(f'VULN: {json.dumps(vuln)}')
            self._log.debug(f'ISSUE: {json.dumps(issue)}')
            self._log.debug(f'SUB-ISSUE: {json.dumps(subissue)}')
            return

        # perform the upsert of the issue and store the response as i.
        try:
            i = self._jira.issues.upsert(new_vuln = self.new_vuln, fields=issue, jql=' and '.join(jql))
        except BadRequestError as err:
            if not self.config['jira'].get('ignore_errors', False):
                sys.exit(2)
            else:
                return

        if self.subtask:
            subissue['parent'] = {'key': i['key']}
            try:
                self._jira.issues.upsert(new_vuln = self.new_vuln, jira_field_name_mapping=self.jira_field_name_mapping, fields=subissue, jql=' and '.join(sjql))
            except BadRequestError as err:
                if not self.config['jira'].get('ignore_errors', False):
                    sys.exit(2)

    def _close_parent(self, parent):
        '''
        Closes a parent task is all of the subtasks are in a closed state.
        '''
        # Here we will get the subtasks, and then iterate through their
        # statuses to ensure that all of them are in a closed state.  If
        # any of the issues are still open in any form, then we will
        # flip the "perform_close" flag to False.
        subs = parent['fields']['subtasks']
        perform_close = True
        for s in [i['fields']['status']['name'] for i in subs]:
            if s not in self.config['closed_transitions']:
                perform_close = False

        # If the perform_close flag is still True, then we will proceed
        # with closing the parent issue.
        if perform_close:
            self._close_issue(parent)

    def _process_closed_vuln(self, vuln, fid):
        '''
        Run through closing tasks and sub-tasks as necessary.
        '''
        # Pass off the processing of the issue and subissue to _process_vuln
        issue, subissue, jql, sjql = self._process_vuln(vuln, fid)
        if self.config.get('dry_run', False):
            self._log.debug(f'VULN: {json.dumps(vuln)}')
            self._log.debug(f'ISSUE: {json.dumps(issue)}')
            self._log.debug(f'SUB-ISSUE: {json.dumps(subissue)}')
            return

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
                self._close_parent(p)

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
        else: #TODO: Remove this once we got the final call
            fid = 'tio_field'

        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        if not fid:
            raise Exception(
                'No IssueType defined for the vuln task {}.'.format(vulns))

        # start to process our way through the vulnerability iterator.
        tconfig = self.config['tenable']
        for vulnitem in vulns:
            # If the vulnerability is from Tenable.io, then we will want to
            # bolt on the asset attributes from the asset cache on to the vuln
            # instance itself.
            if fid == 'tio_field':
                keys = self.config['tenable'].get('tio_asset_attr_cache', list())
                asset = self._asset_cache.get(
                    vulnitem.get('asset', dict()).get('uuid'), dict())
                for key in keys:
                    vulnitem['asset'][key] = asset.get(key)
                vulnitem['asset']['tags'] = asset.get('tags', list())
            v = flatten(vulnitem)

            # if the tio_ignore_accepted flag is set to True, then will will
            # either ignore the vulnerability, or process the vulnerability as
            # a closed vuln.
            iaccept = tconfig.get('tio_ignore_accepted', False)
            autoclose = tconfig.get('tio_autoclose_accepted', True)
            tasset = v.get('asset.uuid', 'NA') in self._termed_assets
            status = v.get(
                'severity_modification_type', '').lower() == 'accepted'

            if (((iaccept or autoclose) and status) or tasset):
                if autoclose or tasset:
                    self._log.info(
                        'Autoclosing {} on {} as it\'s an {} issue'.format(
                            v.get('plugin.id'),
                            v.get('asset.uuid'),
                            'accepted' if status else 'orphaned'
                        )
                    )
                    self._process_closed_vuln(v, fid)
                else:
                    self._log.info(
                        'Skipping {} on {} as it\'s an accepted risk'.format(
                            v.get('plugin.id'), v.get('asset.uuid')))
            else:
                # send the vulnerability instance to processing.
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
        else: #TODO: Remove this once we got the final call
            fid = 'tio_field'

        # if there was no defined task, then raise an exception indicating an
        # issue with the configuration.
        if not fid:
            raise Exception(
                'No IssueType defined for the vuln task {}.'.format(vulns))

        # start to process our way through the vulnerability iterator.
        for vulnitem in vulns:
            # If the vulnerability is from Tenable.io, then we will want to
            # bolt on the asset attributes from the asset cache on to the vuln
            # instance itself.
            if fid == 'tio_field':
                keys = self.config['tenable'].get('tio_asset_attr_cache', list())
                asset = self._asset_cache.get(
                    vulnitem.get('asset', dict()).get('uuid'), dict())
                for key in keys:
                    vulnitem['asset'][key] = asset.get(key)
            v = flatten(vulnitem)
            self._process_closed_vuln(v, fid)

    def first_discovery_user_action_upsert_call(self):
        '''
        self._src.exports_user_action.vulns(
                    include_unlicensed=True,
                    first_found=observed_since,
                    severity=self.config['tenable']['tio_severities'],
                    num_assets=self.config['tenable'].get('chunk_size', 1000),
                    vpr=vpr,
                    tags=tags
                )
        '''
        res, asset, plugin, port = dict(), dict(), dict(), dict()

        # TODO: temp calls which needs to remove once we get final get call api.
        asset_t = self._src.workbenches.asset_info("e7819c59-4ddc-4d32-8232-58edd5ddb046")
        self._log.info("++++++++++++++ Asset Info ++++++++++++++++")
        self._log.info(asset_t)

        asset["uuid"] = "e7819c59-4ddc-4d32-8232-58edd5ddb046"
        asset["tags"] = asset_t.get("tags")
        asset["hostname"] = asset_t.get("hostname")
        asset["fqdn"] = asset_t.get("fqdn")
        asset["network_id"] = asset_t.get("network_id")
        asset["mac_address"] = asset_t.get("mac_address")
        asset["ipv4"] = asset_t.get("ipv4")
        asset["ipv6"] = asset_t.get("ipv6")
        res["asset"] = asset

        plugin_t = self._src.workbenches.vuln_info("10027")
        self._log.info("+++++++++++ Plugin Info ++++++++++++++++")
        self._log.info(plugin_t)
        plugin["id"] = "10027"
        plugin["name"] = plugin_t.get("plugin_details").get("name")
        plugin["family"] = plugin_t.get("plugin_details").get("family")

        plugin["solution"] = plugin_t.get("solution")
        plugin["description"] = plugin_t.get("description")
        plugin["vpr"] = plugin_t.get("vpr")

        reference_information = plugin_t.get("reference_information")
        cve = next(item["values"] for item in reference_information if item["name"] == "cve")
        plugin["cve"] = cve

        plugin["cvss_base_score"] = plugin_t.get("risk_information").get("cvss_base_score")
        plugin["cvss_temporal_score"] = plugin_t.get("risk_information").get("cvss_temporal_score")
        plugin["cvss3_base_score"] = plugin_t.get("risk_information").get("cvss3_base_score")
        plugin["cvss3_temporal_score"] = plugin_t.get("risk_information").get("cvss3_temporal_score")
        plugin["risk_factor"] = plugin_t.get("risk_information").get("risk_factor")

        plugin["patch_publication_date"] = plugin_t.get("vulnerability_information").get("patch_publication_date")
        res["plugin"] = plugin
        res["severity"] = 'High' if plugin_t.get("severity") == '3' else 'Low'
        res["first_found"] = plugin_t.get("discovery").get("seen_first")
        res["last_found"] = plugin_t.get("discovery").get("seen_last")
        res["state"] = "OPEN"

        port = {
                'port': 0,
                'protocol': 'UNKNOWN'
        }
        res["port"] = port

        self._log.debug("Create Jira request: %s",res)
        return [res]

    def closed_user_action_issue_call(self):
        '''
        self._src.exports_user_action.vulns(
                include_unlicensed=True,
                last_fixed=observed_since,
                state=['fixed'],
                severity=self.config['tenable']['tio_severities'],
                num_assets=self.config['tenable'].get('chunk_size', 1000),
                tags=tags
            )
        '''
        return [{
            'asset': {
                'agent_uuid': '1a6d57d8-e993-409f-82ec-20ff37eeeb9f',
                'device_type': 'general-purpose',
                'fqdn': 'ip-172-31-1-214.us-east-2.compute.internal',
                'hostname': 'ip-172-31-1-214.us-east-2.compute.internal',
                'uuid': '1a6d57d8-e993-409f-82ec-20ff37eeeb9f',
                'ipv4': '172.31.1.214',
                'ipv6': 'fe80:0000:0000:0000:007d:4eff:fed1:b3e4',
                'last_authenticated_results': '2021-07-19T20:45:33.831Z',
                'operating_system': ['Red Hat Enterprise Linux 8'],
                'network_id': '00000000-0000-0000-0000-000000000000',
                'tracked': True
            },
            'output': 'Name          : python3-chardet\nVersion       : 3.0.4-7.el8\nFixed version : 3.0.4-10.el7ar',
            'plugin': {
                'bid': [105589, 109018],
                'checks_for_default_account': False,
                'checks_for_malware': False,
                'cpe': ['p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible_core', 'p-cpe:/a:redhat:enterprise_linux:python-kid', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby_parser', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actionmailbox', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_discovery', 'p-cpe:/a:redhat:enterprise_linux:python2-pexpect', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sprockets', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-x-editable-rails', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_docker', 'p-cpe:/a:redhat:enterprise_linux:rubygem-rake', 'p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-dsl', 'p-cpe:/a:redhat:enterprise_linux:puppet-agent-oauth', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-i18n', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-native', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-dynflow', 'p-cpe:/a:redhat:enterprise_linux:python2-jmespath', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-marcel', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ldap_fluff', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-execjs', 'p-cpe:/a:redhat:enterprise_linux:katello-common', 'p-cpe:/a:redhat:enterprise_linux:python-pulp-docker-common', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-memoist', 'p-cpe:/a:redhat:enterprise_linux:python2-apypie', 'p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat-tftpboot', 'p-cpe:/a:redhat:enterprise_linux:foreman-gce', 'p-cpe:/a:redhat:enterprise_linux:python-bson', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-algebrick', 'p-cpe:/a:redhat:enterprise_linux:foreman-postgresql', 'p-cpe:/a:redhat:enterprise_linux:candlepin', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redhat_access_lib', 'p-cpe:/a:redhat:enterprise_linux:python2-billiard', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mini_portile2', 'p-cpe:/a:redhat:enterprise_linux:python3-yarl', 'p-cpe:/a:redhat:enterprise_linux:python-gofer', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rest-client', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-openscap', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_openscap', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-polyglot', 'p-cpe:/a:redhat:enterprise_linux:pulp-rpm-plugins', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_templates', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-azure_mgmt_network', 'p-cpe:/a:redhat:enterprise_linux:python2-isodate', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-rails', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-get_process_mem', 'p-cpe:/a:redhat:enterprise_linux:puppet-foreman_scap_client', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-puma', 'p-cpe:/a:redhat:enterprise_linux:pulp-docker-admin-extensions', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rb-inotify', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deep_cloneable', 'p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt_provision_plugin', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_openscap', 'p-cpe:/a:redhat:enterprise_linux:foreman', 'p-cpe:/a:redhat:enterprise_linux:python-pulp-streamer', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-angular-rails-templates', 'p-cpe:/a:redhat:enterprise_linux:foreman-dynflow-sidekiq', 'p-cpe:/a:redhat:enterprise_linux:rhel8-kickstart-setup', 'p-cpe:/a:redhat:enterprise_linux:foreman-openstack', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_ansible', 'p-cpe:/a:redhat:enterprise_linux:foreman-installer', 'p-cpe:/a:redhat:enterprise_linux:python-oauth2', 'p-cpe:/a:redhat:enterprise_linux:pulp-maintenance', 'p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_remote_execution', 'p-cpe:/a:redhat:enterprise_linux:python3-multidict', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mail', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-railties', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode-display_width', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-little-plugger', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-coffee-rails', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_discovery_image', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-audited', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_rpm_client', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-test', 'p-cpe:/a:redhat:enterprise_linux:repoview', 'p-cpe:/a:redhat:enterprise_linux:foreman-ec2', 'p-cpe:/a:redhat:enterprise_linux:python-imgcreate', 'p-cpe:/a:redhat:enterprise_linux:python2-kombu', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actionview', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ssh', 'p-cpe:/a:redhat:enterprise_linux:python-semantic_version', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deface', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_openscap', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-httpclient', 'p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_certguard_client', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-daemons', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-secure_headers', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-retriable', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_admin', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-optimist', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mimemagic', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dhcp_infoblox', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-declarative-option', 'p-cpe:/a:redhat:enterprise_linux:python-pulp-repoauth', 'p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-tzinfo', 'p-cpe:/a:redhat:enterprise_linux:foreman-ovirt', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-multipart-post', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-core', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sprockets-rails', 'p-cpe:/a:redhat:enterprise_linux:ansiblerole-foreman_scap_client', 'p-cpe:/a:redhat:enterprise_linux:python2-daemon', 'p-cpe:/a:redhat:enterprise_linux:pulp-admin-client', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actioncable', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-logger', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_virt_who_configure', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-websocket-driver', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-friendly_id', 'p-cpe:/a:redhat:enterprise_linux:python3-aiohttp', 'p-cpe:/a:redhat:enterprise_linux:python-blinker', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dns_infoblox', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-stomp', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_azure_rm', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-connection_pool', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-oauth', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-roadie', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-faraday-cookie_jar', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_leapp', 'p-cpe:/a:redhat:enterprise_linux:receptor', 'p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image-service', 'p-cpe:/a:redhat:enterprise_linux:python3-idna', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-text', 'p-cpe:/a:redhat:enterprise_linux:python3-receptor-satellite', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-protection', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-azure_mgmt_resources', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging-journald', 'p-cpe:/a:redhat:enterprise_linux:python2-ansible-runner', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gettext_i18n_rails', 'p-cpe:/a:redhat:enterprise_linux:python2-celery', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sinatra', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-crass', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-kubeclient', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf', 'p-cpe:/a:redhat:enterprise_linux:rubygem-fast_gettext', 'p-cpe:/a:redhat:enterprise_linux:rubygem-rack', 'p-cpe:/a:redhat:enterprise_linux:rubygem-newt', 'p-cpe:/a:redhat:enterprise_linux:rubygem-passenger', 'p-cpe:/a:redhat:enterprise_linux:foreman-vmware', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-promise.rb', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http-cookie', 'p-cpe:/a:redhat:enterprise_linux:satellite-debug-tools', 'p-cpe:/a:redhat:enterprise_linux:python-pymongo-gridfs', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-excon', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-jwt', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rainbow', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-openstack', 'p-cpe:/a:redhat:enterprise_linux:pulp-nodes-parent', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fx', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sidekiq', 'p-cpe:/a:redhat:enterprise_linux:python2-keycloak-httpd-client-install', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-kafo_parsers', 'p-cpe:/a:redhat:enterprise_linux:pcp-mmvstatsd', 'p-cpe:/a:redhat:enterprise_linux:python2-amqp', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mini_mime', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_hooks', 'p-cpe:/a:redhat:enterprise_linux:python-qpid-proton', 'p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ms_rest_azure', 'p-cpe:/a:redhat:enterprise_linux:satellite-common', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_container_client', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mime-types', 'p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks', 'p-cpe:/a:redhat:enterprise_linux:python-pymongo', 'p-cpe:/a:redhat:enterprise_linux:python-nectar'],
                'cve': ['CVE-2018-3258', 'CVE-2019-12781', 'CVE-2020-8840', 'CVE-2019-16782', 'CVE-2020-8184', 'CVE-2020-8161', 'CVE-2020-5216', 'CVE-2020-5217', 'CVE-2020-7238', 'CVE-2018-11751', 'CVE-2020-14061', 'CVE-2020-14380', 'CVE-2020-14062', 'CVE-2020-11619', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10968', 'CVE-2020-10969', 'CVE-2020-10693', 'CVE-2020-14334', 'CVE-2020-14195', 'CVE-2020-7943', 'CVE-2020-7942', 'CVE-2020-5267', 'CVE-2020-7663'],
                'cvss3_base_score': 9.8,
                'cvss3_temporal_score': 8.5,
                'cvss3_temporal_vector': {
                    'remediation_level': 'Official-fix',
                    'report_confidence': 'Confirmed',
                    'raw': 'E:U/RL:O/RC:C'
                },
                'cvss3_vector': {
                    'availability_impact': 'High',
                    'confidentiality_impact': 'High',
                    'integrity_impact': 'High',
                    'raw': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                },
                'cvss_base_score': 7.5,
                'cvss_temporal_score': 5.5,
                'cvss_temporal_vector': {
                    'exploitability': 'Unproven',
                    'remediation_level': 'Official-fix',
                    'report_confidence': 'Confirmed',
                    'raw': 'E:U/RL:OF/RC:C'
                },
                'cvss_vector': {
                    'access_complexity': 'Low',
                    'access_vector': 'Network',
                    'authentication': 'None required',
                    'availability_impact': 'Partial',
                    'confidentiality_impact': 'Partial',
                    'integrity_impact': 'Partial',
                    'raw': 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
                },
                'description': "The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the RHSA-2020:4366 advisory.\n\n  - puppet-agent: Puppet Agent does not properly verify SSL connection when downloading a CRL (CVE-2018-11751)\n\n  - mysql-connector-java: Connector/J unspecified vulnerability (CPU October 2018) (CVE-2018-3258)\n\n  - Django: Incorrect HTTP detection with reverse-proxy connecting via HTTPS (CVE-2019-12781)\n\n  - rubygem-rack: hijack sessions by using timing attacks targeting the session id (CVE-2019-16782)\n\n  - hibernate-validator: Improper input validation in the interpolation of constraint error messages     (CVE-2020-10693)\n\n  - jackson-databind: Serialization gadgets in org.aoju.bus.proxy.provider.*.RmiProvider (CVE-2020-10968)\n\n  - jackson-databind: Serialization gadgets in javax.swing.JEditorPane (CVE-2020-10969)\n\n  - jackson-databind: Serialization gadgets in org.springframework:spring-aop (CVE-2020-11619)\n\n  - jackson-databind: serialization in weblogic/oracle-aqjms (CVE-2020-14061)\n\n  - jackson-databind: serialization in com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool     (CVE-2020-14062)\n\n  - jackson-databind: serialization in org.jsecurity.realm.jndi.JndiRealmFactory (CVE-2020-14195)\n\n  - foreman: unauthorized cache read on RPM-based installations through local user (CVE-2020-14334)\n\n  - Satellite: Local user impersonation by Single sign-on (SSO) user leads to account takeover     (CVE-2020-14380)\n\n  - rubygem-secure_headers: limited header injection when using dynamic overrides with user input     (CVE-2020-5216)\n\n  - rubygem-secure_headers: directive injection when using dynamic overrides with user input (CVE-2020-5217)\n\n  - rubygem-actionview: views that use the `j` or `escape_javascript` methods are susceptible to XSS attacks     (CVE-2020-5267)\n\n  - netty: HTTP Request Smuggling due to Transfer-Encoding whitespace mishandling (CVE-2020-7238)\n\n  - rubygem-websocket-extensions: ReDoS vulnerability in Sec-WebSocket-Extensions parser (CVE-2020-7663)\n\n  - puppet: Arbitrary catalog retrieval (CVE-2020-7942)\n\n  - puppet: puppet server and puppetDB may leak sensitive information via metrics API (CVE-2020-7943)\n\n  - rubygem-rack: directory traversal in Rack::Directory (CVE-2020-8161)\n\n  - rubygem-rack: percent-encoded cookies can be used to overwrite existing prefixed cookie names     (CVE-2020-8184)\n\n  - jackson-databind: Lacks certain xbean-reflect/JNDI blocking (CVE-2020-8840)\n\n  - jackson-databind: Serialization gadgets in shaded-hikari-config (CVE-2020-9546)\n\n  - jackson-databind: Serialization gadgets in ibatis-sqlmap (CVE-2020-9547)\n\n  - jackson-databind: Serialization gadgets in anteros-core (CVE-2020-9548)\n\nNote that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.",
                'exploit_available': False,
                'exploit_framework_canvas': False,
                'exploit_framework_core': False,
                'exploit_framework_d2_elliot': False,
                'exploit_framework_exploithub': False,
                'exploit_framework_metasploit': False,
                'exploitability_ease': 'No known exploits are available',
                'exploited_by_malware': False,
                'exploited_by_nessus': False,
                'family': 'Red Hat Local Security Checks',
                'family_id': 1,
                'has_patch': True,
                'id': 142452,
                'in_the_news': False,
                'name': 'RHEL 8 : Satellite 6.8 release (Important) (RHSA-2020:4366)',
                'patch_publication_date': '2020-10-27T00:00:00Z',
                'modification_date': '2021-04-15T00:00:00Z',
                'publication_date': '2020-11-04T00:00:00Z',
                'risk_factor': 'High',
                'see_also': ['https://cwe.mitre.org/data/definitions/502.html', 'https://cwe.mitre.org/data/definitions/200.html', 'https://cwe.mitre.org/data/definitions/20.html', 'https://cwe.mitre.org/data/definitions/522.html', 'https://cwe.mitre.org/data/definitions/113.html', 'https://cwe.mitre.org/data/definitions/79.html', 'https://cwe.mitre.org/data/definitions/284.html', 'https://cwe.mitre.org/data/definitions/22.html', 'https://cwe.mitre.org/data/definitions/400.html', 'https://cwe.mitre.org/data/definitions/862.html', 'https://cwe.mitre.org/data/definitions/185.html', 'https://cwe.mitre.org/data/definitions/444.html', 'https://cwe.mitre.org/data/definitions/358.html', 'https://cwe.mitre.org/data/definitions/287.html', 'https://cwe.mitre.org/data/definitions/297.html', 'https://access.redhat.com/security/cve/CVE-2019-16782', 'https://bugzilla.redhat.com/1789100', 'https://access.redhat.com/security/cve/CVE-2020-8840', 'https://access.redhat.com/security/cve/CVE-2020-9546', 'https://access.redhat.com/security/cve/CVE-2020-9547', 'https://access.redhat.com/security/cve/CVE-2020-9548', 'https://bugzilla.redhat.com/1816330', 'https://bugzilla.redhat.com/1816332', 'https://bugzilla.redhat.com/1816337', 'https://bugzilla.redhat.com/1816340', 'https://access.redhat.com/security/cve/CVE-2020-10693', 'https://bugzilla.redhat.com/1805501', 'https://cwe.mitre.org/data/definitions/276.html', 'https://cwe.mitre.org/data/definitions/807.html', 'https://access.redhat.com/security/cve/CVE-2020-14334', 'https://bugzilla.redhat.com/1858284', 'https://access.redhat.com/security/cve/CVE-2019-12781', 'https://bugzilla.redhat.com/1724497', 'https://cwe.mitre.org/data/definitions/95.html', 'https://access.redhat.com/security/cve/CVE-2018-3258', 'https://access.redhat.com/security/cve/CVE-2018-11751', 'https://access.redhat.com/security/cve/CVE-2020-5216', 'https://access.redhat.com/security/cve/CVE-2020-5217', 'https://access.redhat.com/security/cve/CVE-2020-5267', 'https://access.redhat.com/security/cve/CVE-2020-7238', 'https://access.redhat.com/security/cve/CVE-2020-7663', 'https://access.redhat.com/security/cve/CVE-2020-7942', 'https://access.redhat.com/security/cve/CVE-2020-7943', 'https://access.redhat.com/security/cve/CVE-2020-8161', 'https://access.redhat.com/security/cve/CVE-2020-8184', 'https://access.redhat.com/security/cve/CVE-2020-10968', 'https://access.redhat.com/security/cve/CVE-2020-10969', 'https://access.redhat.com/security/cve/CVE-2020-11619', 'https://access.redhat.com/security/cve/CVE-2020-14061', 'https://access.redhat.com/security/cve/CVE-2020-14062', 'https://access.redhat.com/security/cve/CVE-2020-14195', 'https://access.redhat.com/security/cve/CVE-2020-14380', 'https://access.redhat.com/errata/RHSA-2020:4366', 'https://bugzilla.redhat.com/1640615', 'https://bugzilla.redhat.com/1788261', 'https://bugzilla.redhat.com/1796225', 'https://bugzilla.redhat.com/1801264', 'https://bugzilla.redhat.com/1801286', 'https://bugzilla.redhat.com/1816720', 'https://bugzilla.redhat.com/1819208', 'https://bugzilla.redhat.com/1819212', 'https://bugzilla.redhat.com/1826805', 'https://bugzilla.redhat.com/1828486', 'https://bugzilla.redhat.com/1831528', 'https://bugzilla.redhat.com/1838281', 'https://bugzilla.redhat.com/1845978', 'https://bugzilla.redhat.com/1848958', 'https://bugzilla.redhat.com/1848962', 'https://bugzilla.redhat.com/1848966', 'https://bugzilla.redhat.com/1849141', 'https://bugzilla.redhat.com/1873926'],
                'solution': 'Update the affected packages.',
                'synopsis': 'The remote Red Hat host is missing one or more security updates.',
                'type': 'local',
                'unsupported_by_vendor': False,
                'version': '1.5',
                'vuln_publication_date': '2018-10-16T00:00:00Z',
                'xrefs': [{
                    'type': 'CWE',
                    'id': '522'
                }, {
                    'type': 'CWE',
                    'id': '400'
                }, {
                    'type': 'CWE',
                    'id': '862'
                }, {
                    'type': 'CWE',
                    'id': '444'
                }, {
                    'type': 'CWE',
                    'id': '502'
                }, {
                    'type': 'CWE',
                    'id': '358'
                }, {
                    'type': 'CWE',
                    'id': '287'
                }, {
                    'type': 'CWE',
                    'id': '276'
                }, {
                    'type': 'CWE',
                    'id': '297'
                }, {
                    'type': 'CWE',
                    'id': '113'
                }, {
                    'type': 'CWE',
                    'id': '200'
                }, {
                    'type': 'CWE',
                    'id': '284'
                }, {
                    'type': 'CWE',
                    'id': '185'
                }, {
                    'type': 'RHSA',
                    'id': '2020:4366'
                }, {
                    'type': 'CWE',
                    'id': '22'
                }, {
                    'type': 'CWE',
                    'id': '79'
                }, {
                    'type': 'CWE',
                    'id': '95'
                }, {
                    'type': 'CWE',
                    'id': '807'
                }, {
                    'type': 'CWE',
                    'id': '20'
                }],
                'vpr': {
                    'score': 6.7,
                    'drivers': {
                        'age_of_vuln': {
                            'lower_bound': 366,
                            'upper_bound': 730
                        },
                        'exploit_code_maturity': 'UNPROVEN',
                        'cvss_impact_score_predicted': False,
                        'cvss3_impact_score': 5.9,
                        'threat_intensity_last28': 'VERY_LOW',
                        'threat_recency': {
                            'lower_bound': 31,
                            'upper_bound': 120
                        },
                        'threat_sources_last28': ['No recorded events'],
                        'product_coverage': 'VERY_HIGH'
                    },
                    'updated': '2021-06-15T05:23:36Z'
                }
            },
            'port': {
                'port': 0,
                'protocol': 'UNKNOWN'
            },
            'scan': {
                'completed_at': '2021-07-19T20:45:33.831Z',
                'started_at': '2021-07-19T20:45:33.831Z',
                'uuid': 'b1f47e8c-ada2-49f0-97ae-bbc1216af2d1'
            },
            'severity': 'high',
            'severity_id': 3,
            'severity_default_id': 3,
            'severity_modification_type': 'NONE',
            'first_found': '2021-07-19T20:45:33.831Z',
            'last_found': '2021-07-19T20:45:33.831Z',
            'state': 'fixed',
            'indexed': '2021-07-19T20:45:58.543Z'
        }]

    def mock_put_call(self, status_changed_issues):
        '''
        self._src.tenable_put_call.vulns(status_changed_issues)
        '''
        # TODO: Implement tenable put call to send the Jiras
        res = []
        if status_changed_issues:
            self._log.info("**************************************************")
            self._log.info("put payload: %s", {"artifacts": status_changed_issues})
            self._log.info("**************************************************")
            for issue in status_changed_issues:
                res.append({
                    "id": "abc-temp-updated-jira",
                    "asset_id": issue.get("asset_id"),
                    "finding_id": "2248d46f-05c9-4fc3-8fa9-ffb6ac7f18e6",
                    "external_id": issue.get("external_id")
                })
        else: 
            self._log.info("!!No Jira found with finding_id and status change!!")
        return {"artifacts": res}

    def mock_post_call(self, new_vuln):
        '''
        self._src.tenable_post_call.vulns(status_changed_issues)
        '''
        # TODO: Implement tenable post call to send the Jiras
        res = []
        if new_vuln:
            self._log.info("**************************************************")
            self._log.info("post payload: %s", {"artifacts": new_vuln})
            self._log.info("**************************************************")
            for vuln in new_vuln:
                res.append({
                    "id": "abc-temp-created-jira",
                    "asset_id": vuln.get("asset_id"),
                    "finding_id": "2248d46f-05c9-4fc3-8fa9-ffb6ac7f18e6",
                    "external_id": vuln.get("external_id")
                })
        else: 
            self._log.info("!!No new vuln found!!")
        return {"artifacts": res}

    def upsert_finding_id(self,responses):

        # Update the finding id if already there and updated else add the finding id.
        for res in responses["artifacts"]:
            jql = 'project = "{key}" AND key = "{external_id}"'.format(
                    key=self._project['key'],
                    external_id=res["external_id"])
            fields = {}
            fields[self.jira_field_name_mapping["Tenable Finding ID"]]=res.get("finding_id")
            issue = self._jira.issues.upsert(jql=jql,fields=fields)
            self._log.info("finding_id added/updated for jira %s issue= %s",res["external_id"],issue)

    def ingest(self, observed_since, first_discovery):
        '''
        Perform the vuln ingestion and transformation.

        Args:
            observed_since (int):
                Unix Timestamp detailing the threshold for vuln age.
            first_discovery (bool):
                Whether to add all observed vulns or only those identified
                for the first time within the age threshold.
        '''
        observed_since = int(observed_since)
        tags = list()
        self.new_vuln.clear() # For fetching new vulns, removing existing.
        for tag in self.config['tenable'].get('tio_tags', list()):
            tags.append((tag['key'], tag['value']))
        # if the source instance is a Tenable.io object, then we will initiate
        # the appropriate export calls.
        if isinstance(self._src, TenableIO):

            live = self._src.exports.assets(
                updated_at=observed_since,
                chunk_size=self.config['tenable'].get('chunk_size', 1000),
                tags=tags
            )

            deleted = self._src.exports.assets(
                deleted_at=observed_since,
                chunk_size=self.config['tenable'].get('chunk_size', 1000)
            )

            terminated = self._src.exports.assets(
                terminated_at=observed_since,
                chunk_size=self.config['tenable'].get('chunk_size', 1000)
            )

            # First we will iterate over the terminated and deleted assets and
            # build a cache of assets to ignore.  In order to do so, we will
            # need to gather the correct field name and id from the config.
            field = None
            for f in self.config['fields']:
                if (f.get('tio_field') == 'asset.uuid'
                  and f.get('type') == 'labels'):
                    field = (f.get('jira_id'), f.get('jira_field'))

            # if we found the field data, then we will iterate through both the
            # deleted and terminated assets and construct a JQL query to remove
            # them.
            if field:
                for dataset in (terminated, deleted):
                    for asset in dataset:
                        self._termed_assets.append(asset['id'])

            # In order to support tagging, we need to build a localized cache of
            # the asset UUIDs and store a list of the unique tag pairs for each.
            # In order to make this simple for Jira, we will be smashing the
            # category and value together and storing the uniques.
            trans_list = self.config['tenable'].get('tio_transform_tags', list())
            acache = self._asset_cache
            for asset in live:
                # if the asset doesn't exist in the tag cache, then we will
                # create the entry and store an empty list.
                if asset['id'] not in acache:
                    acache[asset['id']] = dict(tags=list())

                for a in self.config['tenable'].get('tio_asset_attr_cache', list()):
                    acache[asset['id']][a] = asset.get(a)

                # iterate over the tags
                for tag in asset['tags']:
                    # Generate the tag name to use.
                    tag_name = '{key}:{value}'.format(
                        key=tag['key'].replace(' ', '_'),
                        value=tag['value'].replace(' ', '_')
                    )

                    # If the tag name isn't in the cached list, then add it.
                    if tag_name not in acache[asset['id']]['tags']:
                        acache[asset['id']]['tags'].append(tag_name)

                    # If the tag category is in the list of transformable tags,
                    # we will then also convert it into a asset attribute for
                    # use as a custom field.
                    if tag['key'] in trans_list:
                        acache[asset['id']][tag['key']] = tag['value']

            if self.config.get('dry_run', False):
                self._log.debug(f'{json.dumps(self._asset_cache)}')

            # generate a an export for the open and reopened vulns that match
            # the criticality rating described. Then pass the export iterator
            # to the create_issues method.
            disc = 'first_found' if first_discovery else 'last_found'
            vexport = {
                'include_unlicensed': True,
                disc: observed_since,
                'severity': self.config['tenable']['tio_severities'],
                'num_assets': self.config['tenable'].get('chunk_size', 1000),
            }
            if self.config['tenable'].get('tio_vpr_thresh'):
                vexport['vpr'] = {
                    'gte': self.config['tenable'].get('tio_vpr_thresh')
                }
            if tags:
                vexport['tags'] = tags

            self._log.info('Updating and creating issues marked as Open')
            self.create_issues(self._src.exports.vulns(**vexport))

            # TODO: It replaced for the testing purpose only, need to update the API call once we get the actual one.
            if self.fetch_pending_artifacts:
                upsert_user_action_issues = self.first_discovery_user_action_upsert_call()
                self.create_issues(upsert_user_action_issues)

            # TODO: Implement POST call and send these list of vuln to tenable. 
            if self.update_jira_status_to_tenable:
                res_tedd = self.mock_post_call(self.new_vuln)
                self.upsert_finding_id(res_tedd)

            # generate a an export for the fixed vulns that match the
            # criticality rating described. Then pass the export iterator to
            # the close_issues method.
            vexport.pop(disc)
            vexport['last_fixed'] = observed_since
            vexport['state'] = ['fixed']

            self._log.info('Closing Issues Marked as Fixed.')
            self.close_issues(self._src.exports.vulns(**vexport))

            # TODO: Update this call once we got the correct API from Tenable team.
            # Making seprate call to reduce the risk of Out of Memory issue.
            # TODO: It replaced for the testing purpose only, need to update the API call once we get the actual one.
            if self.fetch_pending_artifacts:
                closed_user_action_issues = self.closed_user_action_issue_call()
                self.close_issues(closed_user_action_issues)

            # If any assets were terminated or deleted, we will then want to
            # search for them and remove the issue tickets associated with
            # them.
            if len(self._termed_assets) > 0:
                self._log.info(' '.join([
                    'Discovered terminated or deleted assets.',
                    'Attempting to clean up orphaned issues.'
                ]))
                jql = ' '.join([
                    'project = "{key}" AND "{name}" in ({tags})'.format(
                        key=self._project['key'],
                        name=field[1],
                        tags=', '.join(['"{}"'.format(i)
                            for i in self._termed_assets])),
                    'AND status not in (Closed, Done, Resolved)'
                ])

                # We will keep calling the search API and working down the
                # issues until we have a total number of issues returned
                # equalling 0.
                resp = self._jira.issues.search(jql)
                while resp['total'] > 0:
                    self._log.info('Autoclosing {} of {} issues.'.format(
                        resp['maxResults'],
                        resp['total']
                        ))
                    for issue in resp['issues']:
                        # Close the issue, then check to see if a parent
                        # issue is associated to the closed issue ticket.
                        # if there is one, then close the parent if no open
                        # child issues exist.
                        self._close_issue(issue)
                        pid = issue['fields'].get('parent', {}).get('key')
                        if pid:
                            parent = self._jira.issues.details(pid)
                            self._close_parent(parent)

                    # Recall the search for API to look for where we are in
                    # the orphaned issues.
                    resp = self._jira.issues.search(jql)

            # Send put call of updated Jira status if update_jira_status_to_tenable is true.
            if self.update_jira_status_to_tenable:
                # Get jira cloud timezone.
                jira_cloud_server_timezone=self._jira.utils.get_timezone()
                dt = arrow.Arrow.fromtimestamp(observed_since).to(jira_cloud_server_timezone)
                issues_jql = ' '.join([
                    'project = "{key}" AND issuetype="{issuetype}" AND status changed DURING ("{updated}", now())'.format(
                        key=self._project['key'],
                        issuetype="Sub-task",
                        updated=dt.strftime("%Y/%m/%d %H:%M")),
                    'ORDER BY updated DESC'
                ])
                count = 0
                total = 100
                status_changed_issues_with_finding_id = []
                status_changed_issues_without_finding_id = []
                while count < total:
                    issue_resp = self._jira.issues.search(issues_jql,maxResults=100,startAt=count)
                    count=count+len(issue_resp['issues'])
                    total=issue_resp['total']
                    for issue in issue_resp['issues']:
                        if issue["fields"].get(self.jira_field_name_mapping["Tenable Finding ID"]):
                            status_changed_issues_with_finding_id.append(self._jira.issues.format_resp(issue,self.jira_field_name_mapping,finding_id=True))
                        else:
                            status_changed_issues_without_finding_id.append(self._jira.issues.format_resp(issue,self.jira_field_name_mapping))

                # Put call for the status changed Jiras which has finding_id.
                self.mock_put_call(status_changed_issues_with_finding_id)
                # Post call for the staus changed Jiras which don't have finding_id.
                res = self.mock_post_call(status_changed_issues_without_finding_id)
                # Update finding_id in Jira.
                self.upsert_finding_id(res)

        # if the source instance is a Tenable.sc object, then we will make the
        # appropriate analysis calls using the query id specified.
        if isinstance(self._src, TenableSC):
            # using the query specified, overload the tool and the last_seen
            # or first_seen filter to pull data from the appropriate timeframe.
            seen_filter = 'lastSeen' if not first_discovery else 'firstSeen'

            vulns = self._src.analysis.vulns(
                (seen_filter, '=', '{}-{}'.format(
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
