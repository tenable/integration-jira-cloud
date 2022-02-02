from restfly.endpoint import APIEndpoint
from .utils import UtilsAPI as utils

class IssuesAPI(APIEndpoint):

    def search_validate(self, issue_ids, *jql):
        return self._api.post('jql/match', json={
            'issueIds': list(issue_ids),
            'jqls': list(jql)
        }).json()

    def search(self, jql, **kwargs):
        kwargs['jql'] = jql
        return self._api.post('search', json=kwargs).json()

    def details(self, id, **kwargs):
        return self._api.get('issue/{}'.format(id), params=kwargs).json()

    def create(self, update_history=False, **kwargs):
        return self._api.post('issue',
            params={'update_history': update_history},
            json=kwargs
        ).json()

    def update(self, id, **kwargs):
        params = {
            'notifyUsers': str(kwargs.pop('notifyUsers', True)).lower(),
            'overrideScreenSecurity': str(kwargs.pop('overrideScreenSecurity', False)).lower(),
            'overrideEditableFlag': str(kwargs.pop('overrideEditableFlag', False)).lower(),
        }
        return self._api.put('issue/{}'.format(id),
            params=params, json=kwargs)

    def get_transitions(self, id):
        return self._api.get('issue/{}/transitions'.format(id)).json()

    def transition(self, id, **kwargs):
        return self._api.post('issue/{}/transitions'.format(id), json=kwargs)

    def upsert(self, new_vuln = [], jira_field_name_mapping= {}, **kwargs):
        jql = kwargs.pop('jql')
        resp = self.search(jql)
        if resp['total'] > 0:
            issue = resp['issues'][0]
            self._log.info('UPDATED {} {}'.format(
                issue['key'], issue['fields']['summary']))
            self.update(issue['id'], **kwargs)
            return issue
        else:
            issue = self.create(**kwargs)
            self._log.info('CREATED {} {}'.format(
                issue['key'], kwargs['fields']['summary']))
            # To get issue details of Jira to send back in tenable
            issues = self.search("project={} AND key={}".format(kwargs["fields"]["project"]["key"],issue['key']))
            if issues["total"] == 1:
                issue = issues["issues"][0]
            else:
                raise Exception("Project {} having more than 1 Jira for key {}".format(kwargs["fields"]["project"]["key"],issue['key']))
            if jira_field_name_mapping:
                new_vuln.append(self.format_resp(issue,jira_field_name_mapping))
            return issue

    def format_resp(self,issue,jira_field_name_mapping,finding_id = False):
        # Form the response in structure to pass in tenable.
        res={
                "port": issue["fields"].get(jira_field_name_mapping["Vulnerability Port"]),
                "protocol": issue["fields"].get(jira_field_name_mapping["Vulnerability Protocol"]),
                "asset_id": ",".join(issue["fields"].get(jira_field_name_mapping["Tenable Asset UUID"])),
                "plugin_id": issue["fields"].get(jira_field_name_mapping["Tenable Plugin ID"]),
                "categoty": "jira",
                "source": "cloud",
                "external_id": issue["key"],
                "status": "CLOSED" if str(issue["fields"].get("status").get("statusCategory").get("key")).lower() == "done" else "ACTIVE",
                "metadata": {
                    "icon": str(utils.get_base64_code_for_url(self,issue["fields"].get("issuetype").get("iconUrl"))),
                    "key": issue["fields"].get("project").get("key"),
                    "url": issue["self"].split("rest")[0]+"browse/"+issue["key"],
                    "description": issue['fields']['summary']
                }
            }
        if finding_id:
            res["finding_id"] = issue["fields"].get(jira_field_name_mapping["Tenable Finding ID"])
        
        return res