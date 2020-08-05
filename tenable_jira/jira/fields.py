from restfly.endpoint import APIEndpoint

class FieldsAPI(APIEndpoint):
    def list(self):
        return self._api.get('field').json()

    def create(self, name, field_type='readonlyfield',
               searcher='textsearcher', description=None):
        return self._api.post('field', json={
            'name': name,
            'type': 'com.atlassian.jira.plugin.system.customfieldtypes:{}'.format(field_type),
            'searcherKey': 'com.atlassian.jira.plugin.system.customfieldtypes:{}'.format(searcher),
            'description': description if description else ''
        }).json()

    def screens(self, id, **kwargs):
        return self._api.get(
            'field/{}/screens'.format(id), params=kwargs).json()

    def upsert(self, fields):
        # Our first step is to pull the current field lists, look for fields
        # with the name that we expect, and then splice in the id to sub-docs.
        flist = self.list()
        for field in fields:
            f_set = False
            for item in flist:
                if item['name'] == field['jira_field'] and not f_set:
                    field['jira_id'] = item['id']
                    f_set = True
                    self._log.info('{jira_field} is {jira_id} (existing)'.format(**field))
                if f_set:
                    break


        # our next step is to iterate over the _field list and then create the
        # fields that are missing.
        for field in fields:
            if 'jira_id' not in field:
                resp = self.create(field['jira_field'],
                    field_type=field['type'],
                    searcher=field['searcher'])
                field['jira_id'] = resp['id']
                self._log.info('{jira_field} is {jira_id} (new)'.format(**field))
        return fields