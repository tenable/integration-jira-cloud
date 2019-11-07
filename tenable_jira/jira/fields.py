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

    def upsert(self, fields):
        # Our first step is to pull the current field lists, look for fields
        # with the name that we expect, and then splice in the id to sub-docs.
        for item in self.list()
            if item['name'] in fields.keys():
                fields[field['name']]['jira_id'] = item['id']

        # our next step is to iterate over the _field list and then create the
        # fields that are missing.
        for name in fields.keys():
            if 'id' not in fields[name]:
                resp = self._jira.fields.create(name,
                    field_type=fields[name]['type'],
                    searcher=fields[name]['searcher'])
                fields[name]['jira_id'] = resp['id']

        return fields