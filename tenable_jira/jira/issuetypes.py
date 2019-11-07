from restfly.endpoint import APIEndpoint

class IssueTypesAPI(APIEndpoint):
    def list(self):
        return self._api.get('issuetypes').json()

    def details(self, id):
        return self._api.get('isuetype/{}'.format(id)).json()

    def create(self, **kwargs):
        return self._api.post('issuetype', json=kwargs).json()

    def update(self, id, **kwargs):
        return self._api.put('issuetype/{}'.format(id), json=kwargs).json()

    def upsert(self, issuetypes):
        itypes = self._list()
        for issuetype in issuetypes:
            for itype in itypes:
                if (itype['name'] == issuetype['name']
                  or itype['id'] == issuetype['jira_id']):
                    issuetype['jira_id'] = itype['id']

        for issuetype in issuetypes:
            if 'jira_id' not in issuetype:
                newtype = self.create(
                    name=issuetype['name'],
                    description=issuetype.get('description', ''),
                    type=issuetype['type']
                )
                issuetype['jira_id'] = newtype['id']
        return issuetypes
