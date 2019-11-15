from restfly.endpoint import APIEndpoint

class IssuesAPI(APIEndpoint):
    def search_validate(self, issue_ids, *jql):
        return self._api.post('jql/match', json={
            'issueIds': list(issue_ids),
            'jqls': list(jqls)
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

    def upsert(self, **kwargs):
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
            return issue

