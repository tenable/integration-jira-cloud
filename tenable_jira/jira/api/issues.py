from typing import Any, List, Dict
from restfly.endpoint import APIEndpoint
from .iterator import JiraIterator


def sbool(value: Any) -> str:
    return str(value).lower()


class IssuesAPI(APIEndpoint):
    _path = 'issue'

    def search(self,
               jql: str,
               expand: List[str],
               fields: List[str],
               **kwargs
               ) -> JiraIterator:
        kwargs['jql'] = jql
        kwargs['expand'] = expand
        kwargs['fields'] = fields
        return JiraIterator(self._api,
                            _method='POST',
                            _envelope='issues',
                            path='search',
                            params=kwargs)

    def get(self, issue_id_or_key: (str | int), **kwargs) -> Dict:
        return self._get(f'{str(issue_id_or_key)}', params=kwargs)

    def create(self, update_history: bool = False, **kwargs) -> Dict:
        return self._post(json=kwargs,
                          params={'update_history': update_history}
                          )

    def update(self,
               issue_id_or_key: (str | int),
               notify_users: bool = True,
               screen_security: bool = False,
               editable_flag: bool = False,
               **kwargs
               ) -> dict:
        return self._put(f'{str(issue_id_or_key)}',
                         json=kwargs,
                         params={
                            'notifyUsers': sbool(notify_users),
                            'overrideScreenSecurity': sbool(screen_security),
                            'overrideEditableFlag': sbool(editable_flag)
                         })

    def get_transitions(self, issue_id_or_key: (str | int)) -> List[Dict]:
        return self._get(f'{str(issue_id_or_key)}')

    def transition(self, issue_id_or_key: (str | int), **kwargs) -> Dict:
        return self._post(f'{str(issue_id_or_key)}', json=kwargs)
