from typing import List, Dict
from restfly.endpoint import APIEndpoint


class IssueTypesAPI(APIEndpoint):
    _path = 'issuetype'

    def list(self) -> List[Dict]:
        return self._get()

    def details(self, issuetype_id: int) -> Dict:
        return self._get(f'{issuetype_id}')

    def create(self, **kwargs) -> Dict:
        return self._post(json=kwargs)

    def update(self, issuetype_id: int, **kwargs) -> Dict:
        return self._put(f'{issuetype_id}', json=kwargs)

    def list_by_project(self, project_id, **kwargs) -> List[Dict]:
        return self._get('project', params={'projectId': project_id})

