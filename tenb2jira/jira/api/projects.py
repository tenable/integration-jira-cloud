from typing import List, Dict
from restfly.endpoint import APIEndpoint
from .iterator import JiraIterator


class ProjectsAPI(APIEndpoint):
    _path = 'project'

    def list(self, **kwargs):
        limit = kwargs.pop('limit', 1000)
        return JiraIterator(
            self._api,
            _envelope='values',
            _method='GET',
            path='project/search',
            limit=limit,
            params=kwargs
        )

    def get(self, project_id: int, **kwargs) -> Dict:
        return self._get(f'{str(project_id)}', params=kwargs)

    def update(self, project_id: int, **kwargs) -> Dict:
        return self._put(f'{str(project_id)}', json=kwargs)

    def delete(self, project_id: int) -> Dict:
        return self._delete(f'{str(project_id)}')

    def statuses(self, project_id: int) -> List[Dict]:
        return self._get(f'{str(project_id)}/statuses')

    def issue_types_hierarchy(self, project_id: int) -> List[Dict]:
        return self._get(f'{str(project_id)}/hierarchy')

    def notification_scheme(self, project_id: int, **kwargs) -> Dict:
        return self._get(f'{str(project_id)}/notificationscheme',
                         params=kwargs
                         )

    def create(self, **kwargs) -> Dict:
        return self._post(json=kwargs)
