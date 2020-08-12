from restfly.endpoint import APIEndpoint
from restfly.errors import NotFoundError

class ProjectsAPI(APIEndpoint):
    def list(self, **kwargs):
        return self._api.get('project', params=kwargs).json()

    def details(self, id, **kwargs):
        return self._api.get('project/{}'.format(id), params=kwargs).json()

    def update(self, id, **kwargs):
        return self._api.put('project/{}'.format(id), json=kwargs).json()

    def delete(self, id):
        return self._api.delete('project/{}'.format(id)).json()

    def statuses(self, id):
        return self._api.get('project/{}/statuses'.format(id)).json()

    def issue_types(self, id):
        return self._api.get('project/{}/hierarchy'.format(id)).json()

    def notification_scheme(self, id, **kwargs):
        return self._api.get(
            'project/{}/notificationscheme'.format(id), params=kwargs).json()

    def create(self, **kwargs):
        return self._api.post('project', json=kwargs).json()

    def upsert(self, **kwargs):
        try:
            return self.details(kwargs['key'])
        except NotFoundError as err:
            self._log.info('Creating Project {key}'.format(**kwargs))
            return self.create(**kwargs)