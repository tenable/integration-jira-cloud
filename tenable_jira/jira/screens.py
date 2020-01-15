from restfly.endpoint import APIEndpoint
from restfly.iterator import APIIterator

class ScreenIterator(APIIterator):
    limit = 100
    def _get_page(self):
        resp = self._api.get('screens', params={
            'startAt': self.limit * (self.num_pages - 1),
            'maxResults': self.limit
        }).json()
        self.total = resp['total']
        self.page = resp['values']

class ScreensAPI(APIEndpoint):
    def list(self, **kwargs):
        return ScreenIterator(
            self._api,
            limit=kwargs.get('limit', 100)
        )

    def add_field_to_default_screen(self, field_id):
        return self._api.post('screens/addToDefault/{}'.format(field_id)).json()

    def available_fields(self, id):
        return self._api.get('screens/{}/availableFields'.format(id)).json()

    def screen_tabs(self, id):
        return self._api.get('screens/{}/tabs'.format(id)).json()

    def create_tab(self, id, **kwargs):
        return self._api.post('screens/{}/tabs'.format(id), json=kwargs).json()

    def update_tab(self, screen_id, tab_id):
        return self._api.put(
            'screens/{}/tabs/{}'.format(screen_id, tab_id), json=kwargs).json()

    def delete_tab(self, screen_id, tab_id):
        self._api.delete(
            'screens/{}/tabs/{}'.format(screen_id, tab_id))

    def screen_tab_fields(self, screen_id, tab_id, **kwargs):
        return self._api.get(
            'screens/{}/tabs/{}/fields'.format(screen_id, tab_id)).json()

    def add_screen_tab_field(self, screen_id, tab_id, field_id):
        return self._api.post(
            'screens/{}/tabs/{}/fields'.format(screen_id, tab_id),
            json={'fieldId': field_id}
        ).json()

    def remove_screen_tab_field(self, screen_id, tab_id, field_id):
        return self._api.delete(
            'screens/{}/tabs/{}/fields/{}'.format(screen_id, tab_id, field_id)
        )

    def move_screen_tab(self, screen_id, tab_id, position):
        return self._api.post(
            'screens/{}/tabs/{}/move/{}'.format(screen_id, tab_id, position)
        ).json()