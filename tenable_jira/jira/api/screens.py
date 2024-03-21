from typing import List, Dict
from restfly.endpoint import APIEndpoint
from .iterator import JiraIterator

class ScreensAPI(APIEndpoint):
    _path = 'screens'

    def search(self, **kwargs):
        limit = kwargs.pop('limit', 100)
        return JiraIterator(
            self._api,
            _method='GET',
            _envelope='values',
            path='screens',
            limit=limit,
            params=kwargs
        )

    def add_field_to_default_screen(self, field_id: str) -> Dict:
        return self._post(f'addToDefault/{field_id}')

    def available_fields(self, screen_id: int) -> List[Dict]:
        return self._get(f'{str(screen_id)}/availableFields')

    def screen_tabs(self, screen_id: int) -> List[Dict]:
        return self._get(f'{str(screen_id)}/tabs')

    def create_tab(self, screen_id: int, **kwargs) -> Dict:
        return self._post(f'{screen_id}/tabs', json=kwargs)

    def update_tab(self, screen_id: int, tab_id: int, **kwargs) -> Dict:
        return self._put(f'{str(screen_id)}/tabs/{str(tab_id)}', json=kwargs)

    def delete_tab(self, screen_id: int, tab_id: int) -> None:
        self._delete(f'{str(screen_id)}/tabs/{str(tab_id)}')

    def screen_tab_fields(self, screen_id, tab_id, **kwargs) -> List[Dict]:
        return self._get(f'{str(screen_id)}/tabs/{str(tab_id)}/fields')

    def add_screen_tab_field(self,
                             screen_id: int,
                             tab_id: int,
                             field_id: int
                             ) -> Dict:
        return self._post(f'{str(screen_id)}/tabs/{str(tab_id)}/fields',
                          json={'fieldId': field_id}
                          )

    def remove_screen_tab_field(self,
                                screen_id: int,
                                tab_id: int,
                                field_id: int
                                ) -> Dict:
        return self._delete(
            f'{str(screen_id)}/tabs/{str(tab_id)}/fields/{str(field_id)}'
        )

    def move_screen_tab(self,
                        screen_id: int,
                        tab_id: int,
                        position: int
                        ):
        return self._post(
            f'{str(screen_id)}/tabs/{str(tab_id)}/move/{str(position)}'
        )
