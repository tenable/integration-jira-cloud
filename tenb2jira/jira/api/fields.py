from typing import Optional, List, Dict
from restfly.endpoint import APIEndpoint


CUSTOM_FIELD_TYPE = 'com.atlassian.jira.plugin.system.customfieldtypes'


class FieldsAPI(APIEndpoint):
    _path = 'field'

    def list(self) -> List[Dict]:
        return self._get()

    def create(self,
               name: str,
               field_type: str = 'readonlyfield',
               searcher: str = 'textsearcher',
               description: Optional[str] = None,
               ) -> dict:
        return self._post(json={
            'name': name,
            'type': f'{CUSTOM_FIELD_TYPE}:{field_type}',
            'searcherKey': f'{CUSTOM_FIELD_TYPE}:{searcher}',
            'description': description if description else ''
        })

    def screens(self, field_id: int, **kwargs) -> List[Dict]:
        return self._get(f'{str(field_id)}/screens', params=kwargs)
