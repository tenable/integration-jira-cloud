from typing import TYPE_CHECKING
from restfly.iterator import APIIterator

if TYPE_CHECKING:
    from .session import JiraAPI


class JiraIterator(APIIterator):
    limit = 1000

    def _get_page(self):
        params = self.params
        params['startAt'] = self.limit * self.num_pages
        params['maxResults'] = self.limit
        match self._method:
            case 'GET':
                resp = self._api.get(self.path, params=params)
            case 'POST':
                resp = self._api.post(self.path, json=params)
        self.total = resp['total']
        self.page = resp[self._envelope]


def search_generator(api: 'JiraAPI',
                     jql: dict,
                     fields: list[str],
                     limit: int = 1000
                     ):
    query = {
       'jql': jql,
       'expand': ['names'],
       'fields': fields,
       'maxResults': limit,
       'use_iter': False
    }
    max_results = 1
    counter = 0
    page_counter = 0
    page = None
    while (limit * page_counter) < max_results:
        query['startAt'] = limit * page_counter
        page = api.issues.search(**query)
        page_counter += 1
        max_results = page.total
        yield page.issues
