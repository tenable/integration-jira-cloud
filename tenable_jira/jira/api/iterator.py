from restfly.iterator import APIIterator


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
