from typing import TYPE_CHECKING

from restfly.iterator import APIIterator

if TYPE_CHECKING:
    from .session import JiraAPI


class JiraIterator(APIIterator):
    limit = 100

    def _get_page(self):
        params = self.params
        params["startAt"] = self.limit * self.num_pages
        params["maxResults"] = self.limit
        match self._method:
            case "GET":
                resp = self._api.get(self.path, params=params)
            case "POST":
                resp = self._api.post(self.path, json=params)
        self.total = resp["total"]
        self.page = resp[self._envelope]


class JiraSearchIterator(APIIterator):
    limit: int = 100
    token: str | None = None

    def _get_page(self):
        req = self.params
        req["maxResults"] = self.limit
        req["nextPageToken"] = self.token

        if self.num_pages > 0 and not self.token:
            raise StopIteration()

        match self._method:
            case "GET":
                resp = self._api.get(self.path, params=req)
            case "POST":
                resp = self._api.post(self.path, json=req)
        self.page = resp[self._envelope]


def search_generator(api: "JiraAPI", jql: dict, fields: list[str], limit: int = 100):
    query = {
        "jql": jql,
        "expand": ["names"],
        "fields": fields,
        "maxResults": limit,
        "use_iter": False,
    }
    max_results = 1
    counter = 0
    page_counter = 0
    page = None
    token = None
    while token is not None or page_counter == 0:
        if token:
            query["nextPageToken"] = token
        page = api.issues.search(**query)
        page_counter += 1
        token = page.get("nextPageToken")
        yield page.issues, -1, page_counter
