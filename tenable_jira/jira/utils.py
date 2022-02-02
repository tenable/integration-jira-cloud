from restfly.endpoint import APIEndpoint
from urllib.request import urlopen 
import base64

class UtilsAPI(APIEndpoint):

    def get_timezone(self):
        # Fetching Jira Cloud's timezone.
        resp = self._api.get('myself').json()
        return resp["timeZone"]

    def get_base64_code_for_url(self, url):
        try:
            # fetch icon details from the IconURL call. 
            return base64.b64encode(urlopen(url).read())
        except Exception:
            # Passing icon as None in case of iconUrl call failure.
            return None