from restfly.session import APISession
from .fields import FieldsAPI
from .issues import IssuesAPI
from .issuetypes import IssueTypesAPI
from .projects import ProjectsAPI
from .screens import ScreensAPI

class Jira(APISession):
    def __init__(self, url, api_username, api_token, **kwargs):
        self._url = url
        self._api_token = api_token
        self._api_username = api_username
        super(Jira, self).__init__(**kwargs)

    def _build_session(self, **kwargs):
        super(Jira, self)._build_session(**kwargs)
        self._session.auth = (self._api_username, self._api_token)

    @property
    def fields(self):
        return FieldsAPI(self)

    @property
    def issues(self):
        return IssuesAPI(self)

    @property
    def issue_types(self):
        return IssueTypesAPI(self)

    @property
    def projects(self):
        return ProjectsAPI(self)

    @property
    def screens(self):
        return ScreensAPI(self)