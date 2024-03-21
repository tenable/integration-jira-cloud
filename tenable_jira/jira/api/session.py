from restfly.session import APISession
from .fields import FieldsAPI
from .issues import IssuesAPI
from .issuetypes import IssueTypesAPI
from .projects import ProjectsAPI
from .screens import ScreensAPI


class JiraAPI(APISession):
    _base_path = 'rest/api/3'
    _box = True

    def _authenticate(self, username, token):
        self._session.auth = (username, token)

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
