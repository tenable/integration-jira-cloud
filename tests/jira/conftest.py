import pytest
from tenb2jira.jira.api.session import JiraAPI


@pytest.fixture
def jiraapi():
    return JiraAPI(url='https://nourl', username='user', token='token')
