import pytest
import responses


@responses.activate
def test_jira_api_session(jiraapi):
    responses.get('https://nourl/rest/api/3/test')
    jiraapi.get('test')
