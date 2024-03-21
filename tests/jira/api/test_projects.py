import pytest
import responses
from responses import matchers
from tenb2jira.jira.api.iterator import JiraIterator


@responses.activate
def test_create(jiraapi):
    test_resp = {'id': 1}
    responses.post('https://nourl/rest/api/3/project',
                   json=test_resp,
                   match=[matchers.json_params_matcher({'test': 'value'})]
                   )
    resp = jiraapi.projects.create(test='value')
    assert resp == test_resp


@responses.activate
def testnotification_scheme(jiraapi):
    responses.get('https://nourl/rest/api/3/project/1/notificationscheme')
    jiraapi.projects.notification_scheme(project_id=1)


@responses.activate
def test_issue_type_hierarchy(jiraapi):
    responses.get('https://nourl/rest/api/3/project/1/hierarchy')
    jiraapi.projects.issue_types_hierarchy(project_id=1)


@responses.activate
def test_statuses(jiraapi):
    responses.get('https://nourl/rest/api/3/project/1/statuses')
    jiraapi.projects.statuses(project_id=1)


@responses.activate
def test_delete(jiraapi):
    responses.delete('https://nourl/rest/api/3/project/1')
    jiraapi.projects.delete(project_id=1)


@responses.activate
def test_update(jiraapi):
    responses.put('https://nourl/rest/api/3/project/1',
                  match=[matchers.json_params_matcher({'test': 'value'})]
                  )
    jiraapi.projects.update(project_id=1, test='value')


@responses.activate
def test_get(jiraapi):
    responses.get('https://nourl/rest/api/3/project/1')
    jiraapi.projects.get(project_id=1)

@responses.activate
def test_search(jiraapi):
    resp = jiraapi.projects.list(jql='this is a test')
    assert isinstance(resp, JiraIterator)
    assert resp.limit == 1000
    assert resp._envelope == 'values'
    assert resp._method == 'GET'
    assert resp.path == 'project/search'
    assert resp.params == {'jql': 'this is a test'}
