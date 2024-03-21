import pytest
import responses
from responses import matchers



@responses.activate
def test_list(jiraapi):
    responses.get('https://nourl/rest/api/3/issuetype')
    jiraapi.issue_types.list()


@responses.activate
def test_details(jiraapi):
    responses.get('https://nourl/rest/api/3/issuetype/1')
    jiraapi.issue_types.details(issuetype_id=1)


@responses.activate
def test_create(jiraapi):
    test_resp = {'id': 1}
    responses.post('https://nourl/rest/api/3/issuetype',
                   json=test_resp,
                   match=[matchers.json_params_matcher({'test': 'value'})]
                   )
    resp = jiraapi.issue_types.create(test='value')
    assert resp == test_resp


@responses.activate
def test_update(jiraapi):
    test_resp = {'id': 1}
    responses.put('https://nourl/rest/api/3/issuetype/1',
                  json=test_resp,
                  match=[matchers.json_params_matcher({'test': 'value'})]
                  )
    resp = jiraapi.issue_types.update(issuetype_id=1, test='value')
    assert resp == test_resp


@responses.activate
def test_list_by_project(jiraapi):
    responses.get('https://nourl/rest/api/3/issuetype/project',
                  match=[matchers.query_param_matcher({'projectId': 1})]
                  )
    jiraapi.issue_types.list_by_project(project_id=1)
