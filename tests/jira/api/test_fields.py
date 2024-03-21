import pytest
import responses
from responses import matchers


@responses.activate
def test_list(jiraapi):
    test_list = [{'id': 1}]
    responses.get('https://nourl/rest/api/3/field', json=test_list)
    resp = jiraapi.fields.list()
    assert resp == test_list


@responses.activate
def test_create(jiraapi):
    responses.post('https://nourl/rest/api/3/field',
                   match=[
                       matchers.json_params_matcher({
                        'name': 'example',
                        'type': 'com.atlassian.jira.plugin.system.customfieldtypes:test',
                        'searcherKey': 'com.atlassian.jira.plugin.system.customfieldtypes:testsearcher',
                        'description': 'something fancy'
                       })
                   ])
    jiraapi.fields.create(name='example',
                          field_type='test',
                          searcher='testsearcher',
                          description='something fancy'
                          )


@responses.activate
def test_screens(jiraapi):
    test_list = [{'id': 1}]
    responses.get('https://nourl/rest/api/3/field/1/screens', json=test_list)
    resp = jiraapi.fields.screens(1)
    assert resp == test_list
