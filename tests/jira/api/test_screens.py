import pytest
import responses
from responses import matchers
from tenb2jira.jira.api.iterator import JiraIterator


@responses.activate
def test_move_screen_tab(jiraapi):
    responses.post('https://nourl/rest/api/3/screens/1/tabs/2/move/3')
    jiraapi.screens.move_screen_tab(screen_id=1,
                                    tab_id=2,
                                    position=3
                                    )


@responses.activate
def test_remove_screen_tab_field(jiraapi):
    responses.delete('https://nourl/rest/api/3/screens/1/tabs/2/fields/3')
    jiraapi.screens.remove_screen_tab_field(screen_id=1,
                                            tab_id=2,
                                            field_id=3
                                            )


@responses.activate
def test_add_screen_tab_field(jiraapi):
    responses.post('https://nourl/rest/api/3/screens/1/tabs/2/fields',
                   match=[matchers.json_params_matcher({'fieldId': 3})]
                   )
    jiraapi.screens.add_screen_tab_field(screen_id=1,
                                         tab_id=2,
                                         field_id=3
                                         )


@responses.activate
def test_screen_tab_fields(jiraapi):
    test_resp = [{'id': 1}]
    responses.get('https://nourl/rest/api/3/screens/1/tabs/2/fields',
                  json=test_resp,
                  )
    resp = jiraapi.screens.screen_tab_fields(screen_id=1, tab_id=2)
    assert resp == test_resp


@responses.activate
def test_delete_tab(jiraapi):
    responses.delete('https://nourl/rest/api/3/screens/1/tabs/2')
    jiraapi.screens.delete_tab(screen_id=1, tab_id=2)


@responses.activate
def test_update_tab(jiraapi):
    responses.put('https://nourl/rest/api/3/screens/1/tabs/2',
                  match=[matchers.json_params_matcher({'test': 'value'})]
                  )
    jiraapi.screens.update_tab(screen_id=1, tab_id=2, test='value')


@responses.activate
def test_create_tab(jiraapi):
    test_resp = {'id': 1}
    responses.post('https://nourl/rest/api/3/screens/1/tabs',
                   json=test_resp,
                   match=[matchers.json_params_matcher({'test': 'value'})]
                   )
    resp = jiraapi.screens.create_tab(screen_id=1, test='value')
    assert resp == test_resp


@responses.activate
def test_screen_tabs(jiraapi):
    test_resp = [{'id': 1}]
    responses.get('https://nourl/rest/api/3/screens/1/tabs', json=test_resp)
    resp = jiraapi.screens.screen_tabs(screen_id=1)
    assert resp == test_resp


@responses.activate
def test_available_fields(jiraapi):
    test_resp = [{'id': 1}]
    responses.get('https://nourl/rest/api/3/screens/1/availableFields',
                  json=test_resp
                  )
    resp = jiraapi.screens.available_fields(screen_id=1)
    assert resp == test_resp


@responses.activate
def test_add_field_to_default_screen(jiraapi):
    responses.post('https://nourl/rest/api/3/screens/addToDefault/1')
    jiraapi.screens.add_field_to_default_screen(field_id=1)


@responses.activate
def test_search(jiraapi):
    resp = jiraapi.screens.search(jql='this is a test')
    assert isinstance(resp, JiraIterator)
    assert resp.limit == 100
    assert resp._envelope == 'values'
    assert resp._method == 'GET'
    assert resp.path == 'screens'
    assert resp.params == {'jql': 'this is a test'}
