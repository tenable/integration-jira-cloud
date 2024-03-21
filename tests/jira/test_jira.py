import logging
import pytest
import responses
from responses import matchers
from box import Box
from tenb2jira.jira.jira import Jira
from tenb2jira.jira.field import Field


@pytest.fixture
def jira_config():
    return {
        'tenable': {
            'platform': 'tvm',
            'platforms': {'tvm': 'Tenable Vulnerability Managmenet'},
        },
        'jira': {
            'url': 'https://nourl',
            'api_username': 'noone',
            'api_token': 'abcdef',
            'severity_map': {'critical': 1, 'high': 2, 'medium': 3, 'low': 4},
            'state_map': {'open': True, 'reopened': True, 'fixed': False},
            'closed': 'Done',
            'closed_map': ['Closed', 'Done', 'Resolved'],
            'closed_message': 'Test Message',
            'project': {
                'key': 'VULN',
                'lead_account_id': 'abcdef',
                'name': 'Test Project',
                'description': 'Something Interesting',
                'url': 'https://tenable.com',
                'assignee': 'UNASSIGNED',
                'type_key': 'business',
                'template_key': 'test-task-tracking'
            },
            'task': {
                'id': 1,
                'name': 'Task',
                'type': 'task',
                'search': {
                    'tvm': ['Test Field']
                },
                'description': {
                    'tvm': [
                        {'name': 'Description', 'attr': 'description'},
                        {'name': 'Solution', 'attr': 'solution'}
                    ],
                },
                'summary': {'tvm': '[{f[name]}]'}
            },
            'subtask': {
                'id': 2,
                'name': 'Sub-task',
                'type': 'subtask',
                'search': {
                    'tvm': ['Test Field']
                },
                'description': {
                    'tvm': [
                        {'name': 'Description', 'attr': 'description'},
                        {'name': 'Solution', 'attr': 'solution'}
                    ],
                },
                'summary': {'tvm': '[{f[name]}]'}
            },
            'fields': [
                {
                    'id': 'customfield_1',
                    'name': 'Test Field',
                    'screen_tab': 'Test',
                    'type': 'readonlyfield',
                    'searcher': 'textsearcher',
                    'task_types': ['task', 'subtask'],
                    'attr': {'tvm': 'test1'}
                },
                {
                    'id': 'customfield_2',
                    'name': 'Test Field2',
                    'screen_tab': 'Test',
                    'type': 'readonlyfield',
                    'searcher': 'textsearcher',
                    'task_types': ['subtask'],
                    'attr': {'tvm': 'test2'}
                },
                {
                    'id': 'customfield_3',
                    'name': 'Test Severity',
                    'screen_tab': 'Test',
                    'type': 'readonlyfield',
                    'searcher': 'textsearcher',
                    'task_types': ['task', 'subtask'],
                    'attr': {'tvm': 'test3'},
                    'map_to_priority': True
                },
                {
                    'id': 'customfield_4',
                    'name': 'Test State',
                    'screen_tab': 'Test2',
                    'type': 'readonlyfield',
                    'searcher': 'textsearcher',
                    'task_types': ['subtask'],
                    'attr': {'tvm': 'test4'},
                    'map_to_state': True
                }
            ]
        }
    }


def test_jira_init(jira_config):
    jira = Jira(jira_config)
    assert jira.config == jira_config


@responses.activate
def test_jira_get_project(jira_config):
    responses.get('https://nourl/rest/api/3/project/VULN',
                  json={'id': 1})
    jira = Jira(jira_config)
    jira.get_project()
    assert jira.project == {'id': 1}
    responses.get('https://nourl/rest/api/3/project/VULN',
                  status=404)
    responses.post('https://nourl/rest/api/3/project', json={'id': 2})
    jira.get_project()
    assert jira.project == {'id': 2}


def test_jira_build_fields(jira_config):
    jira = Jira(jira_config)
    jira.build_fields()
    assert len(jira.fields) == 4
    fids = [f.id for f in jira.fields]
    assert 'customfield_4' in fids
    assert 'customfield_3' in fids
    assert 'customfield_2' in fids
    assert 'customfield_1' in fids


def test_jira_fieldmaps(jira_config):
    jira = Jira(jira_config)
    jira.build_fields()
    assert jira.field_by_id_map['customfield_4'].name == 'Test State'
    assert jira.field_by_name_map['Test Severity'].id == 'customfield_3'


def test_jira_build_tasks(jira_config):
    jira = Jira(jira_config)
    jira.project = {'id': 1}
    jira.build_fields()
    jira.build_tasks()
    assert jira.task.id == 1
    assert jira.subtask.id == 2
    assert [f.id for f in jira.task.fields] == ['customfield_1',
                                                'customfield_3'
                                                ]
    assert [f.id for f in jira.subtask.fields] == ['customfield_1',
                                                   'customfield_2',
                                                   'customfield_3',
                                                   'customfield_4'
                                                   ]


@responses.activate
def test_jira_setup(jira_config, caplog):
    responses.get('https://nourl/rest/api/3/project/VULN',
      json={'id': 1})
    responses.get('https://nourl/rest/api/3/screens',
                  match=[
                      matchers.query_param_matcher({
                          'queryString': 'VULN:',
                          'startAt': 0,
                          'maxResults': 100
                      })
                  ],
                  json={'values': [{'id': 1}], 'total': 1}
                  )
    responses.get('https://nourl/rest/api/3/screens/1/tabs',
                  json=[{'name': 'Test', 'id': 100}]
                  )
    responses.post('https://nourl/rest/api/3/screens/1/tabs',
                   json={'id': 101}
                   )
    responses.get('https://nourl/rest/api/3/screens/1/tabs/100/fields',
                  json=[{'id': 'customfield_1'},
                        {'id': 'customfield_2'},
                        ]
                  )
    responses.post('https://nourl/rest/api/3/screens/1/tabs/100/fields',
                   match=[
                       matchers.json_params_matcher({'fieldId': 'customfield_3'})
                   ]
                   )
    responses.post('https://nourl/rest/api/3/screens/1/tabs/101/fields',
                   match=[
                       matchers.json_params_matcher({'fieldId': 'customfield_4'})
                   ]
                   )
    jira = Jira(jira_config)
    with caplog.at_level(logging.INFO):
        jira.setup()
    event_check = [
        'Creating new tab for screen 1 with the name of Test2.',
        'Adding field customfield_3:"Test Severity" to the screen tab "Test".',
        'Adding field customfield_4:"Test State" to the screen tab "Test2".'
    ]
    for line in event_check:
        assert line in caplog.text
