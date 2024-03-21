import pytest
import responses
from box import Box
from tenb2jira.jira.task import Task, TaskInstance
from tenb2jira.jira.field import Field


@pytest.fixture
def task_config():
    return {
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
    }


@pytest.fixture
def jira_config():
    return {
        'project': {'key': 'VULN'},
        'severity_map': {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4
        },
        'state_map': {
            'open': True,
            'reopened': True,
            'fixed': False
        }
    }


@pytest.fixture
def test_fields():
    config = [
        {
            'id': 'customfield_1',
            'name': 'Test Field',
            'screen_tab': 'Test',
            'type': 'readonlyfield',
            'searcher': 'textsearcher',
            'task_types': ['task'],
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
            'task_types': ['task'],
            'attr': {'tvm': 'test3'},
            'map_to_priority': True
        },
        {
            'id': 'customfield_4',
            'name': 'Test State',
            'screen_tab': 'Test',
            'type': 'readonlyfield',
            'searcher': 'textsearcher',
            'task_types': ['task'],
            'attr': {'tvm': 'test4'},
            'map_to_state': True
        }
    ]
    return [Field(f, platform='tvm', platform_map={}) for f in config]


@pytest.fixture
def test_description():
    return {
        'version': 1,
        'type': 'doc',
        'content': [
            {
                'type': 'heading',
                'attrs': {'level': 1},
                'content': [{
                    'type': 'text',
                    'text': 'Description'
                }]
            },
            {
                'type': 'paragraph',
                'content': [{
                    'type': 'text',
                    'text': 'Test Description'
                }]
            },
            {
                'type': 'heading',
                'attrs': {'level': 1},
                'content': [{
                    'type': 'text',
                    'text': 'Solution'
                }]
            },
            {
                'type': 'paragraph',
                'content': [{
                    'type': 'text',
                    'text': 'Test Solution'
                }]
            },
        ]
    }


def test_task_noapi(jira_config, task_config, test_fields):
    task = Task(config=task_config,
                jira_config=jira_config,
                platform='tvm',
                fields=test_fields
                )
    assert task.id == 1
    assert task.name == 'Task'
    assert task.project_key == 'VULN'
    assert task.search == ['Test Field']
    assert task.description == task_config['description']['tvm']
    assert task.fields == test_fields

    del(task_config['id'])
    project = Box({
        'issueTypes': [{'name': 'Task', 'id': 1}]
    })
    task = Task(config=task_config,
                jira_config=jira_config,
                platform='tvm',
                fields=test_fields,
                project=project
                )
    assert task.id == 1
    assert task.name == 'Task'
    assert task.project_key == 'VULN'
    assert task.search == ['Test Field']
    assert task.description == task_config['description']['tvm']
    assert task.fields == test_fields

    project = Box({
        'issueTypes': [{'name': 'Sub-task', 'id': 1}]
    })
    with pytest.raises(AttributeError):
        task = Task(config=task_config,
                    jira_config=jira_config,
                    platform='tvm',
                    fields=test_fields,
                    project=project
                    )


def test_gen_description(jira_config,
                         task_config,
                         test_fields,
                         test_description
                         ):
    task = Task(config=task_config,
                jira_config=jira_config,
                platform='tvm',
                fields=test_fields
                )
    finding = {
        'description': 'Test Description',
        'solution': 'Test Solution'
    }
    assert task.gen_description(finding) == test_description


def test_gen_summary(jira_config, task_config, test_fields):
    task = Task(config=task_config,
                jira_config=jira_config,
                platform='tvm',
                fields=test_fields
                )
    finding = {'name': 'Test Name'}
    assert task.gen_summary(finding) == '[Test Name]'


def test_generate(jira_config,
                  task_config,
                  test_fields,
                  test_description
                  ):
    task = Task(config=task_config,
                jira_config=jira_config,
                platform='tvm',
                fields=test_fields
                )
    finding = {
        'name': 'Test Name',
        'description': 'Test Description',
        'solution': 'Test Solution',
        'test1': 'something',
        'test2': 'else',
        'test3': 'critical',
        'test4': 'OPEN',
        'bad1': 'nothing to see here',
    }
    tobj = task.generate(finding)
    assert tobj.jql == ['project = "VULN"',
                        'issuetype = "Task"',
                        '"Test Field" ~ "something"']
    assert tobj.fields == {
        'customfield_1': 'something',
        'customfield_2': 'else',
        'customfield_3': 'critical',
        'customfield_4': 'OPEN',
        'description': test_description,
        'summary': '[Test Name]',
        'project': {'key': 'VULN'},
        'issuetype': {'id': 1},
    }
    assert tobj.priority == '1'
    jql = ('project = "VULN" AND issuetype = "Task" '
           'AND "Test Field" ~ "something"')
    assert tobj.jql_stmt == jql
