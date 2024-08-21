import pytest
import responses
from box import Box
from restfly.utils import dict_flatten
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
        'priority': {'id': '1'},
    }
    assert tobj.priority == '1'
    jql = ('project = "VULN" AND issuetype = "Task" '
           'AND "Test Field" ~ "something"')
    assert tobj.jql_stmt == jql


@responses.activate
def test_with_tvm_data(tvm_generator, example_config):
    responses.get('https://cloud.tenable.com/assets/export/0/status',
                  json={'status': 'FINISHED', 'available_chunks': []})
    fields = [Field(f,
                    platform='tvm',
                    platform_map=example_config['tenable']['platforms'])
              for f in example_config['jira']['fields']
              ]
    task = Task(config=example_config['jira']['task'],
                jira_config=example_config['jira'],
                platform='tvm',
                fields=fields
                )
    subtask = Task(config=example_config['jira']['subtask'],
                   jira_config=example_config['jira'],
                   platform='tvm',
                   fields=fields
                   )
    finding = next(tvm_generator)
    rtask = task.generate(finding)
    rsubtask = subtask.generate(finding)
    assert rtask.fields == {
        'customfield_1': ['7f68f334-17ba-4ba0-b057-b77ddd783e60'],
        'customfield_2': ['Location:Illinois', 'Test_Value:Something'],
        'customfield_3': 'Tenable Vulnerability Management',
        'customfield_4': ['hostname'],
        'customfield_5': None,
        'customfield_6': 'hostname.fqdn',
        'customfield_7': ['192.168.0.1', '192.168.0.2'],
        'customfield_8': ['2001:0db8:85a3:0000:0000:8a2e:0370:7334',
                          '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
                          ],
        'customfield_9': '00000000-0000-0000-0000-000000000000',
        'customfield_10': None,
        'customfield_11': None,
        'customfield_12': ['CVE-2024-4367',
                           'CVE-2024-4764',
                           'CVE-2024-4765',
                           'CVE-2024-4766',
                           'CVE-2024-4767',
                           'CVE-2024-4768',
                           'CVE-2024-4769',
                           'CVE-2024-4770',
                           'CVE-2024-4771',
                           'CVE-2024-4772',
                           'CVE-2024-4773',
                           'CVE-2024-4774',
                           'CVE-2024-4775',
                           'CVE-2024-4776',
                           'CVE-2024-4777',
                           'CVE-2024-4778',
                           ],
        'customfield_13': 9.2,
        'customfield_14': 6.4,
        'customfield_15': 5.0,
        'customfield_16': 6.5,
        'customfield_17': 5.9,
        'customfield_18': '51192',
        'customfield_19': 'General',
        'customfield_20': 'SSL Certificate Cannot Be Trusted',
        'customfield_21': 'medium',
        'customfield_22': '2024-03-15T17:19:03.936+0000',
        'customfield_23': '2024-04-16T17:34:40.250+0000',
        'customfield_24': None,
        'customfield_25': 'OPEN',
        'customfield_26': '1443',
        'customfield_27': 'TCP',
        'customfield_28': None,
        'customfield_29': 'medium',
        'customfield_30': 'dd13a88d-2fbf-3d2a-930f-38fdc850f86d',
        'issuetype': {'id': 10101},
        'priority': {'id': '3'},
        'project': {'key': 'VULN'},
        'summary': '[51192] SSL Certificate Cannot Be Trusted',
        'description': {
            'content': [
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Description', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'description', 'type': 'text'}],
                    'type': 'paragraph',
                },
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Solution', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'solution', 'type': 'text'}],
                    'type': 'paragraph',
                },
            ],
            'type': 'doc',
            'version': 1,
        },
    }
    assert rsubtask.fields == {
        'customfield_1': ['7f68f334-17ba-4ba0-b057-b77ddd783e60'],
        'customfield_2': ['Location:Illinois', 'Test_Value:Something'],
        'customfield_3': 'Tenable Vulnerability Management',
        'customfield_4': ['hostname'],
        'customfield_5': None,
        'customfield_6': 'hostname.fqdn',
        'customfield_7': ['192.168.0.1', '192.168.0.2'],
        'customfield_8': ['2001:0db8:85a3:0000:0000:8a2e:0370:7334',
                          '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
                          ],
        'customfield_9': '00000000-0000-0000-0000-000000000000',
        'customfield_10': None,
        'customfield_11': None,
        'customfield_12': ['CVE-2024-4367',
                           'CVE-2024-4764',
                           'CVE-2024-4765',
                           'CVE-2024-4766',
                           'CVE-2024-4767',
                           'CVE-2024-4768',
                           'CVE-2024-4769',
                           'CVE-2024-4770',
                           'CVE-2024-4771',
                           'CVE-2024-4772',
                           'CVE-2024-4773',
                           'CVE-2024-4774',
                           'CVE-2024-4775',
                           'CVE-2024-4776',
                           'CVE-2024-4777',
                           'CVE-2024-4778',
                           ],
        'customfield_13': 9.2,
        'customfield_14': 6.4,
        'customfield_15': 5.0,
        'customfield_16': 6.5,
        'customfield_17': 5.9,
        'customfield_18': '51192',
        'customfield_19': 'General',
        'customfield_20': 'SSL Certificate Cannot Be Trusted',
        'customfield_21': 'medium',
        'customfield_22': '2024-03-15T17:19:03.936+0000',
        'customfield_23': '2024-04-16T17:34:40.250+0000',
        'customfield_24': None,
        'customfield_25': 'OPEN',
        'customfield_26': '1443',
        'customfield_27': 'TCP',
        'customfield_28': None,
        'customfield_29': 'medium',
        'customfield_30': 'dd13a88d-2fbf-3d2a-930f-38fdc850f86d',
        'issuetype': {'id': 10102},
        'priority': {'id': '3'},
        'project': {'key': 'VULN'},
        'summary': '[hostname/1443/TCP] [51192] SSL Certificate Cannot Be Trusted',
        'description': {
            'content': [
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Description', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'description', 'type': 'text'}],
                    'type': 'paragraph',
                },
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Solution', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'solution', 'type': 'text'}],
                    'type': 'paragraph',
                },
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Output', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'output', 'type': 'text'}],
                    'type': 'paragraph',
                },
            ],
            'type': 'doc',
            'version': 1,
        },
    }


@responses.activate
def test_with_tsc_data(tsc_generator, example_config):
    fields = [Field(f,
                    platform='tsc',
                    platform_map=example_config['tenable']['platforms'])
              for f in example_config['jira']['fields']
              ]
    task = Task(config=example_config['jira']['task'],
                jira_config=example_config['jira'],
                platform='tsc',
                fields=fields
                )
    subtask = Task(config=example_config['jira']['subtask'],
                   jira_config=example_config['jira'],
                   platform='tsc',
                   fields=fields
                   )
    finding = next(tsc_generator)
    rtask = task.generate(finding)
    rsubtask = subtask.generate(finding)

    assert repr(rtask) == ('Task("project = "VULN" AND issuetype = "Task" AND '
                           '"Tenable Plugin ID" ~ "123560"", 35)'
                           )
    assert rtask.fields == {
        'customfield_1': ['d90cdab5-b745-3e7e-9268-aa0f445ed924'],
        'customfield_2': None,
        'customfield_3': 'Tenable Security Center',
        'customfield_4': ['target-cent7.incus'],
        'customfield_5': None,
        'customfield_6': 'target-cent7.incus',
        'customfield_7': ['10.238.64.10'],
        'customfield_8': None,
        'customfield_9': None,
        'customfield_10': '1',
        'customfield_11': 'Main',
        'customfield_12': ['CVE-2019-3855',
                           'CVE-2019-3856',
                           'CVE-2019-3857',
                           'CVE-2019-3863'
                           ],
        'customfield_13': None,
        'customfield_14': 9.3,
        'customfield_15': 6.9,
        'customfield_16': 8.8,
        'customfield_17': 7.7,
        'customfield_18': '123560',
        'customfield_19': None,
        'customfield_20': 'CentOS 7 : libssh2 (CESA-2019:0679)',
        'customfield_21': 'High',
        'customfield_22': '2024-02-23T05:03:40.000+0000',
        'customfield_23': '2024-04-04T05:05:26.000+0000',
        'customfield_24': None,
        'customfield_25': 'open',
        'customfield_26': '0',
        'customfield_27': 'TCP',
        'customfield_28': '2019-04-01',
        'customfield_29': 'High',
        'customfield_30': 'bd371510-001f-3c13-86f4-20883ef0cd09',
        'issuetype': {'id': 10101},
        'priority': {'id': '2'},
        'project': {'key': 'VULN'},
        'summary': '[123560] CentOS 7 : libssh2 (CESA-2019:0679)',
        'description': {
            'content': [
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Description', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'No Output', 'type': 'text'}],
                    'type': 'paragraph',
                },
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Solution', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{
                        'text': 'Update the affected libssh2 packages.',
                        'type': 'text'
                    }],
                    'type': 'paragraph',
                },
            ],
            'type': 'doc',
            'version': 1,
        },
    }
    assert rsubtask.fields == {
        'customfield_1': ['d90cdab5-b745-3e7e-9268-aa0f445ed924'],
        'customfield_2': None,
        'customfield_3': 'Tenable Security Center',
        'customfield_4': ['target-cent7.incus'],
        'customfield_5': None,
        'customfield_6': 'target-cent7.incus',
        'customfield_7': ['10.238.64.10'],
        'customfield_8': None,
        'customfield_9': None,
        'customfield_10': '1',
        'customfield_11': 'Main',
        'customfield_12': ['CVE-2019-3855',
                           'CVE-2019-3856',
                           'CVE-2019-3857',
                           'CVE-2019-3863'
                           ],
        'customfield_13': None,
        'customfield_14': 9.3,
        'customfield_15': 6.9,
        'customfield_16': 8.8,
        'customfield_17': 7.7,
        'customfield_18': '123560',
        'customfield_19': None,
        'customfield_20': 'CentOS 7 : libssh2 (CESA-2019:0679)',
        'customfield_21': 'High',
        'customfield_22': '2024-02-23T05:03:40.000+0000',
        'customfield_23': '2024-04-04T05:05:26.000+0000',
        'customfield_24': None,
        'customfield_25': 'open',
        'customfield_26': '0',
        'customfield_27': 'TCP',
        'customfield_28': '2019-04-01',
        'customfield_29': 'High',
        'customfield_30': 'bd371510-001f-3c13-86f4-20883ef0cd09',
        'issuetype': {'id': 10102},
        'priority': {'id': '2'},
        'project': {'key': 'VULN'},
        'summary': '[10.238.64.10/0/TCP] [123560] CentOS 7 : libssh2 (CESA-2019:0679)',
        'description': {
            'content': [
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Description', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'No Output', 'type': 'text'}],
                    'type': 'paragraph',
                },
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Solution', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{
                        'text': 'Update the affected libssh2 packages.',
                        'type': 'text'
                    }],
                    'type': 'paragraph',
                },
                {
                    'attrs': {'level': 1},
                    'content': [{'text': 'Output', 'type': 'text'}],
                    'type': 'heading',
                },
                {
                    'content': [{'text': 'test output', 'type': 'text'}],
                    'type': 'paragraph',
                },
            ],
            'type': 'doc',
            'version': 1,
        },
    }
