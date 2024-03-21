import pytest
import responses
from responses import matchers
from tenb2jira.processor import Processor


@pytest.fixture
@responses.activate
def processor(example_config):
    responses.get('https://not-jira/rest/api/3/project/VULN',
                  json={}
                  )
    responses.get('https://not-jira/rest/api/3/screens',
                  json={'values': [{'id': 1}], 'total': 1}
                  )
    responses.get('https://not-jira/rest/api/3/screens/1/tabs',
                  json=[
                      {'name': 'Vulnerability', 'id': 1},
                      {'name': 'Asset', 'id': 1}
                  ]
                  )
    responses.post('https://not-jira/rest/api/3/screens/1/tabs',
                   json={'id': 1}
                   )
    responses.post('https://not-jira/rest/api/3/screens/1/tabs/1/fields')
    responses.get('https://not-jira/rest/api/3/screens/1/tabs/1/fields',
                  json=[
                      {'id': 'customfield_1'},
                      {'id': 'customfield_2'},
                      {'id': 'customfield_3'},
                      {'id': 'customfield_4'},
                      {'id': 'customfield_5'},
                      {'id': 'customfield_6'},
                      {'id': 'customfield_7'},
                      {'id': 'customfield_8'},
                      {'id': 'customfield_9'},
                      {'id': 'customfield_10'},
                      {'id': 'customfield_11'},
                      {'id': 'customfield_12'},
                      {'id': 'customfield_13'},
                      {'id': 'customfield_14'},
                      {'id': 'customfield_15'},
                      {'id': 'customfield_16'},
                      {'id': 'customfield_17'},
                      {'id': 'customfield_18'},
                      {'id': 'customfield_19'},
                      {'id': 'customfield_20'},
                      {'id': 'customfield_21'},
                      {'id': 'customfield_22'},
                      {'id': 'customfield_23'},
                      {'id': 'customfield_24'},
                      {'id': 'customfield_25'},
                      {'id': 'customfield_26'},
                      {'id': 'customfield_27'},
                      {'id': 'customfield_28'},
                      {'id': 'customfield_29'},
                      {'id': 'customfield_30'},
                  ])
    responses.get('https://not-tenb/rest/system',
                  json={
                      'error_code': None,
                      'response': {}
                  })
    return Processor(example_config)


def test_init(processor, example_config):
    assert processor.config == example_config


@responses.activate
def test_get_closed_transition_id(processor):
    responses.get('https://not-jira/rest/api/3/issue/1/transitions',
                  json={'transitions': [
                      {'name': 'Done', 'id': 3}
                  ]})
    assert processor.get_closed_transition(1) == 3
    assert processor.config['jira']['closed_id'] == 3
    assert processor.get_closed_transition(1) == 3


@responses.activate
def test_close_task(processor):
    msg = {'content': {
        'text': 'Tenable identified the issue as resolved.',
        'type': 'text'
    }}
    responses.get('https://not-jira/rest/api/3/issue/1/transitions',
                  json={'transitions': [
                      {'name': 'Done', 'id': 3}
                  ]})
    responses.post('https://not-jira/rest/api/3/issue/1/transitions',
                   match=[
                        matchers.json_params_matcher({
                            'transition': {'id': 3},
                            'update': {
                                'comment': [
                                   {'add': {'body': {'content': [msg]}}}
                                ]}
                        })
                   ])
    processor.close_task(1)
