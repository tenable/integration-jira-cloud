import pytest
import responses
from responses.matchers import json_params_matcher, query_param_matcher
from tenb2jira.jira.api.iterator import JiraIterator, search_generator


@responses.activate
def test_jira_get_iterator(jiraapi):
    payload = {'test': 'value'}
    test_response = {
        'total': 2000,
        'envelope': [{'id': i} for i in range(1000)],
    }
    test_response2 = {
        'total': 2000,
        'envelope': [{'id': i} for i in range(1000, 2000)],
    }
    responses.get('https://nourl/rest/api/3/test',
                  json=test_response,
                  match=[query_param_matcher({
                    'test': 'value',
                    'startAt': 0,
                    'maxResults': 1000
                  })]
                  )
    responses.get('https://nourl/rest/api/3/test',
                  json=test_response2,
                  match=[query_param_matcher({
                    'test': 'value',
                    'startAt': 1000,
                    'maxResults': 1000
                  })]
                  )
    iter_obj = JiraIterator(jiraapi,
                            params={'test': 'value'},
                            _method='GET',
                            _envelope='envelope',
                            path='test'
                            )
    for obj in iter_obj:
        assert isinstance(obj.id, int)


@responses.activate
def test_jira_post_iterator(jiraapi):
    payload = {'test': 'value'}
    test_response = {
        'total': 2000,
        'envelope': [{'id': i} for i in range(1000)],
    }
    test_response2 = {
        'total': 2000,
        'envelope': [{'id': i} for i in range(1000, 2000)],
    }
    responses.post('https://nourl/rest/api/3/test',
                   json=test_response,
                   match=[json_params_matcher({
                    'test': 'value',
                    'startAt': 0,
                    'maxResults': 1000
                   })]
                   )
    responses.post('https://nourl/rest/api/3/test',
                   json=test_response2,
                   match=[json_params_matcher({
                    'test': 'value',
                    'startAt': 1000,
                    'maxResults': 1000
                   })]
                   )
    iter_obj = JiraIterator(jiraapi,
                            params={'test': 'value'},
                            _method='POST',
                            _envelope='envelope',
                            path='test'
                            )
    for obj in iter_obj:
        assert isinstance(obj.id, int)


@responses.activate
def test_search_generator(jiraapi):
    test_response = {
        'total': 2000,
        'issues': [{'id': i} for i in range(1000)],
    }
    test_response2 = {
        'total': 2000,
        'issues': [{'id': i} for i in range(1000, 2000)],
    }
    responses.post('https://nourl/rest/api/3/search',
                   json=test_response,
                   match=[json_params_matcher({
                    'jql': 'test jql search',
                    'expand': ['names'],
                    'fields': ['id'],
                    'maxResults': 1000,
                    'startAt': 0
                   })]
                   )
    responses.post('https://nourl/rest/api/3/search',
                   json=test_response2,
                   match=[json_params_matcher({
                    'jql': 'test jql search',
                    'expand': ['names'],
                    'fields': ['id'],
                    'maxResults': 1000,
                    'startAt': 1000
                   })]
                   )
    gen_obj = search_generator(api=jiraapi,
                               jql='test jql search',
                               fields=['id']
                               )
    for page in gen_obj:
        assert len(page) == 1000
