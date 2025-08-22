import pytest
import responses
from responses.matchers import json_params_matcher, query_param_matcher

from tenb2jira.jira.api.iterator import JiraIterator, search_generator


@responses.activate
def test_jira_get_iterator(jiraapi):
    payload = {"test": "value"}
    test_response = {
        "total": 200,
        "envelope": [{"id": i} for i in range(100)],
    }
    test_response2 = {
        "total": 200,
        "envelope": [{"id": i} for i in range(100, 200)],
    }
    responses.get(
        "https://nourl/rest/api/3/test",
        json=test_response,
        match=[query_param_matcher({"test": "value", "startAt": 0, "maxResults": 100})],
    )
    responses.get(
        "https://nourl/rest/api/3/test",
        json=test_response2,
        match=[
            query_param_matcher({"test": "value", "startAt": 100, "maxResults": 100})
        ],
    )
    iter_obj = JiraIterator(
        jiraapi,
        params={"test": "value"},
        _method="GET",
        _envelope="envelope",
        path="test",
    )
    for obj in iter_obj:
        assert isinstance(obj.id, int)


@responses.activate
def test_jira_post_iterator(jiraapi):
    payload = {"test": "value"}
    test_response = {
        "total": 200,
        "envelope": [{"id": i} for i in range(100)],
    }
    test_response2 = {
        "total": 200,
        "envelope": [{"id": i} for i in range(100, 200)],
    }
    responses.post(
        "https://nourl/rest/api/3/test",
        json=test_response,
        match=[json_params_matcher({"test": "value", "startAt": 0, "maxResults": 100})],
    )
    responses.post(
        "https://nourl/rest/api/3/test",
        json=test_response2,
        match=[
            json_params_matcher({"test": "value", "startAt": 100, "maxResults": 100})
        ],
    )
    iter_obj = JiraIterator(
        jiraapi,
        params={"test": "value"},
        _method="POST",
        _envelope="envelope",
        path="test",
    )
    for obj in iter_obj:
        assert isinstance(obj.id, int)


@responses.activate
def test_search_generator(jiraapi):
    test_response = {
        "total": 200,
        "nextPageToken": "abcdef",
        "issues": [{"id": i} for i in range(100)],
    }
    test_response2 = {
        "total": 200,
        "issues": [{"id": i} for i in range(100, 200)],
    }
    responses.post(
        "https://nourl/rest/api/3/search/jql",
        json=test_response,
        match=[
            json_params_matcher(
                {
                    "jql": "test jql search",
                    "expand": "names",
                    "fields": ["id"],
                    "maxResults": 100,
                }
            )
        ],
    )
    responses.post(
        "https://nourl/rest/api/3/search/jql",
        json=test_response2,
        match=[
            json_params_matcher(
                {
                    "jql": "test jql search",
                    "expand": "names",
                    "nextPageToken": "abcdef",
                    "fields": ["id"],
                    "maxResults": 100,
                }
            )
        ],
    )
    gen_obj = search_generator(api=jiraapi, jql="test jql search", fields=["id"])
    for page, total, count in gen_obj:
        assert len(page) == 100
        assert total == -1
        assert count < 3
