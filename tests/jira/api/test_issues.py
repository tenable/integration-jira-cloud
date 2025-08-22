import pytest
import responses
from responses import matchers

from tenb2jira.jira.api.iterator import JiraSearchIterator


@responses.activate
def test_transition(jiraapi):
    responses.post(
        "https://nourl/rest/api/3/issue/1/transitions",
        match=[matchers.json_params_matcher({"test": "value"})],
    )
    jiraapi.issues.transition(issue_id_or_key=1, test="value")


@responses.activate
def test_get_transitions(jiraapi):
    responses.get("https://nourl/rest/api/3/issue/1/transitions")
    jiraapi.issues.get_transitions(issue_id_or_key=1)


@responses.activate
def test_update(jiraapi):
    responses.put(
        "https://nourl/rest/api/3/issue/1",
        match=[
            matchers.json_params_matcher({"test": "value"}),
            matchers.query_param_matcher(
                {
                    "notifyUsers": "true",
                    "overrideScreenSecurity": "false",
                    "overrideEditableFlag": "false",
                }
            ),
        ],
    )
    jiraapi.issues.update(issue_id_or_key=1, test="value")


@responses.activate
def test_create(jiraapi):
    responses.post(
        "https://nourl/rest/api/3/issue",
        match=[
            matchers.json_params_matcher({"test": "value"}),
            matchers.query_param_matcher({"update_history": "False"}),
        ],
    )
    jiraapi.issues.create(test="value")


@responses.activate
def test_get(jiraapi):
    responses.get("https://nourl/rest/api/3/issue/1")
    jiraapi.issues.get(issue_id_or_key=1)


@responses.activate
def test_list_no_iter(jiraapi):
    responses.post(
        "https://nourl/rest/api/3/search/jql",
        match=[
            matchers.json_params_matcher(
                {"jql": "test jql search", "expand": "", "fields": ["id"]}
            )
        ],
    )
    jiraapi.issues.search(jql="test jql search", fields=["id"], use_iter=False)


def test_list_iter(jiraapi):
    test_params = {"jql": "test jql search", "expand": "", "fields": ["id"]}
    iter_obj = jiraapi.issues.search(
        jql="test jql search",
        fields=["id"],
        use_iter=True,
    )
    assert isinstance(iter_obj, JiraSearchIterator)
    assert iter_obj._method == "POST"
    assert iter_obj._envelope == "issues"
    assert iter_obj.path == "search/jql"
    assert iter_obj.params == test_params
