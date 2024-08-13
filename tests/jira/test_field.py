import uuid
import pytest
import responses
from tenb2jira.jira.field import Field

@pytest.fixture
def field_config():
    return {
        'id': 1,
        'name': 'Test Field',
        'type': 'readonlyfield',
        'tab': 'Test Tab',
        'screen_tab': 'Asset',
        'searcher': 'textsearcher',
        'description': 'Something',
        'task_types': ['task'],
        'attr': {'tvm': 'test', 'bad': 'bad'}
    }


def test_field_noapi(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    assert f.id == 1
    assert f.name == 'Test Field'
    assert f.attribute == 'test'
    assert f.platform_id is None
    assert f.static_value is None
    field_config['platform_id'] = True
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    assert f.platform_id == 'Test Platform'


@responses.activate
def test_field_existing_api(jiraapi, field_config):
    test_list = [
        {'id': 1, 'name': 'Test Field'}
    ]
    responses.get('https://nourl/rest/api/3/field', json=test_list)
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'},
              api=jiraapi
              )
    assert f.id == 1
    del(field_config['id'])
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'},
              api=jiraapi
              )
    assert f.id == 1


@responses.activate
def test_field_create_api(jiraapi, field_config):
    del(field_config['id'])
    responses.get('https://nourl/rest/api/3/field', json=[])
    responses.post('https://nourl/rest/api/3/field', json={'id': 1})
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'},
              api=jiraapi
              )
    assert f.id == 1
    assert f.create_field(jiraapi) == False


def test_field_parse_value_textfield(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    for ftype in ('readonlyfield', 'textfield'):
        f.type = ftype
        assert f.parse_value({'test': 'value'}) == 'value'
        assert len(f.parse_value({'test': 'A'*300})) == 255


def test_field_parse_value_textarea(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'textarea'
    assert f.parse_value({'test': 'value'}) == 'value'
    assert len(f.parse_value({'test': 'A'*2000})) == 1024


def test_field_parse_value_platform_id(field_config):
    field_config['platform_id'] = True
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    assert f.parse_value({'test': 'value'}) == 'Test Platform'


def test_field_parse_value_static_field(field_config):
    field_config['static_value'] = 'something'
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'readonltfield'
    assert f.parse_value({'test': 'value'}) == 'something'


def test_field_parse_value_labels(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'labels'
    assert f.parse_value({'test': ['val1', 'val2']}) == ['val1', 'val2']
    assert f.parse_value({'test': 'val1, val2'}) == ['val1', 'val2']
    assert f.parse_value({'test': 1}) == ['1']
    test_uuid = uuid.uuid4()
    assert f.parse_value({'test': test_uuid}) == [str(test_uuid)]


def test_field_parse_value_float(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'float'
    assert f.parse_value({'test': 1}) == '1.0'
    assert f.parse_value({'test': 1.0}) == '1.0'
    assert f.parse_value({'test': '1'}) == '1.0'


def test_field_parse_value_datetime(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'datetime'
    test_resp = '2024-04-06T15:51:42.000+0000'
    assert f.parse_value({'test': 1712418702}) == test_resp
    assert f.parse_value({'test': '1712418702'}) == test_resp
    assert f.parse_value({'test': '2024-04-06T15:51:42+00:00'}) == test_resp


def test_field_parse_value_datepicker(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'datepicker'
    test_resp = '2024-04-06'
    assert f.parse_value({'test': 1712418702}) == test_resp
    assert f.parse_value({'test': '1712418702'}) == test_resp
    assert f.parse_value({'test': '2024-04-06T15:51:42+00:00'}) == test_resp


def test_field_parse_value_fallthrough(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'something'
    assert f.parse_value({'test': 'value'}) == 'value'
    assert f.parse_value({'test': 1}) == 1


def test_field_parse_jql_labels(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'labels'
    assert f.parse_jql(['val1', 'val2']) == '"Test Field" in ("val1","val2")'
    assert f.parse_jql(['val1']) == '"Test Field" = "val1"'


def test_field_parse_jql_single(field_config):
    f = Field(config=field_config,
              platform='tvm',
              platform_map={'tvm': 'Test Platform'}
              )
    f.type = 'readonlyfield'
    assert f.parse_jql('value') == '"Test Field" ~ "value"'
    assert f.parse_jql(None) == '"Test Field" is EMPTY'
