from tenable_jira.jira import Jira
from tenable_jira.config import base_config
from restfly.utils import dict_merge
import yaml, json

config_file = 'config.yaml'
issue_id = 95045

config = dict_merge(
    base_config(),
    yaml.load(open(config_file), Loader=yaml.Loader)
)
jira = Jira(
    'https://{}/rest/api/3'.format(config['jira']['address']),
    config['jira']['api_username'],
    config['jira']['api_token']
)

print('-- JSON Dump of Offending Issue --')
print(json.dumps(jira.issues.details(issue_id)))
print('-- JSON Dump of Issue Transitions --')
print(json.dumps(jira.issues.get_transitions(issue_id)))