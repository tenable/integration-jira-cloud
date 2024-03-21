from typing import Any, Optional
from restfly.utils import trunc

from .field import Field
from .api.session import JiraAPI


class TaskInstance:
    fields: dict[str, Any]
    jql: list[str]
    is_open: bool
    idef: "Task"
    priority: str

    def __init__(self, issue_def: "Task", is_open: bool = True):
        self.idef = issue_def
        self.fields = {
            'project': {'key': self.idef.project_key},
            'issuetype': {'id': self.idef.id},
        }
        self.jql = [
            f'project = "{self.idef.project_key}"',
            f'issuetype = "{self.idef.name}"'
        ]
        self.is_open = is_open

    def __repr__(self):
        return f'Task("{self.jql}", {len(self.fields)})'

    @property
    def jql_stmt(self):
        """
        Returns the JQL String to search for this issue.
        """
        return ' AND '.join(self.jql)

    def gen_priority(self, field_id: str) -> None:
        """
        Sets the priority field based on the field id value.

        Args:
            field_id (str): The field key identifier
        """
        value = str(self.fields[field_id]).lower()
        self.priority = str(self.idef.severity_map[value])

    def gen_state(self, field_id: str):
        """
        Sets the open status based on the field id value.

        Args:
            field_id (str): The field key identifier
        """
        value = str(self.fields[field_id]).lower()
        self.is_open = self.idef.state_map[value]


class Task:
    id: int
    name: str
    type: str
    project_key: str
    summary: str
    search: list[str]
    description: list[tuple[str, str]]
    fields: list[Field]
    severity_map: dict[str, int]
    state_map: dict[str, bool]

    def __init__(self,
                 config: dict[str, Any],
                 jira_config: dict[str, Any],
                 platform: str,
                 fields: list[Field],
                 api: Optional[JiraAPI] = None,
                 project: Optional[dict] = None
                 ):
        """
        """
        self.id = config.get('id')
        self.name = config['name']
        self.type = config['type']
        self.project_key = jira_config['project']['key']
        self.severity_map = jira_config['severity_map']
        self.state_map = jira_config['state_map']
        self.search = config['search'][platform]
        self.summary = config['summary'][platform]
        self.description = config['description'][platform]
        self.fields = fields

        if not self.fetch_issue_id(project):
            raise AttributeError(('Could not determine Issue Type id for '
                                  f'{self.name}:{self.type}'
                                  ))

    def fetch_issue_id(self, project: dict):
        """
        """
        if self.id:
            return True
        for issue_type in project.issueTypes:
            if self.name == issue_type.name:
                self.id = int(issue_type.id)
                return True

    def gen_description(self, finding: dict) -> dict:
        """
        Generates the description field based of the description template

        Args:
            finding (dict): The finding object

        Returns:
            dict:
                The description definition.
        """
        content = []
        for item in self.description:
            content.append({
                'type': 'heading',
                'attrs': {'level': 1},
                'content': [{
                    'type': 'text',
                    'text': item['name']
                }]
            })
            content.append({
                'type': 'paragraph',
                'content': [{
                    'type': 'text',
                    'text': trunc(finding.get(item['attr'], 'No Output'),
                                  limit=10000,
                                  suffix='..'
                                  )
                }]
            })
        return {'version': 1, 'type': 'doc', 'content': content}

    def gen_summary(self, finding: dict) -> str:
        """
        Generates the summary field based off the summary template

        Args:
            finding (dict): The finding object

        Returns:
            str:
                The summary fiend content
        """
        return self.summary.format(f=finding)

    def generate(self,
                 finding: dict,
                 is_open: Optional[bool] = None
                 ) -> TaskInstance:
        """
        Generate the Task and the associated JQL from the finding.

        Args:
            finding (dict): The finding object

        Returns:
            tuple[dict, str]:
                Returns the Jira issue object as well as the associated JQL
                for the object.
        """
        issue = TaskInstance(issue_def=self, is_open=is_open)
        issue.fields['description'] = self.gen_description(finding)
        issue.fields['summary'] = self.gen_summary(finding)
        for field in self.fields:
            issue.fields[field.id] = field.parse_value(finding)
            if field.name in self.search:
                issue.jql.append(field.parse_jql(issue.fields[field.id]))
            if field.map_to_priority:
                issue.gen_priority(field.id)
            if field.map_to_state:
                issue.gen_state(field.id)
        return issue
