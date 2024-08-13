from typing import List, Dict, Optional
from enum import Enum
from pydantic import BaseModel, Field, ValidationError


class Platform(str, Enum):
    tvm: str = 'tvm'
    tsc: str = 'tsc'


class Severity(str, Enum):
    critical = 'critical'
    high = 'high'
    medium = 'medium'
    low = 'low'
    info = 'info'


class TaskType(str, Enum):
    task: str = 'task'
    subtask: str = 'subtask'


class State(str, Enum):
    open = 'open'
    reopened = 'reopened'
    fixed = 'fixed'


class JiraParagraph(BaseModel):
    name: str
    attr: str


class JiraDescription(BaseModel, use_enum_values=True):
    tvm: List[JiraParagraph]
    tsc: List[JiraParagraph]


class SeverityMap(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class JiraField(BaseModel, use_enum_values=True):
    id: Optional[str] = None
    name: str
    screen_tab: str
    type: str
    searcher: str
    attr: Optional[Dict[Platform, str]] = None
    description: Optional[str] = None
    task_types: List[TaskType]
    map_to_priority: Optional[bool] = None
    platform_id: Optional[bool] = None
    static_value: Optional[str] = None


class JiraTask(BaseModel, use_enum_values=True):
    id: Optional[int] = None
    name: str
    type: str
    search: Dict[Platform, List[str]]
    summary: Dict[Platform, str]
    description: JiraDescription


class JiraProject(BaseModel):
    key: str
    lead_account_id: str
    name: str
    description: str
    url: str
    assignee: str
    type_key: str
    template_key: str


class Jira(BaseModel, use_enum_values=True):
    api_token: str
    api_username: str
    url: str
    closed: str
    closed_map: List[str]
    state_map: Dict[State, bool]
    severity_map: Dict[Severity, int]
    project: JiraProject
    fields: List[JiraField]
    screens: Optional[List[int]] = None


class Tenable(BaseModel, use_enum_values=True):
    platform: Platform
    access_key: str
    secret_key: str
    url: str
    port: Optional[int] = 443
    severities: List[Severity]
    vuln_age: Optional[int] = 30
    tsc_query_id: Optional[int] = None
    tsc_page_size: Optional[int] = Field(ge=500, le=10000)
    platforms: Dict[Platform, str]


class MappingDatabase(BaseModel):
    path: str


class Configuration(BaseModel, use_enum_values=True):
    tenable: Tenable
    jira: Jira
    mapping_database: MappingDatabase


def validate(config: dict) -> dict:
    """
    Passes the configuration object to pydantic to validate against the config
    schema and returns a list of errors to the configuration observed.

    Args:
        config (dict): The configuration dictionary

    Returns:
        list:
            The list of config errors observed.
    """
    try:
        Configuration.model_validate(config)
    except ValidationError as e:
        return e.errors()
    return []
