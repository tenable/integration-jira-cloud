from typing import List, Dict, Optional
from enum import Enum
from pydantic import BaseModel, Field, ValidationError


class Platform(Enum):
    tvm = 'tvm'
    tsc = 'tsc'


class Severity(Enum):
    critical = 'critical'
    high = 'high'
    medium = 'medium'
    low = 'low'


class TaskType(Enum):
    task = 'task'
    subtask = 'subtask'


class State(Enum):
    open = 'open'
    reopened = 'reopened'
    fixed = 'fixed'


class JiraParagraph(BaseModel):
    name: str
    attr: str


class JiraDescription(BaseModel):
    tvm: List[JiraParagraph]
    tsc: List[JiraParagraph]


class SeverityMap(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class JiraField(BaseModel):
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


class JiraTask(BaseModel):
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


class Jira(BaseModel):
    api_token: str
    api_username: str
    url: str
    closed: str
    closed_map: List[str]
    state_map: Dict[State, bool]
    severity_map: Dict[Severity, int]
    project: JiraProject
    fields: List[JiraField]


class Tenable(BaseModel):
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


class Configuration(BaseModel):
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
        Configuration.parse_obj(config)
    except ValidationError as e:
        return e.errors()
    return []
