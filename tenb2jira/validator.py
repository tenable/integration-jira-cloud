from typing import Annotated, Literal

from pydantic import BaseModel, Field, ValidationError

Platform = Literal["tvm", "tsc"]
Severity = Literal["critical", "high", "medium", "low", "info"]
TaskType = Literal["task", "subtask"]
State = Literal["open", "reopened", "fixed"]


class JiraParagraph(BaseModel):
    name: str
    attr: str


class JiraDescription(BaseModel, use_enum_values=True):
    tvm: list[JiraParagraph]
    tsc: list[JiraParagraph]


class SeverityMap(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class VPRSeverityMap(BaseModel):
    priority: int
    lower_bound: float


class JiraField(BaseModel, use_enum_values=True):
    id: str | None = None
    name: str
    screen_tab: str
    type: str
    searcher: str
    attr: dict[Platform, str] | None = None
    description: str | None = None
    task_types: list[TaskType]
    map_to_priority: bool | None = None
    map_to_vpr_priority: bool | None = None
    platform_id: bool | None = None
    static_value: str | None = None


class JiraTask(BaseModel, use_enum_values=True):
    id: int | None = None
    name: str
    type: str
    closed_id: str | None
    search: dict[Platform, list[str]]
    summary: dict[Platform, str]
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
    closed_map: list[str]
    state_map: dict[State, bool]
    severity_map: dict[Severity, int]
    project: JiraProject
    fields: list[JiraField]
    screens: list[int] | None = None
    use_vpr_severity_map: bool | None = None
    vpr_sev_map: list[VPRSeverityMap] | None = None


class Tenable(BaseModel, use_enum_values=True):
    platform: Platform
    access_key: str
    secret_key: str
    url: str
    port: int = 443
    severities: list[Severity]
    vuln_age: int | None = 30
    tsc_query_id: int | None = None
    tsc_page_size: Annotated[int | None, Field(ge=500, le=10000)] = None
    platforms: dict[Platform, str]
    tags: list[tuple[str, str | list[str]]] | None = None


class MappingDatabase(BaseModel):
    path: str


class Configuration(BaseModel, use_enum_values=True):
    tenable: Tenable
    jira: Jira
    mapping_database: MappingDatabase


def validate(config: dict) -> list:
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
