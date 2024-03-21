from typing import Optional, Any
from restfly.utils import trunc
import arrow

from .api.session import JiraAPI


DATETIME_FMT = 'YYYY-MM-DDTHH:mm:ss.SSSZ'


class Field:
    """
    Class defining the vulnerability -> jira field transformation logic and
    field constructor within Jira.
    """
    id: str
    name: str
    type: str
    searcher: str
    tab: str
    task_types: list[str]
    attribute: (str | None) = None
    description: (str | None) = None
    map_to_state: bool = False
    map_to_priority: bool = False
    platform_id: (str | None) = None
    static_value: (str | None) = None

    def __init__(self,
                 config: dict[str, Any],
                 platform: str,
                 platform_map: dict[str, str],
                 api: Optional[JiraAPI] = None):
        """
        """
        platform_id = None
        if config.get('platform_id'):
            platform_id = platform_map[platform]
        if config.get('attr'):
            self.attribute = config['attr'].get(platform)
        self.id = config.get('id')
        self.name = config['name']
        self.type = config['type']
        self.tab = config['screen_tab']
        self.searcher = config['searcher']
        self.description = config.get('description')
        self.map_to_priority = config.get('map_to_priority', False)
        self.map_to_state = config.get('map_to_state', False)
        self.platform_id = platform_id
        self.task_types = config['task_types']
        self.static_value = config.get('static_value')

        if api and not self.fetch_field_id(api):
            self.create_field(api)

    def __repr__(self):
        return f'Field({self.id}: {self.name})'

    @property
    def attr(self):
        if self.attribute:
            return self.attribute
        if self.static_value:
            return self.attribute
        if self.platform_id:
            return self.platform_id

    def fetch_field_id(self, api) -> bool:
        """
        Attempts to fetch the jira field id for the specified field name
        if no id currently exists within the definition.

        Args:
            api (JiraAPI): The Jira API session

        Returns:
            bool:
                Returns if an id was successfully associated to the field.
        """
        if self.id:
            return True
        fields = api.fields.list()
        for field in fields:
            if self.name == field['name']:
                self.id = field['id']
                return True
        return False

    def create_field(self, api) -> bool:
        """
        Creates the field within Jira and stores the field id

        Args:
            api (JiraAPI): The Jira API session

        Returns:
            bool:
                Returns True if a new field was created.
        """
        if self.id:
            return False
        resp = api.fields.create(name=self.name,
                                 field_type=self.type,
                                 searcher=self.searcher,
                                 description=self.description
                                 )
        self.id = resp['id']
        return True

    def parse_value(self, finding: dict) -> Any:
        """
        Extracts the field value from the finding

        Args:
            finding (dict): The flattened vulnerability finding

        Returns:
            Any:
                The expected field value
        """
        # If the platform_id attribute is set, then we will return that value
        if self.platform_id:
            return self.platform_id

        # If the static_value attribute is set, then we will return that value
        if self.static_value:
            return self.static_value

        # fetch the value using the defined attribute
        value = finding.get(self.attribute)

        # Next we will perform some formatting based on the expected values
        # that Jira expects in the API.
        match self.type:
            # These fields are string values that should be truncated to
            # 255 characters.
            case 'readonlyfield' | 'textfield':
                return trunc(str(value), 255)

            # Textarea is a string value that should be truncated to 1024 chars
            case 'textarea':
                return trunc(str(value), 1024)

            # Labels are a list of string values.  We will attempt to split
            # a string by comma, or simply recast the list into a list of
            # strings should we get a list.
            case 'labels':
                if isinstance(value, str):
                    return [v.strip() for v in value.split(',')]
                if isinstance(value, list):
                    return [str(i) for i in value]
                if value is None:
                    return []
                raise TypeError(f'Value {value} is not a string or list')

            # float values should always be returned as a float.
            case 'float':
                return float(value) if value is not None else 0.0

            # datetime values should be returned in a specific format.  Here
            # we attempt to normalize both timestamp and ISO formatted values
            # info the Jira-specified format.
            case 'datetime':
                if value is None:
                    return None
                try:
                    return arrow.get(value).format(DATETIME_FMT)
                except arrow.parser.ParserError:
                    return arrow.get(int(value)).format(DATETIME_FMT)

            # For any other value types, we will just bass the value back
            # exactly as we retrieved it.
            case _:
                return value

    def parse_jql(self, value: Any) -> str:
        """
        Returns a JQL fragment as it relates to the field and value passed.

        Args:
            value (Any): The field value
        """
        # labels expect a =, almost everything else should use contains (~)
        operator = '=' if self.type == 'labels' else '~'

        # if the value is a list, we need to check if there is more than 1
        # element in the list.  If there is, then we will construct an "in"
        # statement looking for any of the values.  If there is only a single
        # value, then we have to return a normal "contains" statement using
        # the only item in the list.
        if isinstance(value, list):
            if len(value) > 1:
                operator = 'in'
                vals = [f'"{str(i)}"' for i in value]
                value = f'({",".join(vals)})'
            else:
                value = f'"{str(value[0])}"'
        # if the value is None, then we need to specify a specific operator
        # and value to handle that.
        elif not value:
            operator = 'is'
            value = 'EMPTY'
        else:
            value = f'"{value}"'

        # Return the JQL fragment
        return f'"{self.name}" {operator} {str(value)}'
