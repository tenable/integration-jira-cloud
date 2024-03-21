from typing import Any
import logging
from restfly.errors import NotFoundError
from .field import Field
from .task import Task
from .api.session import JiraAPI


log = logging.getLogger('Jira')


class Jira:
    """
    Class defining the vuln -> jira task transformation logic and project
    validation and buildout code.
    """
    task: Task
    subtask: Task
    fields: list[Field]
    api: JiraAPI
    config: dict[str, Any]
    project: dict

    @property
    def field_by_name_map(self):
        return {f.name:f for f in self.fields}

    @property
    def field_by_id_map(self):
        return {f.id:f for f in self.fields}

    def __init__(self, config: dict):
        self.config = config
        self.fields = []
        self.api = JiraAPI(url=config['jira']['url'],
                           username=config['jira']['api_username'],
                           token=config['jira']['api_token']
                           )

    def setup(self):
        """
        Performs the initial setup tasks for the jira project.
        """
        self.get_project()
        self.build_fields()
        self.build_screens()
        self.build_tasks()

    def build_fields(self):
        """
        Perform the initial validation && linking between the required fields
        and the fields that may already exist within Jira.  If any fields
        don't exist, we will create them as part of the initialization of the
        fields.
        """
        platform = self.config['tenable']['platform']

        # For each field, we will initialize the field, which will attempt to
        # match the field to an existing one by name if no id is present in the
        # config.  Once the field was successfully linked/created, we will
        # store the id back into the config for that field and then add the
        # field object to this object's field listing.
        for field in self.config['jira']['fields']:
            fobj = Field(config=field,
                         platform=platform,
                         platform_map=self.config['tenable']['platforms'],
                         api=self.api
                         )
            field['id'] = fobj.id
            self.fields.append(fobj)

    def build_tasks(self):
        """
        Performs the initial valitaion and linking between the
        """
        # Collect the fields for the task, feed them into the constructor, and
        # save the task id to the config.
        task_fields = [f for f in self.fields if 'task' in f.task_types]
        self.task = Task(config=self.config['jira']['task'],
                         jira_config=self.config['jira'],
                         platform=self.config['tenable']['platform'],
                         fields=task_fields,
                         api=self.api,
                         project=self.project
                         )
        self.config['jira']['task']['id'] = self.task.id

        # Collect the fields for the subtask, feed them into the constructor,
        # and save the subtask id to the config.
        sub_fields = [f for f in self.fields if 'subtask' in f.task_types]
        self.subtask = Task(config=self.config['jira']['subtask'],
                            jira_config=self.config['jira'],
                            platform=self.config['tenable']['platform'],
                            fields=sub_fields,
                            api=self.api,
                            project=self.project
                            )
        self.config['jira']['subtask']['id'] = self.subtask.id

    def get_project(self):
        """
        Checks to see if the project exists within Jira based on the project
        key and creates the project if it doesn't exist.
        """
        j = self.api
        config = self.config['jira']['project']
        try:
            project = j.projects.get(config['key'])
        except NotFoundError:
            project = j.projects.create(
                key=config['key'],
                name=config['name'],
                description=config['description'],
                url=config['url'],
                leadAccountId=config['lead_account_id'],
                assigneeType=config['assignee'],
                projectTemplateKey=config['template_key'],
                projectTypeKey=config['type_key']
            )
        self.project = project

    def build_screens(self):
        """
        Validates & builds out the task screens and field mappings.
        """
        config = self.config['jira']['project']

        # If manage screens to set to false, then we don't actually want to
        # do anything here.  Just return to the caller.
        if not self.config['jira'].get('manage_screens', True):
            return

        # Get the list of screens related to thsi project.  THe only way I have
        # found to get the screens associated to a project via the Jira API is
        # to perform a screen search using the project key as part of the
        # search string.
        screens = self.api.screens.search(queryString=f'{config["key"]}:')
        for screen in screens:
            # collect the tabs for the screen and then collect the fields that
            # are associated to that tab.
            ctabs = self.api.screens.screen_tabs(screen.id)
            tabs = {i.name: i.id for i in ctabs}
            for tab in ctabs:
                fields = self.api.screens.screen_tab_fields(screen.id, tab.id)
                tabs[tab.name] = {
                    'id': tab.id,
                    'fields': [f.id for f in fields]
                }

            # for each field we will check to see if the field id exists within
            # the defined tabs field list.  If not, we will add the field to
            # the tab.  We will also create any new tabs based on the defined
            # tab names within the field list.
            for field in self.fields:
                if field.tab not in tabs.keys():
                    log.info(f'Creating new tab for screen {screen.id} '
                             f'with the name of {field.tab}.')
                    new_tab = self.api.screens.create_tab(screen.id,
                                                          name=field.tab
                                                          )
                    tabs[field.tab] = {
                        'id': new_tab.id,
                        'fields': []
                    }
                if field.id not in tabs[field.tab]['fields']:
                    log.info(f'Adding field {field.id}:"{field.name}" to '
                             f'the screen tab "{field.tab}".')
                    self.api.screens.add_screen_tab_field(screen.id,
                                                          tabs[field.tab]['id'],
                                                          field.id
                                                          )
