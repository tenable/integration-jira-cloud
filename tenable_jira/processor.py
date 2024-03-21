from typing import Generator
from .jira.jira import Jira
from .tenable.tenable import Tenable
from .mapping.models import TaskMap, SubTaskMap, Base
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import Session


class Processor:
    jira: Jira
    tenable: Tenable
    config: dict
    engine: Engine

    def __init__(self, config: dict):
        self.config = config
        self.jira = Jira(config)
        self.tenable = Tenable(config)
        self.engine = create_engine('sqlite://')
        Base.metadata.create_all(self.engine)

    def setup(self):
        self.jira.setup()

    def build_issue_db(self):

        pkey = self.config['jira']['project']['key']
        jql = f'project = "{pkey}" AND issuetype = ""'
