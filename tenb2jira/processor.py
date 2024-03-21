import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime
from uuid import UUID
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy import create_engine, Engine, delete
from sqlalchemy.orm import Session
import arrow
from .jira.jira import Jira
from .jira.api.iterator import search_generator
from .tenable.tenable import Tenable
from .models import TaskMap, SubTaskMap, Base


log = logging.getLogger('Processor')


class Processor:
    jira: Jira
    tenable: Tenable
    config: dict
    engine: Engine
    last_run: arrow.Arrow
    start_time: arrow.Arrow
    finished_time: arrow.Arrow
    finding_id: str
    asset_id: str
    plugin_id: str
    closed_map: list[str]

    def __init__(self, config: dict):
        dburi = f'sqlite:///{config["mapping_database"].get("path")}'
        self.last_run = arrow.get(config['tenable'].get('last_run', 0))
        self.config = config
        self.jira = Jira(config)
        self.tenable = Tenable(config)
        self.engine = create_engine(dburi)
        self.max_workers = self.config['jira'].get('max_workers', 4)
        self.closed_map = self.config['jira']['closed_map']
        Base.metadata.create_all(self.engine)
        self.jira.setup()
        self.finding_id = self.jira.field_by_name_map['Tenable Finding ID'].id
        self.asset_id = self.jira.field_by_name_map['Tenable Asset UUID'].id
        self.plugin_id = self.jira.field_by_name_map['Tenable Plugin ID'].id

    def get_closed_transition(self, jira_id: int) -> int:
        """
        Checks the config file for the closed transition id, and if it exists
        return it.  If the transition id is not stored in the config file,
        attempts to gather the available transitions from the jira issue id
        presented and looks for the closed transition by name.
        """
        # if we can get the closed transition, then we will use it.
        if self.config['jira'].get('closed_id'):
            return self.config['jira'].get('closed_id')

        # if no closed_id was configured, then we will configure it ourselves
        # using the current jira issue id as a template to get the transition
        # we need.
        page = self.jira.api.issues.get_transitions(jira_id)
        for transition in page.transitions:
            if transition.name == self.config['jira']['closed']:
                self.config['jira']['closed_id'] = transition.id
                return transition.id

    def close_task(self, jira_id: int):
        """
        Closes the Jira issue and appends the configured comment within Jira.
        """
        closed_id = self.get_closed_transition(jira_id)
        msg = {
            'content': {
                'text': self.config['jira']['closed_message'],
                'type': 'text'
            }
        }
        self.jira.api.issues.transition(
            issue_id_or_key=jira_id,
            transition={'id': closed_id},
            update={'comment': [{'add': {'body': {'content': [msg]}}}]}
        )

    def build_mapping_db_model(self,
                               issuetype: str,
                               model: Base,
                               fields: dict[str, str],
                               pk: str,
                               limit: int = 1000
                               ):
        """
        Queries Jira and builds the database cache based off of the results of
        the search for the given database model.
        """
        key = self.config['jira']['project']['key']
        cmap = ', '.join([f'"{i}"' for i in self.config['jira']['closed_map']])
        jql = (f'project = "{key}" AND issuetype = "{issuetype}" '
               f'AND status not in ({cmap})'
               )
        with Session(self.engine) as s:
            for page in search_generator(api=self.jira.api,
                                         jql=jql,
                                         fields=list(fields.keys())
                                         ):
                issues = []
                for issue in page:
                    item = {}
                    skip = False
                    for key, value in issue.fields.items():
                        if value is None:
                            skip = True
                        if isinstance(value, list):
                            value = value[0]
                        item[fields[key]] = value
                    # item = {fields[k]: v for k, v in issue.fields.items()}
                    item['updated'] = self.start_time
                    item['jira_id'] = int(issue.id)
                    if not skip:
                        issues.append(model(**item).asdict())
                if issues:
                    stmt = insert(model).values(issues)\
                                        .on_conflict_do_nothing()
                    s.execute(stmt)
                    s.commit()

    def build_cache(self):
        """
        Build the database cache for both the Tasks and SubTasks.
        """
        log.info('Building Task SQL Cache.')
        self.build_mapping_db_model(issuetype=self.jira.task.name,
                                    model=TaskMap,
                                    fields={self.plugin_id: 'plugin_id'},
                                    pk='plugin_id'
                                    )
        log.info('Building Subtask SQL Cache.')
        self.build_mapping_db_model(issuetype=self.jira.subtask.name,
                                    model=SubTaskMap,
                                    fields={
                                        self.finding_id: 'finding_id',
                                        self.asset_id: 'asset_id',
                                        self.plugin_id: 'plugin_id'
                                    },
                                    pk='finding_id'
                                    )

    def upsert_task(self, s: Session, finding: dict) -> (int | None):
        """
        Performs task generation && checks both the local cache and Jira to
        determine if the task is a new issue or an existing and performs the
        associated action.
        """
        task = self.jira.task.generate(finding)

        # If the finding related to this task is not in an open state, then
        # there is no reason to continue.  Return back a NoneType value.
        if not task.is_open:
            log.info(f'Finding related to Task {task.fields[self.plugin_id]} '
                     'is closed, skipping'
                     )
            return None

        sql = s.query(TaskMap)\
               .filter_by(plugin_id=task.fields[self.plugin_id])\
               .one_or_none()

        # If we had a match from the SQL cache and the plugin information
        # has been updated recently, we will then update the task in Jira
        # and return the jira issue id back to the caller.
        if sql:
            if finding.get('integration_pid_updated') > self.last_run:
                if sql.updated <= self.start_time:
                    self.jira.api.issues.update(sql.jira_id,
                                                fields=task.fields,
                                                priority=task.priority,
                                                )
                sql.updated = datetime.now()
                s.commit()
                log.info(f'Matched Task "{sql.jira_id}" to '
                         'SQL Cache and updated.')
            return sql.jira_id

        # As no match was found in the SQL cache, we will instead have to talk
        # to Jira to attempt to find a matching task from the open tasks
        # already in Jira.
        cmap = ', '.join([f'"{i}"' for i in self.closed_map])
        jql = f'{task.jql_stmt} AND status not in ({cmap})'
        page = self.jira.api.issues.search(jql=jql,
                                           fields=['id', 'key'],
                                           use_iter=False
                                           )

        # If only 1 match was found (and we should generally only ever have)
        # a single match if one exists), then we will update the sql cache with
        # the mapping and update the task if the plugin information has been
        # updated as of the last run.  Lastly, we will return the Jira issue id
        # back to the caller.
        if len(page.issues) == 1:
            sql = TaskMap(plugin_id=task.fields[self.plugin_id],
                          jira_id=page.issues[0].id,
                          updated=datetime.now(),
                          )
            s.add(sql)
            s.commit()
            if finding.get('integration_pid_updated') > self.last_run:
                self.jira.api.issues.update(sql.jira_id,
                                            fields=task.fields,
                                            priority=task.priority,
                                            )
            log.info(f'Found Task "{sql.jira_id}", '
                     'added to SQL Cache and updated.')
            return sql.jira_id

        # If there was no match in either the sql cache or within Jira, we will
        # then create a new task and map it back into the sql cache.  Just like
        # above, we will then return the jira issue id to the caller.
        if len(page.issues) == 0:
            resp = self.jira.api.issues.create(fields=task.fields,
                                               priority=task.priority,
                                               )
            sql = TaskMap(plugin_id=task.fields[self.plugin_id],
                          jira_id=resp.id,
                          updated=datetime.now()
                          )
            s.add(sql)
            s.commit()
            log.info(f'Created Task "{resp.id}" and added to SQL Cache.')
            return resp.id

        # In the event that multiple tasks are returned from the search,
        # something went seriously wrong.  We will log to the console, then
        # raise an exception to terminate further processing at this point.
        if len(page.issues) > 1:
            msg = ('Multiple Jira Tasks match Plugin '
                   f'"{task.fields[self.plugin_id]}".  Jira IDs are '
                   f'"{", ".join(i.key for i in page.issues)}".'
                   )
            log.error(msg)
            raise Exception(msg)

    def upsert_subtask(self,
                       s: Session,
                       task_id: (int | None),
                       finding: dict
                       ) -> (int | None):
        """
        Performs subtask generation && checks both the local cache and Jira to
        determine if the subtask is a new issue or an existing and performs the
        associated action.
        """
        task = self.jira.subtask.generate(finding)
        task.fields['parent'] = {'id': str(task_id)}
        sql = s.query(SubTaskMap)\
               .filter_by(finding_id=UUID(task.fields[self.finding_id]))\
               .one_or_none()

        # If we had a match from the SQL cache we will then update the task in
        # Jira and return the jira issue id back to the caller.
        if sql:
            if not task.is_open:
                sql.is_open = task.is_open
                sql.updated = datetime.now()
                s.commit()
                self.close_task(sql.jira_id)
                action = 'closed subtask'
            else:
                self.jira.api.issues.update(sql.jira_id,
                                            fields=task.fields,
                                            priority=task.priority,
                                            )
                action = 'updated subtask'
            log.info(f'Matched SubTask "{sql.jira_id}" to '
                     f'SQL Cache and {action}.'
                     )
            return sql.jira_id

        # If the task is not in the SQL cache and isn't an open subtask, we
        # should then skip this item.
        elif not sql and not task.is_open:
            log.info(f'Subtask {task.fields[self.finding_id]} is not in the '
                     'SQL cache and is not open.  Skipping.'
                     )
            return

        # As no match was found in the SQL cache, we will instead have to talk
        # to Jira to attempt to find a matching subtask from the open subtasks
        # already in Jira.
        cmap = ', '.join([f'"{i}"' for i in self.config['jira']['closed_map']])
        jql = f'{task.jql_stmt} AND status not in ({cmap})'
        page = self.jira.api.issues.search(jql=jql,
                                           fields=['id', 'key'],
                                           use_iter=False
                                           )
        match len(page.issues):
            # If only 1 match was found (and we should generally only ever
            # have) a single match if one exists), then we will update the sql
            # cache with the mapping and update the task.  Lastly, we will
            # return the Jira issue id back to the caller.
            case 1:
                sql = SubTaskMap(plugin_id=task.fields[self.plugin_id],
                                 asset_id=task.fields[self.asset_id],
                                 finding_id=task.fields[self.finding_id],
                                 jira_id=page.issues[0].id,
                                 is_open=task.is_open,
                                 updated=datetime.now(),
                                 )
                s.add(sql)
                s.commit()
                if task.is_open:
                    self.jira.api.issues.update(sql.jira_id,
                                                fields=task.fields,
                                                priority=task.priority,
                                                )
                    action = 'updated subtask'
                else:
                    self.close_task(sql.jira_id)
                    action = 'closed subtask'
                log.info(f'Found Subtask "{sql.jira_id}", '
                         f'added to SQL Cache and {action}.')
                return sql.jira_id

            # If there was no match in either the sql cache or within Jira, we
            # will then create a new task and map it back into the sql cache.
            # Just like above, we will then return the jira issue id to the
            # caller.
            case 0:
                if task.is_open:
                    resp = self.jira.api.issues.create(fields=task.fields)
                    sql = SubTaskMap(plugin_id=task.fields[self.plugin_id],
                                     asset_id=task.fields[self.asset_id][0],
                                     finding_id=task.fields[self.finding_id],
                                     jira_id=resp.id,
                                     is_open=task.is_open,
                                     updated=datetime.now(),
                                     )
                    s.add(sql)
                    s.commit()
                    log.info(f'Created Subtask "{resp.id}" and '
                             'added to SQL Cache.'
                             )
                    return resp.id

            # In the event that multiple tasks are returned from the
            # search, something went seriously wrong.  We will log to the
            # console, then raise an exception to terminate further
            # processing at this point.
            case _:
                msg = ('Multiple Jira SubTasks match Finding '
                       f'"{task.fields[self.finding_id]}".  Jira IDs are '
                       f'"{", ".join(i.key for i in page.issues)}".'
                       )
                log.error(msg)
                raise Exception(msg)

    def close_dead_assets(self, dead_assets: iter):
        """
        Closes all subtasks associated with dead hosts.
        """
        with Session(self.engine) as s:
            # For each dead asset we will query all the of the subtasks
            # associated with it and then close each of those subtasks.
            for asset in dead_assets:
                issues = s.query(SubTaskMap)\
                          .filter_by(asset_id=UUID(asset['id']))\
                          .all()
                for issue in issues:
                    issue.is_open = False
                    self.close_task(issue.jira_id)
                    log.info(f'Closed SubTask {issue.jira_id} as it\'s '
                             'associated to a dead host.'
                             )
            s.commit()

    def close_empty_tasks(self):
        """
        Close tasks that have no open subtasks associated with them.
        """
        with Session(self.engine) as s:
            # First we will mass delete all of the closed subtasks.
            rm_stmt = delete(SubTaskMap).where(SubTaskMap.is_open == False)
            s.execute(rm_stmt)

            # Lastly we will look for all of the
            close_me = s.query(TaskMap, SubTaskMap)\
                        .outerjoin(SubTaskMap,
                                   TaskMap.plugin_id == SubTaskMap.plugin_id)\
                        .filter(SubTaskMap.plugin_id == None)\
                        .all()

            # Using as many threads as we need (up to the max configured)
            # go ahead and close the taska that have no open subtasks.
            with ThreadPoolExecutor(max_workers=self.max_workers) as e:
                for task, _ in close_me:
                    log.info(f'Closing Task "{task.jira_id}" '
                             'as it has no open SubTasks')
                    e.submit(self.close_task, task.jira_id)

    def finding_job(self, finding: dict):
        """
        A simple worker method for updating a task & subtask
        """
        with Session(self.engine) as session:
            task_id = self.upsert_task(s=session, finding=finding)
            self.upsert_subtask(s=session, task_id=task_id, finding=finding)

    def sync(self):
        """
        Tenable to Jira Synchronization method.
        """
        self.start_time = datetime.now()
        ts = int(arrow.get(self.start_time).timestamp())

        # Get the findings and the asset cleanup generators.
        findings = self.tenable.get_generator()
        asset_cleanup = self.tenable.get_asset_cleanup()

        # build the db cache
        self.build_cache()

        # Using as many threads as we need (up to the max configured)
        # go ahead and process the findings.
        with ThreadPoolExecutor(max_workers=self.max_workers) as e:
            for finding in findings:
                e.submit(self.finding_job, finding)

        # cleanup the dead hosts and clear out the empty tasks.
        self.close_dead_assets(asset_cleanup)
        self.close_empty_tasks()

        # update the last_run timestamp with the time that we started the sync.
        self.config['tenable']['last_run'] = ts
        self.finished_time = datetime.now()

        # Delete the mapping database.
        with Path(self.config["mapping_database"].get("path")) as p:
            p.unlink()
