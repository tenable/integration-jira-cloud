import pytest
from uuid import UUID
import datetime
from tenb2jira.models import TaskMap, SubTaskMap


def test_taskmap():
    now = datetime.datetime.now()
    obj = TaskMap(plugin_id=1,
                  jira_id=1,
                  updated=now
                  )
    assert obj.plugin_id == 1
    assert obj.jira_id == 1
    assert obj.updated == now


def test_subtaskmap():
    fid = '7f68f334-17ba-4ba0-b057-b77ddd783e60'
    aid = '116411f4-083c-42c7-beaf-5b4a046811d0'
    now = datetime.datetime.now()
    obj = SubTaskMap(finding_id=fid,
                     asset_id=aid,
                     jira_id=1,
                     plugin_id=1,
                     is_open=True,
                     updated=now
                     )
    assert obj.updated == now
    assert obj.finding_id == UUID(fid)
    assert obj.asset_id == UUID(aid)
    assert obj.plugin_id == 1
    assert obj.jira_id == 1
    assert obj.is_open == True


def test_asdict():
    now = datetime.datetime.now()
    obj = TaskMap(plugin_id=1,
                  jira_id=1,
                  updated=now
                  )
    assert obj.asdict() == {
        'plugin_id': 1,
        'jira_id': 1,
        'updated': now
    }
