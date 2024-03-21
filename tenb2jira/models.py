from typing import List
from uuid import UUID
from datetime import datetime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    def asdict(self):
        return {k: getattr(self, k) for k in self.__mapper__.c.keys()}


class TaskMap(Base):
    __tablename__ = 'task'
    plugin_id: Mapped[int] = mapped_column(primary_key=True,
                                           sqlite_on_conflict_unique='IGNORE'
                                           )
    jira_id: Mapped[int]
    updated: Mapped[datetime]
    subtasks: Mapped[List["SubTaskMap"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class SubTaskMap(Base):
    __tablename__ = 'subtask'
    finding_id: Mapped[UUID] = mapped_column(primary_key=True,
                                             sqlite_on_conflict_unique='IGNORE'
                                             )
    asset_id: Mapped[UUID]
    jira_id: Mapped[int]
    plugin_id: Mapped[int] = mapped_column(ForeignKey('task.plugin_id'))
    is_open: Mapped[bool]
    updated: Mapped[datetime]
    task: Mapped["TaskMap"] = relationship(back_populates="subtasks")

    def __init__(self,
                 finding_id: str,
                 asset_id: str,
                 jira_id: int,
                 plugin_id: int,
                 is_open: bool = True,
                 **kwargs,
                 ):
        self.finding_id = UUID(finding_id)
        self.asset_id = UUID(asset_id)
        self.jira_id = int(jira_id)
        self.plugin_id = int(plugin_id)
        self.is_open = bool(is_open)
        super().__init__(**kwargs)

