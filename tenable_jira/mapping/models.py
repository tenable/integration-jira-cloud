from typing import List
from sqlalchemy import ForeignKey, String, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class TaskMap(Base):
    __tablename__ = 'task'
    plugin_id: Mapped[int] = mapped_column(primary_key=True)
    jira_id: Mapped[str]
    subtasks: Mapped[List["SubTaskMap"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class SubTaskMap(Base):
    __tablename__ = 'subtask'
    id: Mapped[UUID] = mapped_column(primary_key=True)
    asset_id: Mapped[UUID]
    jira_id: Mapped[str]
    issue_id: Mapped[int] = mapped_column(ForeignKey('issue.plugin_id'))
    task: Mapped["TaskMap"] = relationship(back_populates="subtasks")
