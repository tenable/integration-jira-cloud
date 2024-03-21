FROM python:3.12-alpine

COPY setup.py /src/
COPY tenable_jira /src/tenable_jira

RUN pip install /src && rm -rf /src

WORKDIR /

ENTRYPOINT '/usr/local/bin/tenb2jira'
