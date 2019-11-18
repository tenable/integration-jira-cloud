# Tenable.io for Jira Cloud

This integration is designed to pull Tenable.io vulnerability data and then
generate Jira Tasks and sub-tasks based on the current state of those
vulnerabilities.  Vulnerabilities will also be automatically closed once the
state of the vulnerability is marked as "fixed" within Tenable.io.

* The integration will create a _**Vulnerability Management**_ project, create
  the appropriate custom fields, and link them to the associated screen in order
  to store and display all of the necessary information.
* The integration will create a _**Task**_ for each Vulnerability and then each
  _vulnerability instance_ will be a _**Sub-task**_.  This means that if you
  have 5 hosts with [plugin 151074][151074], then you would have 1 Task with the
  details of [151074] and then 5 Sub-tasks associated with that task, each one
  pointing to a specific instance of that vulnerability on a specific host.
* Vulnerability Instances (Sub-tasks) will be closed automatically by the
  integration once the vulnerability is _**fixed**_ within Tenable.io.
* Vulnerabilities (Tasks) will be closed once all Sub-tasks have entered a
  closed state.
* If a vulnerability was found to have been re-opened, then new issue tickets
  will be generated (The integration will not re-open previously closed issues
  (otherwise known as necromancy))
* All data imports from Tenable.io use the last_found/last_seen fields.  This
  ensures that all issues are updated whenever new information becomes
  available.
* Task summaries are generated using the following formula:

```
[Plugin ID] Plugin Name
```

* Sub-task summaries are generated using the following formula:

```
[IP Address/Port Number/Protocol] [Plugin ID] Plugin Name
```

[151074]: https://www.tenable.com/plugins/nessus/131074

## Requirements

* Tenable.io API Keys associated to an account with Admin privileges (required
  for the Vuln Export APIs).
* Jira Cloud Basic Auth API Token & Username.  For automatic project creation
  and management, the account must be an Admin.
* A host to run the script on.  This can be located anywhere as the integration
  is cloud-to-cloud.

## Setup

```
pip install tenable-jira-cloud
```

## Configuration

In order to configure the integration, you will need to provide the script a
configuration file in the YAML format.  An [example config file][configfile]
is provided that details what items are required at a minimum in order for the
script to run.  A simple example would look like the following:

```yaml
tenable:
  access_key: 000001773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3700000
  secret_key: 111111773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3711111

jira:
  api_token: 11111scPw10lX2WvDoj00000
  api_username: username@company.com
  address: company.atlassian.net
```

[configfile]: example_config_file.yaml

## Options

As most of the configuration options for this script are contained within the
configuration file itself, only a few options are exposed via the commandline
interface:

```
Usage: tenable-jira [OPTIONS] [CONFIGFILE]

  Tenable.io -> Jira Cloud Transformer & Ingester

Options:
  -v, --verbose                 Logging Verbosity
  -s, --observed-since INTEGER  The unix timestamp of the age threshold
  -r, --run-every INTEGER       How many hours between recurring imports
  --help                        Show this message and exit.
```

Further the following environment variables can be used:

```
VERBOSITY           Logging Verbosity.
                        0 - WARNING
                        1 - INFO
                        2 - DEBUG
SINCE               The observed-since option.
RUN_EVERY           The run-every option.
```

## Example Usage

Run once and transform everything from all time:

```
tenable-jira config.yaml
```

Run once and only import findings that have been seen since yesterday:

```
tenable-jira -s $(date -v-1d +%s) config.yaml
```

Run the import every 24 hours

```
tenable-jira -r 24 config.yaml
```