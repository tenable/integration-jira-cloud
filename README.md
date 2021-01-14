# Tenable for Jira Cloud

This integration is designed to pull Tenable.io vulnerability data, then
generate Jira Tasks and sub-tasks based on the vulnerabilities' current state.
Vulnerabilities are automatically closed once the state of the vulnerability is
marked as "fixed" in Tenable.io or Tenable.sc.

* The integration creates a _**Vulnerability Management**_ _Business_ project using
  the project key _**VULN**_ and the _Simplified Task Tracking_ template.  The
  integration then creates the appropriate custom fields and links them to the
  associated screen that stores and displays all of the necessary information.
* The integration creates a _**Task**_ for each Vulnerability and creates each
  _vulnerability instance_ as a _**Sub-task**_.  Example: if you have 5 hosts
  with [plugin 151074][151074], the integration creates 1 Task with the details
  of [151074] and creates 5 Sub-tasks, each one pointing to a specific instance
  of the vulnerability on a specific host.
* Vulnerability Instances (Sub-tasks) are closed automatically by the
  integration once the vulnerability is _**fixed**_ in Tenable.io.
* Vulnerabilities (Tasks) are closed once all Sub-tasks enter a closed state.
* If a vulnerability is re-opened, new issue tickets are generated
  (The integration will not reopen previously closed issues (otherwise known
  as necromancy))
* All data imports from Tenable.io use the last_found/last_seen fields.  This
  ensures that all issues are updated whenever new information becomes
  available.
* For those that don't mind a bit more management of the script in exchange for
  less permissions, there is a **setup-only** mode that will create the project,
  fields, and screens, then generate a full configuration file afterwards.  This
  file must be then used for all future runs of the integration and may need to
  be modified with the new, non-elevated user's authentication settings.
* Task summaries are generated using the following formula:

```
[Plugin ID] Plugin Name
```

* Sub-task summaries are generated using the following formula:

```
[IP Address/Port Number/Protocol] [Plugin ID] Plugin Name
```

* The integration will create the following fields into the Jira instance
    * CVEs
    * CVSSv2 Base Score
    * CVSSv2 Temporal Score
    * CVSSv3 Base Score
    * CVSSv3 Temporal Score
    * Device DNS Name
    * Device IPv4 Addresses
    * Device IPv6 Addresses
    * Device Hostname
    * Device MAC Addresses
    * Device NetBIOS Name
    * Device Network ID
    * Tenable Asset UUID
    * Tenable Platform
    * Tenable Plugin Family
    * Tenable Plugin ID
    * Tenable Plugin Name
    * Tenable VPR Score
    * Vulnerability First Seen
    * Vulnerability Last Seen
    * Vulnerability Last Fixed
    * Vulnerability State
    * Vulnerability Port
    * Vulnerability Protocol
    * Vulnerability Repository ID
    * Vulnerability Repository Name
    * Vulnerability Severity

* Vulnerability Definition (Task Issuetype) uniqueness is determined by the
  following attributes:
    * Tenable Plugin ID

* Vulnerability Instance (Sub-Task Issuetype) uniqueness is determines by the
  following attributes:
    * Tenable Platform
    * Tenable Plugin ID
    * Tenable Asset UUID
    * Device IPv4 Addresses
    * Device IPv6 Addresses
    * Vulnerability Port
    * Vulnerability Protocol


[151074]: https://www.tenable.com/plugins/nessus/131074

## Requirements

* Python 3.6+ Installed (Versions less than 3.6 are untested and YMMV).
* Tenable.io API Keys associated to an account with Admin privileges (required
  for the Vuln Export APIs) and is associated to the "All Access" access group.
* Tenable.sc API Keys (or Username/Password) associated to an account with full
  access to the vulnerability data.
* For Tenable.sc, an Analysis Query ID that represents the query to run against
  the vulnerability data.
* Jira Cloud Basic Auth API Token and Username.  For automatic project creation
  and management, the account must have Admin privileges.
* A host to run the script on.  This can be located anywhere as the integration
  is cloud-to-cloud.

## Permissions

* The script requires **Site Admin** Access at least initially to create the
  project, the custom fields, and link everything to the right screens.
* The script requires Admin access to the project that it has created.
  Depending on the permissions setup within your own Jira Cloud instance, this
  may not be enough however.  If you are seeing errors, please refer to the
  list of required permissions (below).
* If using setup-only (as Admin) to let the script create all of the requirements,
  afterwards, it's been [reported][i28_perms] that the following permissions should
  yeild successful runs:
  * Assignable User
  * Assign Issues
  * Close Issues
  * Create Issues
  * Delete Issues
  * Edit Issues
  * Link Issues
  * Modify Reporter
  * Move Issues
  * Resolve Issues
  * Schedule Issues
  * Set Issue Security
  * Transition Issues

[i28_perms]: https://github.com/tenable/integration-jira-cloud/issues/28#issuecomment-607386580


# Quickstart

for detailed instructions, please refer to the [wiki](https://github.com/tenable/integration-jira-cloud/wiki).

## Setup

```
pip install tenable-jira-cloud
```

## Configuration

In order to configure the integration, you need to provide the script with a
configuration file in YAML format.  The [example config file][configfile]
details the items required for the script to run.  A simple Tenable.io example
looks like the following:

```yaml
tenable:
  access_key: 000001773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3700000
  secret_key: 111111773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3711111

jira:
  api_token: 11111scPw10lX2WvDoj00000
  api_username: username@company.com
  address: company.atlassian.net

project:
  leadAccountId: 554433:00112233-ffee-aabb-aabb-998877665544
```

A Tenable.sc example using API keys would look like:

```yaml
tenable:
  platform: tenable.sc
  address: tenablesc.company.tld
  query_id: 406
  access_key: 000001773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3700000
  secret_key: 111111773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3711111

jira:
  api_token: 11111scPw10lX2WvDoj00000
  api_username: username@company.com
  address: company.atlassian.net

project:
  leadAccountId: 554433:00112233-ffee-aabb-aabb-998877665544
```

The same example using username/password would look like:

```yaml
tenable:
  platform: tenable.sc
  address: tenablesc.company.tld
  query_id: 406
  username: api_user
  password: sekretsquirrel

jira:
  api_token: 11111scPw10lX2WvDoj00000
  api_username: username@company.com
  address: company.atlassian.net

project:
  leadAccountId: 554433:00112233-ffee-aabb-aabb-998877665544
```


[configfile]: example_config_file.yaml

## Options

Most of the configuration options for this script are contained within the
configuration file itself with only a few options exposed via the
commandline interface:

```
Usage: tenable-jira [OPTIONS] [CONFIGFILE]

  Tenable.io -> Jira Cloud Transformer & Ingester

Options:
  -s, --observed-since INTEGER  The unix timestamp of the age threshold
  --setup-only                  Performs setup tasks and generates a config
                                file.
  --help                        Show this message and exit.
```

The following environment variables can be used:

```
SINCE               The observed-since option.
RUN_EVERY           The run-every option.
```


By default, the integration will only create jira tickets for CRITICAL and HIGH tenable findings only.
To create jira tickets for MEDIUM and LOW severity findings as well, update the config.yaml file to add the `tio_severities`  to the tenable section, as shown here:

```yaml
tenable:
  access_key: 000001773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3700000
  secret_key: 111111773236158ce8943c7369c12f98c092be2e1582b95ef86da5a6c3711111

  tio_severities:
    - critical
    - high
    - medium
    - low

...
```




## Example Usage

Basic Run:

```
tenable-jira config.yaml
```

Run and only import findings seen since yesterday:

```
tenable-jira -s $(date -v-1d +%s) config.yaml
```

Generate a config file to sidestep setup & validation:

```
tenable-jira config.yaml --setup-only
```

## Common Problems

JIRA Cloud's API doesn't have hard linkages between a projects, screens, and issuetypes.  While the integration generally seems to select the appropriate screens and issuetypes, sometimes for various reasons it will fail.  When this happens the integration will error in one of a couple of predictable ways.

### Common issue 1: **Invalid Issuetypes**

Refer to https://github.com/tenable/integration-jira-cloud/issues/18#issuecomment-594759198 and https://github.com/tenable/integration-jira-cloud/issues/23#issuecomment-604502293

### Common issue 2: **No Screens selected**

https://github.com/tenable/integration-jira-cloud/issues/23#issuecomment-604631753

## Support

Tenable offers support for this integration on a best-effort basis.  Tenable asserts that the integration contained in this repository should work on a clean Jira environment. Tenable makes no guarantees that this integration will work without customization to the integration or your Jira environment.  If customization is required to get this integration working, we recommend that you reach out to Tenable's professional services team to assist with any modifications that may be required.

If you would prefer that this integration be directly integrated into the Tenable platform, please reach out to your Customer Success Manager (CSM) about filing a feature request to get this functionality added to your platform.

## Changelog

[View the Changelog](CHANGELOG.md).
