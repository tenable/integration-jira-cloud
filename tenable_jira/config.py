import yaml

def base_config():
    return yaml.load(config, Loader=yaml.Loader)

# WARNING: These are the default values that control how the transformer
#          processes vulnerability data into Jira tickets.  While the code
#          itself is meant to be very flexible, it's quite easy to shoot
#          yourself in the foot.  The complete configuration has therefor
#          been vendored below and parameters are overridden from the supplied
#          config file.  Overloading any values not explicitly documented in
#          the documentation is considered custom modification and will not be
#          officially supported as part of this out-of-the box integration.
#
#          In short, MODIFY AT YOUR OWN RISK.

config = '''
tenable:
  # What platform should we be connecting to?
  #  Must be either tenable.io and tenable.sc
  platform: tenable.io

  # Tenable.io or Tenable.sc API Access Key
  access_key:

  # Tenable.io or Tenable.sc API Secret Key
  secret_key:

  # The hostname for the Tenable.sc host
  address:

  # The port number on Tenable.sc to connect to
  port: 443

  # Note that Tenable.sc supports either session authentication or key
  # authentication.  You only need to provide one or the other.
  #
  # The username to use for Tenable.sc session auth.
  username:

  # The password to use for Tenable.sc session auth.
  password:

  # Tenable.io vulnerability severities to convert to JIRA tickets.
  tio_severities:
    - high
    - critical

  # Tenable.sc Query to use as the basis for generating JIRA tickets.
  query_id:

  # Number of assets per chunk to export from Tenable.io.
  chunk_size: 1000

  # Page size for Tenable.sc Analysis calls.
  page_size: 1000


jira:
  # The API Token to use to authenticate to the Jira application
  api_token:

  # The User that will be authenticaing to the Jira application
  api_username:

  # The address pointing to the Jira application.
  address: your-domain.atlassian.net

# The project definition is passed directly to the project creator if no project
# by the specified key does not exist.
# https://developer.atlassian.com/cloud/jira/platform/rest/v3/?utm_source=%2Fcloud%2Fjira%2Fplatform%2Frest%2F&utm_medium=302#api-rest-api-3-project-get
project:
  # The project Key to use.
  key: VULN

  # The name of the project
  name: Vulnerability Management

  # The project type
  projectTypeKey: business

  # The Jira project template id.
  projectTemplateKey: com.atlassian.jira-core-project-templates:jira-core-simplified-task-tracking

  # A description for the project
  description: Managing vulnerabilities discovered from Tenable products.

  # URL for the project.,
  url: https://tenable.com

  # The assignee determination for new issues.  Must be either
  # UNASSIGNED or PROJECT_LEAD as per the API docs.
  assigneeType: UNASSIGNED

  # The UUID for the project lead user.
  leadAccountId:


# This section defines the issue-types & how to search them.  There should only
# ever be a singular "standard" and no more than 1 "subtask".  The issue-type
# name is what will be used throughout the rest of the config file to determine
# what issue-type gets what data fields.
issue_types:
  - name: Task
    type: standard
    search:
      - Tenable Plugin ID
  - name: Sub-task
    type: subtask
    search:
      - Tenable Platform
      - Tenable Plugin ID
      - Tenable Asset UUID
      - Device IPv4 Addresses
      - Device IPv6 Addresses
      - Vulnerability Port
      - Vulnerability Protocol


# What transitions should be considered closed?
closed_transitions:
  - Closed
  - Done
  - Resolved


# Jira issues have some predefined fields.  When leveraging those, we will want
# to define how to use them here.  As the same field can be used differently
# depending on issue-type, we define how to use the field per issue-type.  When
# defining a vulnerability field or fields to use, we will use a parameterized
# string in the python standard.  All vuln items are passed as the vuln dict and
# the keys reference the flattened dictionary structure.
#
# Simple Single-line Example:
# summary:        <-- The Jira Field Name
#   Task:         <-- The Issue Type
#     tio_field:  <-- What to do with Tenable.io data
#     tsc_field:  <-- What to do with Tenable.sc data
#
# Multi-Paragraph Example:
# description:    <-- The Jira Field Name
#   Task:         <-- The Issue Type
#     - name:     <-- The name of the document section
#       tio_field <-- What to do with Tenable.io data
#       tsc_field <-- What to do with Tenable.sc data
issue_default_fields:
  summary:
    Task:
      tio_field: '[{vuln[plugin.id]}] {vuln[plugin.name]}'
      tsc_field: '[{vuln[pluginID]}] {vuln[pluginName]}'
    Sub-task:
      tio_field: '[{vuln[asset.hostname]}/{vuln[port.port]}/{vuln[port.protocol]}] [{vuln[plugin.id]}] {vuln[plugin.name]}'
      tsc_field: '[{vuln[ip]}/{vuln[port]}/{vuln[protocol]}] [{vuln[pluginID]}] {vuln[pluginName]}'
  description:
    Task:
      - name: Description
        tio_field: '{vuln[plugin.description]}'
        tsc_field: '{vuln[description]}'
      - name: Solution
        tio_field: '{vuln[plugin.solution]}'
        tsc_field: '{vuln[solution]}'
    Sub-task:
      - name: Description
        tio_field: '{vuln[plugin.description]}'
        tsc_field: '{vuln[description]}'
      - name: Solution
        tio_field: '{vuln[plugin.solution]}'
        tsc_field: '{vuln[solution]}'
      - name: Output
        tio_field: '{vuln[output]}'
        tsc_field: '{vuln[pluginOutput]}'


# Screen definition section
screen:
  # What screens should we be managing?
  name:
    - Task Management Edit/View Issue Screen
    - Task Management Create Issue Screen

  # How should the fields be laid out?  The tab name of "default" would specify
  # the main tab that you'd see when opening the issue.  Any other tabs are
  # sub-tabs that must be clicked into.
  tabs:
    Vulnerability:
      - CVEs
      - Tenable VPR Score
      - CVSSv2 Base Score
      - CVSSv2 Temporal Score
      - CVSSv3 Base Score
      - CVSSv3 Temporal Score
      - Tenable Plugin ID
      - Tenable Plugin Family
      - Tenable Plugin Name
      - Vulnerability Severity
      - Vulnerability First Seen
      - Vulnerability Last Seen
      - Vulnerability Last Fixed
      - Vulnerability State
      - Vulnerability Port
      - Vulnerability Protocol
      - Patch Publication Date
    Asset:
      - Tenable Asset UUID
      - Tenable Asset Tags
      - Tenable Platform
      - Device Hostname
      - Device NetBIOS Name
      - Device DNS Name
      - Device IPv4 Addresses
      - Device IPv6 Addresses
      - Device MAC Addresses
      - Device Network ID
      - Vulnerability Repository ID
      - Vulnerability Repository Name

# The custom fields are created automatically if they do not exist.  Further the
# mapping between the jira_field and the tio_field & tsc_field indicate what
# data is passed into the Jira custom field.
fields:

# An example of a specified field is as follows:
# - jira_field: NAME    - Name of the Jira Field. We search for this w/in the API.
#   jira_id: ID         - If specified, use this field ID instead of creating.
#   type: DATATYPE      - The type of data that will be stored here.
#   searcher: SEARCHER  - The Jira searcher to use for searching in Jira
#   issue_type:         - The issue types that this field is to be associated with.
#     - TYPE1
#     - TYPE2
#   tio_field: field.name - Tenable.io field to parse for this JIRA field.
#   tsc_field: field.name - Tenable.sc field to parse for this JIRA field.

  - jira_field: Tenable Platform
    type: readonlyfield
    searcher: textsearcher
    is_platform_id: true
    issue_type:
      - Sub-Task

  # Vulnerability fields
  - jira_field: CVEs
    type: labels
    searcher: labelsearcher
    issue_type:
      - Task
    tio_field: plugin.cve
    tsc_field: cve

  - jira_field: CVSSv2 Base Score
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.cvss_base_score
    tsc_field: baseScore

  - jira_field: CVSSv2 Temporal Score
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.cvss_temporal_score
    tsc_field: temporalScore

  - jira_field: CVSSv3 Base Score
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.cvss3_base_score
    tsc_field: cvssV3BaseScore

  - jira_field: CVSSv3 Temporal Score
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.cvss3_temporal_score
    tsc_field: cvssV3TemporalScore

  - jira_field: Patch Publication Date
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.patch_publication_date
    tsc_field: patchPubDate

  - jira_field: Tenable Plugin ID
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.id
    tsc_field: pluginID

  - jira_field: Tenable Plugin Family
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.family
    tsc_field: family.name

  - jira_field: Tenable Plugin Name
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.name
    tsc_field: pluginName

  - jira_field: Vulnerability Severity
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.risk_factor
    tsc_field: severity.name

  # Vulnerability Instance fields
  - jira_field: Tenable Asset UUID
    type: labels
    searcher: labelsearcher
    issue_type:
      - Sub-task
    tio_field: asset.uuid

  - jira_field: Tenable Asset Tags
    type: labels
    searcher: labelsearcher
    issue_type:
      - Sub-task
    is_tio_tags: true

  - jira_field: Device MAC Addresses
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tio_field: asset.mac_address
    tsc_field: macAddress

  - jira_field: Device IPv4 Addresses
    type: labels
    searcher: labelsearcher
    issue_type:
      - Sub-task
    tio_field: asset.ipv4
    tsc_field: ip

  - jira_field: Device IPv6 Addresses
    type: labels
    searcher: labelsearcher
    issue_type:
      - Sub-task
    tio_field: asset.ipv6

  - jira_field: Device Hostname
    type: labels
    searcher: labelsearcher
    issue_type:
      - Sub-task
    tio_field: asset.hostname
    tsc_field: dnsName

  - jira_field: Device NetBIOS Name
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tsc_field: netbiosName

  - jira_field: Device DNS Name
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tio_field: asset.fqdn
    tsc_field: dnsName

  - jira_field: Device Network ID
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tio_field: asset.network_id

  - jira_field: Vulnerability First Seen
    type: datetime
    searcher: datetimerange
    issue_type:
      - Sub-task
    tio_field: first_found
    tsc_field: firstSeen

  - jira_field: Vulnerability Last Seen
    type: datetime
    searcher: datetimerange
    issue_type:
      - Sub-task
    tio_field: last_found
    tsc_field: lastSeen

  - jira_field: Vulnerability Last Fixed
    type: datetime
    searcher: datetimerange
    issue_type:
      - Sub-task
    tio_field: last_fixed

  - jira_field: Vulnerability State
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tio_field: state

  - jira_field: Vulnerability Port
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tio_field: port.port
    tsc_field: port

  - jira_field: Vulnerability Protocol
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tio_field: port.protocol
    tsc_field: protocol

  - jira_field: Vulnerability Repository ID
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tsc_field: repository.id

  - jira_field: Vulnerability Repository Name
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Sub-task
    tsc_field: repository.name

  - jira_field: Tenable VPR Score
    type: readonlyfield
    searcher: textsearcher
    issue_type:
      - Task
      - Sub-task
    tio_field: plugin.vpr.score
    tsc_field: vprScore
'''