# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.22]
### Fixed
- Addressed timing gaps in the daemonization process #107
- Addressed issue with Jira summary field expecting fields to never be over 255 char. #102

[1.1.22]: https://github.com/tenable/pyTenable/compare/1.1.21...1.1.22

## [1.1.21]
### Fixed
- Issue identified with yaml.load() method that was insecure.  switched to safe_load instead.

### Added
- Ability to pull vulns by `first_found` as well as `last_found`.  This has been explained within a new section of the readme. #100

[1.1.21]: https://github.com/tenable/pyTenable/compare/1.1.20...1.1.21

# [1.1.20]
## Fixed
- Arrow version 1.x changes timestamp interface #103
- Tags with spaces are getting split by Jira #98

# [1.1.19]
## Fixed
- Severity Prioritization was only being handled on the issue, not subissue #96

## Changed
- README not described the TYPE of Jira project being created. #90


## [1.1.18]

## Fixed

- Asset Metadata merging was missing tagging data after changes made to support #74/#80
- Tenable Asset UUID now populated with agent UUID when using Tenable.sc

### Added

- `dry_run` boolean param within the config to dump the raw vuln, generate issue, and generate sub-issue to help identify problems.  In this mode, no tickets are actually created within Jira.

## [1.1.17]

### Fixed

- Vuln Export API changed, making the default behavior undesirable.

### Added

- Added default age to exports for Tenable.io. It's possible to override this with the `tenable.tio_age` parameter.
- Added ability to transform tags into asset attributes #74 #80

## [1.1.16]

### Fixed

- If no custom fields are listed, then the script will fail. set a default null list if unspecified.

## [1.1.15]

### Added

- Added ability to pass custom field definitions from the config without overloading the existing ones (additive definitions)

### Fixed

- Always add all asset attributes to the vuln doc (open AND fixed).

## [1.1.14]

### Added

- Added ability to merge asset data into vuln instance tickets
- Added ability to set Jira priority based on severity.

## [1.1.13]

### Fixed

- Removed accidental test value used for force a failure condition.

## [1.1.12]

### Added

- Added ability to ignore Jira Cloud API errors via config setting.

### Fixed

- The Jira Field id should reliably return on the first match

## [1.1.11]

### Added

- Asset tag support for Tenable.io

## [1.1.10]

### Added

- Autoclosing of terminated and deleted assets
- Additional debug reporting.

### Changed

- Closing methods are now more centralized.

### Fixed

- Patch publication wasn't a screen field.

## [1.1.9]

### Fixed

- First Seen and Last Seen in Tenable.io is actually first_found and last_found #45

### Added

- Added Patch Publication Date to base config #45

## [1.1.8]

### Fixed

- Addition of admin checking in CLI broke IO integration. #42

## [1.1.6]

### Added

- Optional support for filtering based on VPR #41
- Optional auto-closing of accepted risks #8
- Logging if the IO API Keys aren't tied to an admin-level account.

## [1.1.5]

### Added

- Added optional parameter to ignore accepted risks in Tenable.io #8

## [1.1.4]

### Added

- Added `--troubleshoot` commandline flag to generate output to use to help issue resolution.

## [1.1.3]

### Fixed

- Tenable Platform custom field wasn't getting the appropriate value in JQL searches, resulting in duplication #16

## [1.1.2]

### Fixed

- Embedded config referred to "Device IPv4" instead of "Device IPv4 Addresses" #15

## [1.1.1]

### Added

- Info logging will now output the field, screens, and tab IDs.

### Fixed

- Jira field lengths cannot exceed 32767 chars. #13
- Generified the Issue closing error log to avoid type mismatches #4

## [1.1.0]

### Added

- Setup-only mode to support configuration generation #1
- Tenable.sc support for ticket creation and management #2

### Fixed

- pyYAML compiled loaders switched for interpreted ones for compatability #7

## [1.0.1]

### Fixed

- Screen pagination wasn't being handled properly #3
- pyYAML wasn't defined as a requirement #6

### Added

- Closed transition states are now configurable. #4
- Support for a separate setup job #1

## [1.0.0]

- Initial Version

[1.1.20]: https://github.com/tenable/integration-jira-cloud/compare/1.1.19...1.1.20
[1.1.19]: https://github.com/tenable/integration-jira-cloud/compare/1.1.18...1.1.19
[1.1.18]: https://github.com/tenable/integration-jira-cloud/compare/1.1.17...1.1.18
[1.1.17]: https://github.com/tenable/integration-jira-cloud/compare/1.1.16...1.1.17
[1.1.16]: https://github.com/tenable/integration-jira-cloud/compare/1.1.15...1.1.16
[1.1.15]: https://github.com/tenable/integration-jira-cloud/compare/1.1.14...1.1.15
[1.1.14]: https://github.com/tenable/integration-jira-cloud/compare/1.1.13...1.1.14
[1.1.13]: https://github.com/tenable/integration-jira-cloud/compare/1.1.12...1.1.13
[1.1.12]: https://github.com/tenable/integration-jira-cloud/compare/1.1.11...1.1.12
[1.1.11]: https://github.com/tenable/integration-jira-cloud/compare/1.1.11...1.1.10
[1.1.10]: https://github.com/tenable/integration-jira-cloud/compare/1.1.9...1.1.10
[1.1.9]: https://github.com/tenable/integration-jira-cloud/compare/1.1.8...1.1.9
[1.1.8]: https://github.com/tenable/integration-jira-cloud/compare/1.1.7...1.1.8
[1.1.7]: https://github.com/tenable/integration-jira-cloud/compare/1.1.6...1.1.7
[1.1.6]: https://github.com/tenable/integration-jira-cloud/compare/1.1.5...1.1.6
[1.1.5]: https://github.com/tenable/integration-jira-cloud/compare/1.1.4...1.1.5
[1.1.4]: https://github.com/tenable/integration-jira-cloud/compare/1.1.3...1.1.4
[1.1.3]: https://github.com/tenable/integration-jira-cloud/compare/1.1.2...1.1.3
[1.1.2]: https://github.com/tenable/integration-jira-cloud/compare/1.1.1...1.1.2
[1.1.1]: https://github.com/tenable/integration-jira-cloud/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/tenable/integration-jira-cloud/compare/1.0.1...1.1.0
[1.0.1]: https://github.com/tenable/integration-jira-cloud/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/tenable/integration-jira-cloud/compare/56cd7f0...1.0.0
