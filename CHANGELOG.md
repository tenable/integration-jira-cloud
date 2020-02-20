# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.1]: https://github.com/tenable/integration-jira-cloud/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/tenable/integration-jira-cloud/compare/1.0.1...1.1.0
[1.0.1]: https://github.com/tenable/integration-jira-cloud/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/tenable/integration-jira-cloud/compare/56cd7f0...1.0.0