# Change Log

All notable changes to this project will be documented in this file.

## [4.1.2](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/4.1.1...4.1.2)
### Bug Fixes

## [4.1.1](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/4.1.0...4.1.1)
### Bug Fixes
* Log an error instead of raising an exception when there are several results with the same grouping and distinct field
  values (see Alert Wizard plugin [issue 60](https://github.com/airbus-cyber/graylog-plugin-alert-wizard/issues/60))

## [4.1.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/4.0.1...4.1.0)
### Features
* Add compatibility with Graylog 4.2

## [4.0.1](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/4.0.0...4.0.1)
### Bug Fixes
* raised java.lang.IllegalStateException when evaluating an event definition with no grouping fields but a distinct field
* did not trigger for event definitions with distinct fields
* raise java.lang.IllegalArgumentException when triggering an event definition with several grouping fields

## [4.0.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/2.2.0...4.0.0)
### Features
* Add compatibility with Graylog 4.1
* Changed plugin license to SSPL version 1

## [2.2.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/2.1.2...2.2.0)
### Features
* Add compatibility with Graylog 3.3

## [2.1.2](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/2.1.1...2.1.2)
### Bug Fixes
* Fix Create only 1 event when the condition is satisfied

## [2.1.1](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/2.1.0...2.1.1)
### Bug Fixes
* Fix event source streams empty

## [2.1.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/2.0.0...2.1.0)
### Features
* Disabled isolated Plugin (shares a class loader with other plugins that have isolated=false)

## [2.0.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/1.2.2...2.0.0)
### Features
* Add compatibility with Graylog 3.2

## [1.2.2](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/1.2.1...1.2.2)
### Fix
* ([Issue #8](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/issues/8)) No backlog if backslash in a
  field

## [1.2.1](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/1.2.0...1.2.1)
### Fix
* ([Issue #7](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/issues/7)) Alert does not trigger if
  backlog is 0

## [1.2.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/1.1.0...1.2.0)
### Features
* Add compatibility with Graylog 3.0

## [1.1.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/compare/1.0.0...1.1.0)
### Features
* Add the Search Query functionality for compatibility with Graylog
  2.5 ([issue #2](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/issues/2))

## [1.0.0](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/tree/1.0.0)
* First release
