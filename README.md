# Aggregation Count Plugin for Graylog

[![Continuous Integration](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/actions/workflows/ci.yml/badge.svg)](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-SSPL-green)](https://www.mongodb.com/licensing/server-side-public-license)
[![GitHub Release](https://img.shields.io/badge/release-v2.2.0-blue.svg)](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/releases)

#### Alert condition plugin for Graylog to perform aggregation

The alert condition triggers whenever the stream received more or less than X messages matching the same values of some message fields and with distinct values of other message fields in the last Y minutes.

Perfect for example to be alerted when there are brute-force attempts on your platform. Create a stream that catches every authentification failure and be alerted when that stream exceeds a given threshold per user.

Also perfect for example to be alerted when there are network port scans on your platform. Create a stream that catches your network traffic and be alerted when that stream exceeds a given threshold per source and per destination and with distinct values of port.

Please also take note that only a single alert is raised for this condition during the alerting interval, although multiple messages containing different values for the message fields may have been received since the last alert.

Example of raised alert:

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-aggregation-count/master/images/alert.png)

## Version Compatibility

|  Plugin Version | Graylog Version |
| --------------- | --------------- |
| 4.1.x           | 4.2.x           |
| 4.0.x           | 4.1.x           |
| 2.2.x           | 3.3.x           |
| 2.1.x           | 3.2.x           |
| 2.0.x           | 3.2.x           |
| 1.2.x           | 3.0.x           |
| 1.1.x           | 2.5.x           |
| 1.0.x           | 2.4.x           |

## Installation

[Download the plugin](https://github.com/airbus-cyber/graylog-plugin-aggregation-count/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

## Usage

First you have to select the alert type **Aggregation Count Alert Condition**

Then, you can configure the **Grouping Fields**  and the **Distinction Fields** to count messages respectively with the same values and with distinct values.

Optionally you can add a **Comment** about the configuration of the condition.

You can also set all the common parameters : **Threshold Type**, **Threshold**, **Search within the last**, **Execute search every** and **Search Query**.

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-aggregation-count/master/images/edit_condition.png)

## Build

This project is using Maven 3 and requires Java 8 or higher.

* Clone this repository.
* Run `mvn package` to build a JAR file.
* Optional: Run `mvn jdeb:jdeb` and `mvn rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

## License

This plugin is released under version 1 of the [Server Side Public License (SSPL)](LICENSE).
