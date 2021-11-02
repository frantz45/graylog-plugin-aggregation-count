/*
 * Copyright (C) 2018 Airbus CyberSecurity (SAS)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';

import AggregationCountFormContainer from "./components/event-definitions/event-definition-types/AggregationCountFormContainer";
import AggregationCountSummary from "./components/event-definitions/event-definition-types/AggregationCountSummary";

PluginStore.register(new PluginManifest({}, {
    eventDefinitionTypes: [
        {
            type: 'aggregation-count',
            displayName: 'Aggregation Count Alert Condition',
            sortOrder: 2, // Sort before conditions working on events
            description: 'This condition is triggered when the number of messages with the same value of some message fields '
                + 'and with distinct values of other messages fields is higher/lower than a defined threshold in a given time range.',
            formComponent: AggregationCountFormContainer,
            summaryComponent: AggregationCountSummary,
            defaultConfig: {
              stream: '',
              threshold_type: 'more than',
              threshold: '0',
              search_within_ms: 60*1000,
              execute_every_ms: 60*1000,
              grouping_fields: [],
              distinction_fields: [],
              comment: '',
              search_query: '*',
            },
        },
    ],
}));