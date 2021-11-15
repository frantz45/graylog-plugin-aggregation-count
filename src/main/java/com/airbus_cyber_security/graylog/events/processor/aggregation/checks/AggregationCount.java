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

package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountProcessorConfig;
import com.google.common.collect.Lists;
import com.google.common.primitives.Ints;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.processor.aggregation.AggregationSearch;
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.Parameter;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

public class AggregationCount {
    private static final int SEARCH_LIMIT = 500;

    private final Check check;

    public AggregationCount(Searches searches, MoreSearch moreSearch, AggregationCountProcessorConfig configuration, EventDefinition eventDefinition,
                            AggregationSearch.Factory aggregationSearchFactory) {
        String resultDescriptionPattern = buildResultDescriptionPattern(configuration);
        Result.Builder resultBuilder = new Result.Builder(resultDescriptionPattern);
        boolean hasFields = !(configuration.groupingFields().isEmpty() && configuration.distinctionFields().isEmpty());
        if (hasFields) {
            this.check = new AggregationField(configuration, searches, resultBuilder, aggregationSearchFactory, eventDefinition);
        } else {
            this.check = new NoFields(configuration, searches, moreSearch, resultBuilder);
        }
    }

    public Result runCheck(TimeRange timerange) {
        return this.check.run(timerange, SEARCH_LIMIT);
    }

    private String buildResultDescriptionPattern(AggregationCountProcessorConfig configuration) {

        String result = "Stream had {0} messages in the last "
                + configuration.searchWithinMs() + " milliseconds with trigger condition "
                + configuration.thresholdType().toLowerCase(Locale.ENGLISH) + " than "
                + configuration.threshold() + " messages";

        if (!configuration.groupingFields().isEmpty()) {
            result += " with the same value of the fields " + String.join(", ", configuration.groupingFields());
        }

        if (!configuration.groupingFields().isEmpty() && !configuration.distinctionFields().isEmpty()) {
            result += ", and";
        }

        if (!configuration.distinctionFields().isEmpty()) {
            result += " with distinct values of the fields " + String.join(", ", configuration.distinctionFields());
        }

        result += ". (Executes every: " + configuration.executeEveryMs() + " milliseconds)";

        return result;
    }

    public List<MessageSummary> getMessageSummaries(TimeRange timeRange, int limit) throws EventProcessorException {
        return this.check.getMessageSummaries(timeRange, limit);
    }
}
