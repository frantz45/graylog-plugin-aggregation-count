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
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.primitives.Ints;
import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.Parameter;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public class NoFields implements Check {

    private final AggregationCountProcessorConfig configuration;
    private final Searches searches;
    private final MoreSearch moreSearch;
    private final int searchLimit;
    private final Result.Builder resultBuilder;

    public NoFields(AggregationCountProcessorConfig configuration, Searches searches, MoreSearch moreSearch, int searchLimit, Result.Builder resultBuilder) {
        this.configuration = configuration;
        this.searches = searches;
        this.moreSearch = moreSearch;
        this.searchLimit = searchLimit;
        this.resultBuilder = resultBuilder;
    }

    private String buildQueryFilter(String streamId, String query) {
        Preconditions.checkArgument(streamId != null, "streamId parameter cannot be null");
        String trimmedStreamId = streamId.trim();
        Preconditions.checkArgument(!trimmedStreamId.isEmpty(), "streamId parameter cannot be empty");
        StringBuilder builder = (new StringBuilder()).append("streams:").append(trimmedStreamId);
        if (query != null) {
            String trimmedQuery = query.trim();
            if (!trimmedQuery.isEmpty() && !"*".equals(trimmedQuery)) {
                builder.append(" AND (").append(trimmedQuery).append(")");
            }
        }

        return builder.toString();
    }

    @Override
    public Result run(TimeRange range) {
        String filter = buildQueryFilter(this.configuration.stream(), this.configuration.searchQuery());
        CountResult result = this.searches.count("*", range, filter);
        long count = result.count();
        boolean triggered;
        switch (ThresholdType.fromString(this.configuration.thresholdType())) {
            case MORE:
                triggered = count > (long) this.configuration.threshold();
                break;
            case LESS:
                triggered = count < (long) this.configuration.threshold();
                break;
            default:
                triggered = false;
        }

        if (!triggered) {
            return this.resultBuilder.buildEmpty();
        }
        List<MessageSummary> summaries = Lists.newArrayList();
        SearchResult backlogResult = this.searches.search("*", filter, range, this.searchLimit, 0, new Sorting("timestamp", Sorting.Direction.DESC));

        for (ResultMessage resultMessage: backlogResult.getResults()) {
            Message msg = resultMessage.getMessage();
            summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
        }
        return this.resultBuilder.build(count, summaries);
    }

    @Override
    public List<MessageSummary> getMessageSummaries(int limit, TimeRange timeRange) throws EventProcessorException {
        final List<MessageSummary> summaries = Lists.newArrayListWithCapacity((int) limit);
        final AtomicLong msgCount = new AtomicLong(0L);
        final MoreSearch.ScrollCallback callback = (messages, continueScrolling) -> {
            for (final ResultMessage resultMessage : messages) {
                if (msgCount.incrementAndGet() > limit) {
                    continueScrolling.set(false);
                    break;
                }
                final Message msg = resultMessage.getMessage();
                summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
            }
        };
        Set<String> streams = new HashSet<>();
        streams.add(configuration.stream());
        Set<Parameter> parameters = new HashSet<>();
        this.moreSearch.scrollQuery(configuration.searchQuery(), streams, parameters, timeRange, Math.min(500, Ints.saturatedCast(limit)), callback);
        return summaries;
    }
}
