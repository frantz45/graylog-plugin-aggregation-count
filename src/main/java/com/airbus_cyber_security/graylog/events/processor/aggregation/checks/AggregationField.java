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
import org.apache.logging.log4j.util.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.processor.aggregation.*;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.util.*;

public class AggregationField implements Check {
    private static final Logger LOG = LoggerFactory.getLogger(AggregationField.class);
    private static final String KEY_SEPARATOR = " - ";

    private final AggregationCountProcessorConfig configuration;
    private final Searches searches;
    private final Result.Builder resultBuilder;

    private String thresholdType;
    private int threshold;
    private String aggregatesThresholdType;
    private int aggregatesThreshold;

    private final AggregationSearch.Factory aggregationSearchFactory;
    private final EventDefinition eventDefinition;

    public AggregationField(AggregationCountProcessorConfig configuration, Searches searches, Result.Builder resultBuilder, AggregationSearch.Factory aggregationSearchFactory, EventDefinition eventDefinition) {
        this.configuration = configuration;
        this.searches = searches;
        this.resultBuilder = resultBuilder;
        this.setThresholds(configuration);
        this.aggregationSearchFactory = aggregationSearchFactory;
        this.eventDefinition = eventDefinition;
    }

    // TODO this is really complicated, this is related to the way the result is computed
    // could be simplified, but I am not doing it right now, since it may be risky
    // 1) first put grouping fields and distinct fields together to compute the count
    // 2) then, if there are distinct fields, for each grouping field combination, compute the cardinality of distinct fields
    //    should at the same time collect the combinations of values (grouping fields and distinct field), this is needed to get the message summaries
    // 3) then iterate over the grouping fields combinations and compute the message summaries
    private void setThresholds(AggregationCountProcessorConfig configuration) {
        if (!configuration.distinctionFields().isEmpty()) {
            this.thresholdType = ThresholdType.MORE.getDescription();
            this.threshold = 0;
            this.aggregatesThresholdType = configuration.thresholdType();
            this.aggregatesThreshold = configuration.threshold();
        } else {
            this.thresholdType = configuration.thresholdType();
            this.threshold = configuration.threshold();
            this.aggregatesThresholdType = ThresholdType.MORE.getDescription();
            this.aggregatesThreshold = 0;
        }
    }

    public List<String> getFields() {
        List<String> fields = new ArrayList<>();
        if (!this.configuration.groupingFields().isEmpty()) {
            fields.addAll(this.configuration.groupingFields());
        }
        if (!this.configuration.distinctionFields().isEmpty()) {
            fields.addAll(this.configuration.distinctionFields());
        }
        return fields;
    }

    private boolean isTriggered(ThresholdType thresholdType, int threshold, long count) {
        return (((thresholdType == ThresholdType.MORE) && (count > threshold)) ||
                ((thresholdType == ThresholdType.LESS) && (count < threshold)));
    }

    public Map<String, List<String>> getMatchedTerm(Map<String, Long> results) {
        Map<String, List<String>> matchedTerms = new HashMap<>();
        for (Map.Entry<String, Long> term : results.entrySet()) {

            String matchedFieldValue = term.getKey();
            Long count = term.getValue();

            if (isTriggered(ThresholdType.fromString(this.thresholdType), this.threshold, count)) {
                // TODO this is not really nice: we are splitting something we had before
                String[] valuesFields = matchedFieldValue.split(KEY_SEPARATOR);
                int i = 0;
                StringBuilder bldStringValuesAgregates = new StringBuilder("Agregates:");
                for (String field : getFields()) {
                    if (this.configuration.groupingFields().contains(field) && i < valuesFields.length) {
                        bldStringValuesAgregates.append(valuesFields[i]);
                    }
                    i++;
                }
                String valuesAgregates = bldStringValuesAgregates.toString();

                if (matchedTerms.containsKey(valuesAgregates)) {
                    matchedTerms.get(valuesAgregates).add(matchedFieldValue);
                } else {
                    matchedTerms.put(valuesAgregates, Lists.newArrayList(matchedFieldValue));
                }
            }
        }
        return matchedTerms;
    }

    private String buildSearchQuery(String firstField, List<String> nextFields, String matchedFieldValue) {
        matchedFieldValue = matchedFieldValue.replaceAll("\\\\", "\\\\\\\\");
        for (String field : nextFields) {
            matchedFieldValue = matchedFieldValue.replaceFirst(KEY_SEPARATOR, "\" AND " + field + ": \"");
        }
        return (this.configuration.searchQuery() + " AND " + firstField + ": \"" + matchedFieldValue + "\"");
    }

    private void addSearchMessages(List<MessageSummary> summaries, String searchQuery, String filter, TimeRange range, int searchLimit) {
        final SearchResult backlogResult = this.searches.search(searchQuery, filter,
                range, searchLimit, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        for (ResultMessage resultMessage : backlogResult.getResults()) {
            if (summaries.size() >= searchLimit) {
                break;
            }
            summaries.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
    }

    public List<MessageSummary> getListMessageSummary(Map<String, List<String>> matchedTerms, String firstField, List<String> nextFields, TimeRange range, int limit) {
        Map<String, Long> frequenciesFields = new HashMap<>();
        for (Map.Entry<String, List<String>> matchedTerm : matchedTerms.entrySet()) {
            String valuesAgregates = matchedTerm.getKey();
            List<String> listAggregates = matchedTerm.getValue();

            frequenciesFields.put(valuesAgregates, (long) listAggregates.size());
            LOG.debug(listAggregates.size() + " aggregates for values " + valuesAgregates);
        }

        String filter = "streams:" + this.configuration.stream();
        List<MessageSummary> summaries = Lists.newArrayListWithCapacity(limit);
        for (Map.Entry<String, Long> frequencyField : frequenciesFields.entrySet()) {
            if (isTriggered(ThresholdType.fromString(this.aggregatesThresholdType), this.aggregatesThreshold, frequencyField.getValue())) {
                for (String matchedFieldValue : matchedTerms.get(frequencyField.getKey())) {
                    String searchQuery = buildSearchQuery(firstField, nextFields, matchedFieldValue);

                    LOG.debug("Search: " + searchQuery);

                    addSearchMessages(summaries, searchQuery, filter, range, limit);

                    LOG.debug(summaries.size() + " Messages in CheckResult");
                }
            }
        }
        return summaries;
    }

    public Map<String, Long> getTermsResult(String stream, TimeRange timeRange, int limit) {
        ImmutableList.Builder<AggregationSeries> seriesBuilder = ImmutableList.builder();
        seriesBuilder.add(AggregationSeries.builder().id("aggregation_id").function(AggregationFunction.COUNT).build());
        AggregationEventProcessorConfig config = AggregationEventProcessorConfig.Builder.create()
                .groupBy(new ArrayList<>(this.getFields()))
                .query(this.configuration.searchQuery())
                .streams(ImmutableSet.of(stream))
                .executeEveryMs(this.configuration.executeEveryMs())
                .searchWithinMs(this.configuration.searchWithinMs())
//                .conditions() // TODO or not TODO, that is the question
                .series(seriesBuilder.build())
                .build(); // TODO
        AggregationEventProcessorParameters parameters = AggregationEventProcessorParameters.builder()
                .streams(ImmutableSet.of(stream)).batchSize(Long.valueOf(limit).intValue())
                .timerange(timeRange)
                .build(); // TODO Check if this is correct
        String owner = "event-processor-" + AggregationEventProcessorConfig.TYPE_NAME + "-" + this.eventDefinition.id();
        AggregationSearch search = this.aggregationSearchFactory.create(config, parameters, owner, this.eventDefinition);
        try {
            AggregationResult result = search.doSearch();
            return convertResult(result);
        } catch (EventProcessorException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            LOG.error("Error when converting result");
            e.printStackTrace();
            LOG.info("Complementary information in case of exception, timerange: {}, {}", timeRange.getFrom(), timeRange.getTo());
        }

        ImmutableMap.Builder<String, Long> terms = ImmutableMap.builder();
        return terms.build(); // TODO improve error case?
    }

    private Map<String, Long> convertResult(AggregationResult result) {
        ImmutableMap.Builder<String, Long> terms = ImmutableMap.builder();
        for (AggregationKeyResult keyResult: result.keyResults()) {
            String key = buildTermKey(keyResult);
            for (AggregationSeriesValue seriesValue : keyResult.seriesValues()) {
                Long value = Double.valueOf(seriesValue.value()).longValue();
                terms.put(key, value);
            }
        }

        try {
            // FIX: it seems there may be the same key several times in the result.
            // A suitable fix would probably be to retain only the max (in case of a condition MORE)
            // and the min (in case of a condition LESS)
            // This gets a bit too complex for my taste
            // It is probably better to just forget about distinct field (and use the graylog builtin aggregation facility)
            return terms.build();
        } catch (IllegalArgumentException e) {
            // If this ever happens, then it means it is possible to have two keyResults with the same key
            // => then, instead of putting the value in terms, should maybe add or replace the value (depends on the exact behavior of graylog)
            LOG.info("It seems there are two results with the same key. Listing all results...");
            LOG.info("Result's effective timerange {}, {}", result.effectiveTimerange().from(), result.effectiveTimerange().to());
            for (AggregationKeyResult keyResult: result.keyResults()) {
                String key = buildTermKey(keyResult);
                LOG.info("timestamp: {}", keyResult.timestamp());
                LOG.info("key: {} ->", key);
                for (AggregationSeriesValue seriesValue: keyResult.seriesValues()) {
                    Long value = Double.valueOf(seriesValue.value()).longValue();
                    LOG.info("value: {}", value);
                    terms.put(key, value);
                }
            }

            throw e;
        }
    }

    private String buildTermKey(AggregationKeyResult keyResult) {
        Collection<String> keys = keyResult.key();
        StringBuilder builder = new StringBuilder();
        keys.forEach(key -> {
            if (0 < builder.length()) {
                builder.append(" - ");
            }
            builder.append(key);
        });
        return builder.toString();
    }

    /**
     * Check if the condition is triggered
     * <p>
     * This condition is triggered when the number of messages with the same value of some message fields
     * and with distinct values of other messages fields is higher/lower than a defined threshold in a given time range.
     *
     * @return AggregationCountCheckResult
     * Result Description and list of messages that satisfy the conditions
     */
    @Override
    public Result run(TimeRange range, int limit) {
        List<String> nextFields = new ArrayList<>(getFields());
        String firstField = nextFields.remove(0);

        Map<String, Long> result = getTermsResult(this.configuration.stream(), range, limit);

        Map<String, List<String>> matchedTerms = getMatchedTerm(result);

        List<MessageSummary> summaries = getListMessageSummary(matchedTerms, firstField, nextFields, range, limit);

        /* If rule triggered return the check result */
        if (summaries.size() == 0) {
            return this.resultBuilder.buildEmpty();
        }

        return this.resultBuilder.build(summaries.size(), summaries);
    }

    @Override
    public List<MessageSummary> getMessageSummaries(TimeRange timeRange, int limit) {
        List<String> nextFields = new ArrayList<>(this.getFields());
        String firstField = nextFields.remove(0);

        Map<String, Long> result = this.getTermsResult(this.configuration.stream(), timeRange, limit);

        Map<String, List<String>> matchedTerms = this.getMatchedTerm(result);

        return this.getListMessageSummary(matchedTerms, firstField, nextFields, timeRange, limit);
    }
}
