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
import org.graylog2.rest.models.search.responses.TermsResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AggregationField implements Check {
    private static final Logger LOG = LoggerFactory.getLogger(AggregationField.class);

    private final AggregationCountProcessorConfig configuration;
    private final Searches searches;
    private final int searchLimit;
    private final Result.Builder resultBuilder;

    private String thresholdType;
    private int threshold;
    private String aggregatesThresholdType;
    private int aggregatesThreshold;

    private final AggregationSearch.Factory aggregationSearchFactory;
    private final EventDefinition eventDefinition;

    public AggregationField(AggregationCountProcessorConfig configuration, Searches searches, int searchLimit, Result.Builder resultBuilder, AggregationSearch.Factory aggregationSearchFactory, EventDefinition eventDefinition) {
        this.configuration = configuration;
        this.searches = searches;
        this.searchLimit = searchLimit;
        this.resultBuilder = resultBuilder;
        this.setThresholds(configuration);
        this.aggregationSearchFactory = aggregationSearchFactory;
        this.eventDefinition = eventDefinition;
    }

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

    /**
     * @param matchedTerms non-null list of matched terms to return
     * @param termsResult
     * @return return the rule count
     **/
    public long getMatchedTerm(Map<String, List<String>> matchedTerms, TermsResult termsResult) {
        long ruleCount = 0;
        boolean isFirstTriggered = true;
        for (Map.Entry<String, Long> term : termsResult.terms().entrySet()) {

            String matchedFieldValue = term.getKey();
            Long count = term.getValue();

            if (isTriggered(ThresholdType.fromString(thresholdType), threshold, count)) {
                String[] valuesFields = matchedFieldValue.split(" - ");
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

                if (isFirstTriggered) {
                    ruleCount = count;
                    isFirstTriggered = false;
                }
            }
        }
        return ruleCount;
    }

    private String buildSearchQuery(String firstField, List<String> nextFields, String matchedFieldValue) {
        matchedFieldValue = matchedFieldValue.replaceAll("\\\\", "\\\\\\\\");
        for (String field : nextFields) {
            matchedFieldValue = matchedFieldValue.replaceFirst(" - ", "\" AND " + field + ": \"");
        }
        return (this.configuration.searchQuery() + " AND " + firstField + ": \"" + matchedFieldValue + "\"");
    }

    private void addSearchMessages(List<MessageSummary> summaries, String searchQuery, String filter, TimeRange range) {
        final SearchResult backlogResult = this.searches.search(searchQuery, filter,
                range, this.searchLimit, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        for (ResultMessage resultMessage : backlogResult.getResults()) {
            if (summaries.size() >= this.searchLimit) {
                break;
            }
            summaries.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
    }

    public boolean getListMessageSummary(List<MessageSummary> summaries, Map<String, List<String>> matchedTerms,
                                         String firstField, List<String> nextFields, TimeRange range, String filter) {
        boolean ruleTriggered = false;
        Map<String, Long> frequenciesFields = new HashMap<>();
        for (Map.Entry<String, List<String>> matchedTerm : matchedTerms.entrySet()) {
            String valuesAgregates = matchedTerm.getKey();
            List<String> listAggregates = matchedTerm.getValue();

            if (!frequenciesFields.containsKey(valuesAgregates)) {
                frequenciesFields.put(valuesAgregates, (long) listAggregates.size());
                LOG.debug(listAggregates.size() + " aggregates for values " + valuesAgregates);
            }
        }

        for (Map.Entry<String, Long> frequencyField : frequenciesFields.entrySet()) {
            if (isTriggered(ThresholdType.fromString(aggregatesThresholdType), aggregatesThreshold, frequencyField.getValue())) {
                ruleTriggered = true;

                for (String matchedFieldValue : matchedTerms.get(frequencyField.getKey())) {
                    String searchQuery = buildSearchQuery(firstField, nextFields, matchedFieldValue);

                    LOG.debug("Search: " + searchQuery);

                    addSearchMessages(summaries, searchQuery, filter, range);

                    LOG.debug(summaries.size() + " Messages in CheckResult");
                }
            }
        }
        return ruleTriggered;
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
    public Result run(TimeRange range) {
        List<String> nextFields = new ArrayList<>(getFields());
        String firstField = nextFields.remove(0);

        /* Get the matched term */
        TermsResult result = getTermsResult(this.configuration.stream(), range, this.searchLimit);
        //this.searches.terms(firstField, nextFields, this.searchLimit, this.configuration.searchQuery(), filter, range, Sorting.Direction.DESC);

        Map<String, List<String>> matchedTerms = new HashMap<>();
        long ruleCount = getMatchedTerm(matchedTerms, result);

        /* Get the list of summary messages */
        List<MessageSummary> summaries = Lists.newArrayListWithCapacity(this.searchLimit);
        final String filter = "streams:" + this.configuration.stream();
        boolean ruleTriggered = getListMessageSummary(summaries, matchedTerms, firstField, nextFields, range, filter);

        /* If rule triggered return the check result */
        if (ruleTriggered) {
            long messageNumber;
            if (!configuration.distinctionFields().isEmpty()) {
                messageNumber = summaries.size();
            } else {
                messageNumber = ruleCount;
            }
            return this.resultBuilder.build(messageNumber, summaries);
        }

        return this.resultBuilder.buildEmpty();
    }

    public TermsResult getTermsResult(String stream, TimeRange timeRange, long limit) {
        ImmutableList.Builder<AggregationSeries> seriesBuilder = ImmutableList.builder();
        for (String groupingField : this.configuration.groupingFields()) { // TODO check for first grouping field (maybe unexpected date)
            seriesBuilder.add(AggregationSeries.builder().id("aggregation_id" + groupingField).function(AggregationFunction.COUNT).field(groupingField).build());
        }
        String query = this.configuration.searchQuery();
        AggregationEventProcessorConfig config = AggregationEventProcessorConfig.Builder.create()
                .groupBy(new ArrayList<>(this.configuration.groupingFields()))
                .query(query)
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
            return convertResult(query, result);
        } catch (EventProcessorException e) {
            e.printStackTrace();
        }

        ImmutableMap.Builder<String, Long> terms = ImmutableMap.builder();
        return TermsResult.create(0, terms.build(), 0, 0, 0, query); // TODO improve error case?
    }

    private TermsResult convertResult(String query, AggregationResult result) {
        ImmutableMap.Builder<String, Long> terms = ImmutableMap.builder();
        for (AggregationKeyResult keyResult : result.keyResults()) {
            for (AggregationSeriesValue seriesValue : keyResult.seriesValues()) {
                String key = buildTermKey(seriesValue.key());
                Long value = Double.valueOf(seriesValue.value()).longValue();
                terms.put(key, value);
            }
        }

        long total = result.totalAggregatedMessages();
        return TermsResult.create(0, terms.build(), 0, 0, total, query);
    }

    private String buildTermKey(Collection<String> keys) {
        StringBuilder builder = new StringBuilder();
        keys.forEach(key -> {
            if (0 < builder.length()) {
                builder.append(" - ");
            }
            builder.append(key);
        });
        return builder.toString();
    }

}
