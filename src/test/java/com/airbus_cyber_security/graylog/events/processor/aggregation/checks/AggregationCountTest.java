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
import com.google.common.collect.Lists;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.aggregation.*;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.*;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class AggregationCountTest {

    private final int threshold = 2;

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private MoreSearch moreSearch;
    @Mock
    private Searches searches;
    @Mock
    private AggregationSearch.Factory aggregationSearchFactory;
    @Mock
    private AggregationSearch aggregationSearch;

    private EventDefinitionDto eventDefinitionDto = EventDefinitionDto.builder()
            .id("dto-id")
            .title("Test Correlation")
            .description("A test correlation event processors")
            .config(getAggregationCountProcessorConfig())
            .alert(false)
            .keySpec(ImmutableList.of())
            .notificationSettings(EventNotificationSettings.withGracePeriod(60000))
            .priority(1)
            .build();

    private AggregationCount subject;

    private AggregationCountProcessorConfig getAggregationCountProcessorConfig() {
        return AggregationCountProcessorConfig.builder()
                .stream("main stream")
                .thresholdType(ThresholdType.MORE.getDescription())
                .threshold(threshold)
                .searchWithinMs(2 * 60 * 1000)
                .executeEveryMs(2 * 60 * 1000)
                .groupingFields(new HashSet<>())
                .distinctionFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .build();
    }

    @Test
    public void runCheckShouldPreciseMoreThanInTheResult() {

        ThresholdType type = ThresholdType.MORE;
        List<String> groupingFields = new ArrayList<>();
        List<String> distinctionFields = new ArrayList<>();
        int thresholdTest = 9;

        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, thresholdTest, groupingFields, distinctionFields);
        this.subject = new AggregationCount(this.searches, this.moreSearch, configuration, this.eventDefinitionDto, this.aggregationSearchFactory);

        final CountResult countResult = mock(CountResult.class);
        when(countResult.count()).thenReturn(thresholdTest + 1L);
        when(this.searches.count(anyString(), any(TimeRange.class), anyString())).thenReturn(countResult);
        when(this.searches.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());

        Result result = this.subject.runCheck(buildDummyTimeRange());

        assertThat(result.getResultDescription(), containsString("more than"));
    }

    @Test
    public void runCheckWithAggregateMorePositive() throws Exception {
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");
        List<String> distinctionFields = new ArrayList<>();
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(ThresholdType.MORE, 2, groupingFields, distinctionFields);
        this.subject = new AggregationCount(this.searches, this.moreSearch, configuration, this.eventDefinitionDto, this.aggregationSearchFactory);

        mockFactorySearch();

        searchTermsThreeAggregateWillReturn(threshold + 1);
        when(this.searches.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());
        Result result = this.subject.runCheck(buildDummyTimeRange());

        String resultDescription = "Stream had 3 messages in the last 0 milliseconds with trigger condition more than 2 messages with the same value of the fields ip_src, user. (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 3, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithAggregateLessPositive() throws Exception {
        final ThresholdType type = ThresholdType.LESS;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields);
        this.subject = new AggregationCount(this.searches, this.moreSearch, configuration, this.eventDefinitionDto, this.aggregationSearchFactory);

        mockFactorySearch();
        searchTermsOneAggregateShouldReturn(threshold + 1L);
        when(this.searches.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());

        Result result = this.subject.runCheck(buildDummyTimeRange());

        String resultDescription = "Stream had 1 messages in the last 0 milliseconds with trigger condition less than " + threshold + " messages with the same value of the fields " + String.join(", ", configuration.groupingFields())
                + ", and with distinct values of the fields " + String.join(", ", configuration.distinctionFields()) + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 1, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithAggregateMoreNegative() throws Exception {
        ThresholdType type = ThresholdType.MORE;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields);
        this.subject = new AggregationCount(this.searches, this.moreSearch, configuration, this.eventDefinitionDto, this.aggregationSearchFactory);

        mockFactorySearch();
        searchTermsOneAggregateShouldReturn(threshold - 1L);

        Result result = this.subject.runCheck(buildDummyTimeRange());
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());


// TODO
//        AggregationSearch aggregationSearch = mock(AggregationSearch.class);
//        when(this.aggregationSearchFactory.create(any(AggregationEventProcessorConfig.class),
//                any(AggregationEventProcessorParameters.class ),
//                anyString(),
//                any(EventDefinition.class))).thenReturn(aggregationSearch);
    }

    @Test
    public void runCheckWithAggregateLessNegative() throws Exception {
        ThresholdType type = ThresholdType.LESS;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        List<String> distinctionFields = new ArrayList<>();
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields);
        this.subject = new AggregationCount(this.searches, this.moreSearch, configuration, this.eventDefinitionDto, this.aggregationSearchFactory);

        mockFactorySearch();
        searchTermsThreeAggregateWillReturn(threshold + 1);

        Result result = this.subject.runCheck(buildDummyTimeRange());
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithAggregateMorePositiveWithNoBacklog() throws Exception {
        ThresholdType type = ThresholdType.MORE;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");
        List<String> distinctionFields = new ArrayList<>();
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields);
        this.subject = new AggregationCount(this.searches, this.moreSearch, configuration, this.eventDefinitionDto, this.aggregationSearchFactory);

        mockFactorySearch();
        searchTermsThreeAggregateWillReturn(threshold + 1);
        when(this.searches.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());

        Result result = this.subject.runCheck(buildDummyTimeRange());
        String resultDescription = "Stream had " + (threshold + 1) + " messages in the last 0 milliseconds with trigger condition more than "
                + configuration.threshold() + " messages with the same value of the fields " + String.join(", ", configuration.groupingFields())
                + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 3, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithNoGroupingFieldsAndNoDistinctFields() {
        ThresholdType type = ThresholdType.MORE;
        List<String> groupingFields = new ArrayList<>();
        List<String> distinctionFields = new ArrayList<>();
        final int thresholdTest = 9;

        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, thresholdTest, groupingFields, distinctionFields);
        this.subject = new AggregationCount(this.searches, this.moreSearch, configuration, this.eventDefinitionDto, this.aggregationSearchFactory);

        final CountResult countResult = mock(CountResult.class);
        when(countResult.count()).thenReturn(thresholdTest + 1L);
        when(this.searches.count(anyString(), any(TimeRange.class), anyString())).thenReturn(countResult);
        when(this.searches.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());

        Result result = this.subject.runCheck(buildDummyTimeRange());

        String resultDescription = "Stream had 10 messages in the last 0 milliseconds with trigger condition more than 9 messages. (Executes every: 0 milliseconds)";
        assertEquals("ResultDescription", resultDescription, result.getResultDescription());
    }

    private AggregationCountProcessorConfig getAggregationCountProcessorConfigWithFields(ThresholdType type,
                                                                                         int threshold, List<String> groupingFields, List<String> distinctionFields) {
        return AggregationCountProcessorConfig.builder()
                .stream("main stream")
                .thresholdType(type.getDescription())
                .threshold(threshold)
                .searchWithinMs(0)
                .executeEveryMs(0)
                .groupingFields(new TreeSet<>(groupingFields))
                .distinctionFields(new TreeSet<>(distinctionFields))
                .comment("test comment")
                .searchQuery("*")
                .build();
    }

    private void searchTermsOneAggregateShouldReturn(long count) throws Exception {
        mockAggregationResult(1);
//        final TermsResult termsResult = mock(TermsResult.class);
//        Map<String, Long> terms = new HashMap<String, Long>();
//        terms.put("user - ip1", count);
//
//        when(termsResult.terms()).thenReturn(terms);

        // TODO Make test
        //when(moreSearch.terms(anyString(), anyList(), any(int.class), anyString(), anyString(), any(TimeRange.class), any(Sorting.Direction.class))).thenReturn(termsResult);

    }

    private void searchTermsThreeAggregateWillReturn(int count) throws Exception {
        mockAggregationResult(count);

//        final TermsResult termsResult = mock(TermsResult.class);
//        Map<String, Long> terms = new HashMap<String, Long>();
//        terms.put("user - ip1", count);
//        terms.put("user - ip2", count);
//        terms.put("user - ip3", count);
//
//        when(termsResult.terms()).thenReturn(terms);

        // TODO Make test
        //when(moreSearch.terms(anyString(), anyList(), any(int.class), anyString(), anyString(), any(TimeRange.class), any(Sorting.Direction.class))).thenReturn(termsResult);
    }

    private AggregationSeriesValue mockSeriesValue(int count, String... keys) {
        AggregationSeriesValue aggregationSeriesValue = mock(AggregationSeriesValue.class);
        when(aggregationSeriesValue.key()).thenReturn(ImmutableList.copyOf(keys));
        when(aggregationSeriesValue.value()).thenReturn(Double.valueOf(count));
        return aggregationSeriesValue;
    }

    private void mockFactorySearch() throws Exception {
        when(this.aggregationSearchFactory.create(any(AggregationEventProcessorConfig.class),
                any(AggregationEventProcessorParameters.class),
                anyString(),
                any(EventDefinition.class))).thenReturn(aggregationSearch);
    }

    private void mockAggregationResult(int count) throws Exception {
        ImmutableList.Builder<AggregationSeriesValue> seriesValues = ImmutableList.builder();
        for (int i = 1; i <= count; i++) {
            AggregationSeriesValue aggregationSeriesValue = mockSeriesValue(count, "user", "ip" + i);
            seriesValues.add(aggregationSeriesValue);
        }

        AggregationKeyResult aggregationKeyResult = mock(AggregationKeyResult.class);
        when(aggregationKeyResult.seriesValues()).thenReturn(seriesValues.build());

        AggregationResult aggregationResult = mock(AggregationResult.class);
        when(aggregationResult.totalAggregatedMessages()).thenReturn(3L * count);
        when(aggregationResult.keyResults()).thenReturn(ImmutableList.of(aggregationKeyResult));

        when(aggregationSearch.doSearch()).thenReturn(aggregationResult);
    }

    private SearchResult buildDummySearchResult() {
        List<ResultMessage> hits = Lists.newArrayList(
                ResultMessage.parseFromSource("id", "index", new HashMap<String, Object>())
        );
        return new SearchResult(hits, 2, new HashSet<>(), "originalQuery", "builtQuery", 0);
    }

    private TimeRange buildDummyTimeRange() {
        DateTime now = DateTime.now(DateTimeZone.UTC);
        return AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
    }
}
