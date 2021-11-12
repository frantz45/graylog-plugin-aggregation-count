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

package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.AggregationCount;
import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.AggregationField;
import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.Result;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.primitives.Ints;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventOriginContext;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog.events.processor.aggregation.AggregationSearch;
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.Parameter;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public class AggregationCountProcessor implements EventProcessor {
    public interface Factory extends EventProcessor.Factory<AggregationCountProcessor> {
        @Override
        AggregationCountProcessor create(EventDefinition eventDefinition);
    }

    private static final Logger LOG = LoggerFactory.getLogger(AggregationCountProcessor.class);

    private final EventDefinition eventDefinition;
    private final EventProcessorDependencyCheck dependencyCheck;
    private final DBEventProcessorStateService stateService;
    private final AggregationCount aggregationCount;
    private final AggregationCountProcessorConfig configuration;
    private final MoreSearch moreSearch;
    private final Searches searches;
    private final AggregationSearch.Factory aggregationSearchFactory;

    @Inject
    public AggregationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, Searches searches, MoreSearch moreSearch,
                                     AggregationSearch.Factory aggregationSearchFactory) {
        this.eventDefinition = eventDefinition;
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.configuration = (AggregationCountProcessorConfig) eventDefinition.config();
        this.aggregationCount = new AggregationCount(searches, moreSearch, configuration, eventDefinition, aggregationSearchFactory);
        this.moreSearch = moreSearch;
        this.searches = searches;
        this.aggregationSearchFactory = aggregationSearchFactory;
    }

    @Override
    public void createEvents(EventFactory eventFactory, EventProcessorParameters eventProcessorParameters, EventConsumer<List<EventWithContext>> eventConsumer) throws EventProcessorException {
        final AggregationCountProcessorParameters parameters = (AggregationCountProcessorParameters) eventProcessorParameters;

        TimeRange timerange = parameters.timerange();
        // TODO: We have to take the Elasticsearch index.refresh_interval into account here!
        if (!this.dependencyCheck.hasMessagesIndexedUpTo(timerange.getTo())) {
            final String msg = String.format(Locale.ROOT, "Couldn't run aggregation count <%s/%s> for timerange <%s to %s> because required messages haven't been indexed, yet.",
                    eventDefinition.title(), eventDefinition.id(), timerange.getFrom(), timerange.getTo());
            throw new EventProcessorPreconditionException(msg, eventDefinition);
        }

        Result aggregationCountCheckResult = this.aggregationCount.runCheck(timerange);

        if (aggregationCountCheckResult.getMessageSummaries() != null && !aggregationCountCheckResult.getMessageSummaries().isEmpty()) {
            eventConsumer.accept(eventsFromResult(eventFactory, timerange, aggregationCountCheckResult));
        }

        // Update the state for this processor! This state will be used for dependency checks between event processors.
        stateService.setState(eventDefinition.id(), timerange.getFrom(), timerange.getTo());
    }

    private ImmutableList<EventWithContext> eventsFromResult(EventFactory eventFactory, TimeRange timerange, Result aggregationCountCheckResult) {
        Event event = eventFactory.createEvent(eventDefinition, timerange.getFrom(), aggregationCountCheckResult.getResultDescription());
        event.addSourceStream(configuration.stream());

        event.setTimerangeStart(timerange.getFrom());
        event.setTimerangeEnd(timerange.getTo());

        MessageSummary msgSummary = aggregationCountCheckResult.getMessageSummaries().get(0);
        event.setOriginContext(EventOriginContext.elasticsearchMessage(msgSummary.getIndex(), msgSummary.getId()));
        LOG.debug("Created event: [id: " + event.getId() + "], [message: " + event.getMessage() + "].");

        final ImmutableList.Builder<EventWithContext> listEvents = ImmutableList.builder();
        // TODO: Choose a better message for the context
        EventWithContext eventWithContext = EventWithContext.create(event, msgSummary.getRawMessage());
        listEvents.add(eventWithContext);

        return listEvents.build();
    }

    @Override
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> messageConsumer, long limit) throws EventProcessorException {
        if (limit <= 0) {
            return;
        }

        final TimeRange timeRange = AbsoluteRange.create(event.getTimerangeStart(), event.getTimerangeEnd());
        boolean hasFields = !(configuration.groupingFields().isEmpty() && configuration.distinctionFields().isEmpty());
        if (hasFields) {
            AggregationField aggregationField = new AggregationField(configuration, this.searches, (int) limit, null, this.aggregationSearchFactory, this.eventDefinition);

            List<String> nextFields = new ArrayList<>(aggregationField.getFields());
            String firstField = nextFields.remove(0);

            /* Get the matched term */
            Map<String, Long> result = aggregationField.getTermsResult(this.configuration.stream(), timeRange, (int) limit);

            Map<String, List<String>> matchedTerms = new HashMap<>();
            long ruleCount = aggregationField.getMatchedTerm(matchedTerms, result);

            /* Get the list of summary messages */
            List<MessageSummary> summaries = Lists.newArrayListWithCapacity((int) limit);
            final String filter = "streams:" + this.configuration.stream();
            aggregationField.getListMessageSummary(summaries, matchedTerms, firstField, nextFields, timeRange, filter);

            messageConsumer.accept(summaries);
        } else {
            final AtomicLong msgCount = new AtomicLong(0L);
            final MoreSearch.ScrollCallback callback = (messages, continueScrolling) -> {

                final List<MessageSummary> summaries = Lists.newArrayList();
                for (final ResultMessage resultMessage : messages) {
                    if (msgCount.incrementAndGet() > limit) {
                        continueScrolling.set(false);
                        break;
                    }
                    final Message msg = resultMessage.getMessage();
                    summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
                }
                messageConsumer.accept(summaries);
            };
            Set<String> streams = new HashSet<>();
            streams.add(configuration.stream());
            Set<Parameter> parameters = new HashSet<>();
            moreSearch.scrollQuery(configuration.searchQuery(), streams, parameters, timeRange, Math.min(500, Ints.saturatedCast(limit)), callback);
        }
    }
}
