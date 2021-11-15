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
import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.Result;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventOriginContext;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog.events.processor.aggregation.AggregationSearch;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;
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

    @Inject
    public AggregationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, Searches searches, MoreSearch moreSearch,
                                     AggregationSearch.Factory aggregationSearchFactory) {
        this.eventDefinition = eventDefinition;
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.configuration = (AggregationCountProcessorConfig) eventDefinition.config();
        this.aggregationCount = new AggregationCount(searches, moreSearch, configuration, eventDefinition, aggregationSearchFactory);
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
        List<MessageSummary> summaries = this.aggregationCount.getMessageSummaries(timeRange, (int) limit);
        messageConsumer.accept(summaries);
    }
}
