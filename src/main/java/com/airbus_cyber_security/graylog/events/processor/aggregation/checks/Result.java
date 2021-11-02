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

import org.graylog2.plugin.MessageSummary;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

public class Result {

    private final String resultDescription;

    private final List<MessageSummary> messageSummaries;

    private Result(final String resultDescription, final List<MessageSummary> messageSummaries) {
        this.resultDescription = resultDescription;
        this.messageSummaries = messageSummaries;
    }

    public String getResultDescription() {
        return resultDescription;
    }

    public List<MessageSummary> getMessageSummaries() {
        return messageSummaries;
    }

    public static class Builder {
        private final String resultDescriptionPattern;

        public Builder(String resultDescriptionPattern) {
            this.resultDescriptionPattern = resultDescriptionPattern;
        }

        public Result buildEmpty() {
            return new Result("", new ArrayList<>());
        }

        public Result build(long count, List<MessageSummary> summaries) {
            String resultDescription = MessageFormat.format(this.resultDescriptionPattern, count);
            return new Result(resultDescription, summaries);
        }
    }
}
