import React from 'react';
import PropTypes from 'prop-types';

class AggregationCountSummary extends React.Component {
    static propTypes = {
        config: PropTypes.string.isRequired,
    };

    render() {
        const { config } = this.props;
        return (
            <React.Fragment>
                <tr>
                    <td>Stream:</td>
                    <td>{config.stream || 'No stream for this condition.'}</td>
                </tr>
                <tr>
                    <td>Threshold Type:</td>
                    <td>{config.threshold_type || 'No threshold type for this condition.'}</td>
                </tr>
                <tr>
                    <td>Threshold:</td>
                    <td>{config.threshold}</td>
                </tr>
                <tr>
                    <td>Time Range:</td>
                    <td>{config.time_range}</td>
                </tr>
                <tr>
                    <td>Grace Period:</td>
                    <td>{config.grace_period}</td>
                </tr>
                <tr>
                    <td>Message Backlog:</td>
                    <td>{config.message_backlog}</td>
                </tr>
                <tr>
                    <td>Grouping Fields:</td>
                    <td>{config.grouping_fields.join(', ') || 'No grouping fields for this condition.'}</td>
                </tr>
                <tr>
                    <td>Distinction Fields:</td>
                    <td>{config.distinction_fields.join(', ') || 'No distinction fields for this condition.'}</td>
                </tr>
                <tr>
                    <td>Comment:</td>
                    <td>{config.comment}</td>
                </tr>
                <tr>
                    <td>Search Query:</td>
                    <td>{config.search_query}</td>
                </tr>
                <tr>
                    <td>Repeat Notifications</td>
                    <td>{config.repeat_notifications? 'true' : 'false'}</td>
                </tr>
            </React.Fragment>
        );
    }
}

export default AggregationCountSummary;