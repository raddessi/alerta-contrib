
import dateutil.parser
import logging
import os
import re
import requests

try:
    from alerta.plugins import app  # alerta >= 5.0
except ImportError:
    from alerta.app import app  # alerta < 5.0
from alerta.plugins import PluginBase


LOG = logging.getLogger('alerta.plugins.victorops')

VICTOROPS_SERVICE_KEY = os.environ.get('VICTOROPS_SERVICE_KEY') or app.config['VICTOROPS_SERVICE_KEY']
VICTOROPS_EVENTS_URL = 'https://alert.victorops.com/integrations/generic/20131114/alert/%s/{routing_key}' % (
    VICTOROPS_SERVICE_KEY,
)
SERVICE_KEY_MATCHERS = os.environ.get('VICTOROPS_SERVICE_KEY_MATCHERS') or app.config.get('VICTOROPS_SERVICE_KEY_MATCHERS', [])
DASHBOARD_URL = os.environ.get('DASHBOARD_URL') or app.config.get('DASHBOARD_URL', '')
SEND_REPEAT_ALERTS = bool(os.environ.get('VICTOROPS_SEND_REPEAT_ALERTS')) or app.config.get('VICTOROPS_SEND_REPEAT_ALERTS', False)
ROUTING_KEY_ATTRIBUTE = os.environ.get('VICTOROPS_ROUTING_KEY_ATTRIBUTE') or app.config.get('VICTOROPS_ROUTING_KEY_ATTRIBUTE', "routing_key")

# info taked from https://help.victorops.com/knowledge-base/rest-endpoint-integration-guide/
# and https://docs.alerta.io/en/latest/api/alert.html?highlight=Alert#severity-table
ALERT_SEVERITY_MAP = {
    "security": "critical",
    "critical": "critical",
    "major": "critical",
    "minor": "warning",
    "warning": "warning",
    "informational": "info",
    "debug": "info",
    "trace": "",
    "indeterminate": "warning",
    "cleared": "recovery",
    "normal": "recovery",
    "ok": "recovery",
    "unknown": "warning",
}

# info taked from https://help.victorops.com/knowledge-base/rest-endpoint-integration-guide/
# and https://docs.alerta.io/en/latest/api/alert.html?highlight=Alert#status-table
ALERT_STATUS_MAP = {
    "open": None,
    "assign": "acknowledgement",
    "ack": "acknowledgement",
    "closed": None,
    "expired": None,
    "blackout": None,
    "shelved": None,
    "unknown": None,
}


class TriggerEvent(PluginBase):

    def victorops_service_key(self, resource):
        if not SERVICE_KEY_MATCHERS:
            LOG.debug('No matchers defined! Default service key: %s' % (VICTOROPS_SERVICE_KEY))
            return VICTOROPS_SERVICE_KEY

        for mapping in SERVICE_KEY_MATCHERS:
            if re.match(mapping['regex'], resource):    
                LOG.debug('Matched regex: %s, service key: %s' % (mapping['regex'], mapping['api_key']))
                return mapping['api_key']

        LOG.debug('No regex match! Default service key: %s' % (VICTOROPS_SERVICE_KEY))
        return VICTOROPS_SERVICE_KEY

    def pre_receive(self, alert):
        return alert

    def post_receive(self, alert):

        if alert.repeat and not SEND_REPEAT_ALERTS:
            return

        # set the routing key in the url from the alert attribute if present
        events_url = VICTOROPS_EVENTS_URL.format(routing_key=alert.attributes.get(ROUTING_KEY_ATTRIBUTE, ""))

        message = "%s: %s alert for %s - %s is %s" % (
            alert.environment, alert.severity.capitalize(),
            ','.join(alert.service), alert.resource, alert.event
        )

        payload = {
            "message_type": ALERT_SEVERITY_MAP[alert.severity],
            "entity_id": "/".join([alert.event, alert.resource]),
            "entity_display_name": message,
            "state_message": alert.text,
            "state_start_time": alert.create_time.strftime("%s"),
            "monitor_name": alert.origin,
            "monitoring_tool": alert.event_type,
        }

        LOG.debug('VictorOps payload: %s', payload)

        try:
            r = requests.post(events_url, json=payload, timeout=2)
        except Exception as e:
            raise RuntimeError("VictorOps connection error: %s" % e)

        LOG.debug('VictorOps response: %s - %s', r.status_code, r.text)

    def status_change(self, alert, status, text):
        message_type = ALERT_STATUS_MAP[status]
        if not message_type:
            return

        # set the routing key in the url from the alert attribute if present
        events_url = VICTOROPS_EVENTS_URL.format(routing_key=alert.attributes.get(ROUTING_KEY_ATTRIBUTE, ""))

        message = "%s: %s alert for %s - %s is %s" % (
            alert.environment, alert.severity.capitalize(),
            ','.join(alert.service), alert.resource, alert.event
        )

        payload = {
            "message_type": message_type,
            "entity_id": "/".join([alert.event, alert.resource]),
            "entity_display_name": message,
            "state_message": text,
            "state_start_time": alert.create_time.strftime("%s"),
            "monitor_name": alert.origin,
            "monitoring_tool": alert.event_type,
        }

        LOG.debug('VictorOps payload: %s', payload)

        try:
            r = requests.post(events_url, json=payload, timeout=2)
        except Exception as e:
            raise RuntimeError("VictorOps connection error: %s" % e)

        LOG.debug('VictorOps response: %s - %s', r.status_code, r.text)
