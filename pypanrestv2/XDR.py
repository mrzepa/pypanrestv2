import requests
from datetime import datetime, timezone
import secrets
import string
import hashlib
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging

logger = logging.getLogger(__name__)

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Cortex:
    """
    This class is used to establish a connection with a Cortex XDR tenant.
    It generates the necessary headers for authentication.
    """
    def __init__(self, api_key_id, api_key, base_url, api_version='/public_api/v1'):
        self.api_key_id = api_key_id
        self.api_key = api_key
        self.base_url = base_url
        self.api_version = api_version

    def generate_header(self):
        """
        Generates the authentication header required for Cortex XDR API requests.
        """
        nonce = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
        auth_key = f"{self.api_key}{nonce}{timestamp}".encode("utf-8")
        api_key_hash = hashlib.sha256(auth_key).hexdigest()

        return {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self.api_key_id),
            "Authorization": api_key_hash
        }

class XDR_Base:
    """
    Base class for XDR interactions. This class initializes a connection session
    and defines basic GET method functionality for the derived classes.
    """
    def __init__(self, cortex_instance, api_name='', **kwargs):
        self.cortex_instance = cortex_instance
        self.api_name = api_name
        self.session = requests.Session()
        self.call_name = kwargs.get('call_name')
        self.params = kwargs.get('params')

    def get(self):
        """
        Generic GET request to retrieve data from Cortex XDR API.
        """
        url = f"{self.cortex_instance.base_url}{self.cortex_instance.api_version}{self.api_name}{self.call_name}"
        response = self.session.post(url, headers=self.cortex_instance.generate_header(), json=self.params)
        return json.loads(response.text) if response.status_code == 200 else response.status_code

    def status(self):
        self.api_name = '/healthcheck/'
        self.call_name = ''
        return self.get().get('status')

    def info(self):
        self.api_name = '/system/'
        self.call_name = 'get_tenant_info'
        self.params = {'request_data': {}}

        return self.get()
class Incidents(XDR_Base):
    """
    Class to handle incidents-related interactions with Cortex XDR.
    """
    def __init__(self, cortex_instance, **kwargs):
        super().__init__(cortex_instance, '/incidents', **kwargs)

        self.call_name = ''
        self.params = kwargs.get('params') or {}
        self.filter = []
        self.ALERTFILTER = []
        self.SEARCH_FROM = kwargs.get('SEARCH_FROM') or 0
        self.SEARCH_TO = kwargs.get('SEARCH_TO') or 100
        self.SORT_FIELD = kwargs.get('SORT_FIELD')
        self.KEYWORD = kwargs.get('KEYWORD') or 'asc'

    def IncidentFilterBuilder(self, FIELD, OPERATOR, VALUELIST):
        Valid_FilterFields = ['modification_time', 'creation_time', 'incident_id_list', 'description', 'alert_sources',
                              'status', 'starred']
        Valid_FilterOperators = ['in', 'gte', 'lte', 'eq', 'neq', 'contains']
        Valid_status = ['new', 'under_investigation', 'resolved_true_positive', 'resolved_known_issue',
                        'resolved_duplicate_incident', 'resolved_false_positive', 'resolved_auto_resolve']

        if FIELD not in Valid_FilterFields:
            raise ValueError(f'{FIELD} is not a valid Field value. Please use one of {Valid_FilterFields}')

        if OPERATOR not in Valid_FilterOperators:
            raise ValueError(f'{OPERATOR} is not a valid Operator value. Please use one of {Valid_FilterOperators}')

        if OPERATOR == 'in':
            if FIELD in ['incident_id_list', 'alert_sources', 'description']:
                if not isinstance(VALUELIST, list):
                    raise ValueError(f'{VALUELIST} must be a list')
        elif OPERATOR == 'contains':
            if FIELD not in ['description']:
                raise ValueError(f'When using Operator {OPERATOR}, the only valid keywords are [description].')
        elif OPERATOR in ['gte', 'lte']:
            if FIELD not in ['modification_time', 'creation_time']:
                raise ValueError(
                    f'When using Operator {OPERATOR}, the only valid keywords are [modification_time, creation_time].')
        elif OPERATOR in ['eq', 'neq']:
            if FIELD not in ['status']:
                raise ValueError(f'When using Operator {OPERATOR}, the only valid keywords are [status].')
            for i in VALUELIST:
                if i not in Valid_status:
                    raise ValueError(f'Status must be one of {Valid_status}.')

        self.filter.append({'field': FIELD, 'operator': OPERATOR, 'value': VALUELIST})

    def AlertFilterBuilder(self, FIELD, OPERATOR, VALUELIST):
        Valid_FilterFields = ['alert_id_list', 'alert_source', 'severity', 'creation_time', 'server_creation_time']
        Valid_FilterOperators = ['in', 'gte', 'lte']
        Valid_severity = ['low', 'medium', 'high', 'critical', 'informational']

        if FIELD not in Valid_FilterFields:
            raise ValueError(f'{FIELD} is not a valid Field value. Please use one of {Valid_FilterFields}')

        if OPERATOR not in Valid_FilterOperators:
            raise ValueError(f'{OPERATOR} is not a valid Operator value. Please use one of {Valid_FilterOperators}')

        if OPERATOR == 'in':
            if FIELD == 'alert_id':
                if not isinstance(FIELD, list):
                    raise ValueError(f'{FIELD} must be a list')
            elif FIELD == 'severity':
                for i in VALUELIST:
                    if i not in Valid_severity:
                        raise ValueError(f'{FIELD} must be one of {Valid_severity} but {i} was provided.')
        elif OPERATOR in ['gte', 'lte']:
            if FIELD not in ['creation_time']:
                raise ValueError(f'When using Operator {OPERATOR}, the only valid keywords are [creation_time].')
        self.ALERTFILTER.append({'field': FIELD, 'operator': OPERATOR, 'value': VALUELIST})

    def GetIncidents(self):
        self.api_name = '/incidents'
        self.call_name = '/get_incidents/'
        self.SORT_FIELD = 'modification_time'
        self.params = {
            'request_data': {
                'search_from': self.SEARCH_FROM,
                'search_to': self.SEARCH_TO,
                'sort': {
                    'field': self.SORT_FIELD,
                    'keyword': self.KEYWORD
                },
                'filters': self.filter
            }
        }
        return self.get()

    def GetAlerts(self):
        self.api_name = '/alerts'
        self.call_name = '/get_alerts_multi_events/'
        self.SORT_FIELD = 'severity'
        self.params = {
            'request_data': {
                'search_from': self.SEARCH_FROM,
                'search_to': self.SEARCH_TO,
                'sort': {
                    'field': self.SORT_FIELD,
                    'keyword': self.KEYWORD
                },
                'filters': self.ALERTFILTER
            }
        }
        return self.get()

class Endpoint(XDR_Base):
    """
    Class to handle endpoint-related interactions with Cortex XDR.
    """
    def __init__(self, cortex_instance, **kwargs):
        super().__init__(cortex_instance, '/endpoints', **kwargs)

        self.call_name = ''
        self.params = kwargs.get('params') or {}
        self.filter = []
        self.search_from = kwargs.get('search_from') or 0
        self.search_to = kwargs.get('search_to') or 100
        self.sort_field = kwargs.get('sort_field') or 'last_seen'
        self.keyword = kwargs.get('keyword') or 'asc'

    def get_all(self):
        self.call_name = '/get_endpoints'
        return self.get()

    def filter_builder(self, field, operator, valuelist):
        valid_filter_fields = ['endpoint_id_list', 'endpoint_status', 'dist_name', 'first_seen', 'last_seen', 'ip_list',
                               'group_name', 'platform', 'alias', 'isolate', 'hostname']
        valid_filter_operators = ['in', 'gte', 'lte']

        valid_endpoint_status = ['connected', 'disconnected', 'lost', 'uninstalled']
        valid_platform = ['windows', 'linux', 'macos', 'android']
        valid_isolate = ['isolated', 'unisolated']
        valid_scan_status = ['none', 'pending', 'in_progress', 'canceled', 'aborted', 'pending_cancellation',
                             'success', 'error']

        if field not in valid_filter_fields:
            raise ValueError(f'{field} is not a valid Field value. Please use one of {valid_filter_fields}')

        if operator not in valid_filter_operators:
            raise ValueError(f'{operator} is not a valid Operator value. Please use one of {valid_filter_operators}')

        if operator == 'in':
            if field in ['endpoint_id_list', 'dist_name', 'group_name', 'alias', 'hostname', 'username']:
                for i in valuelist:
                    if not isinstance(i, str):
                        raise ValueError(f'{i} must be a string')

            elif field == 'endpoint_status':
                for i in valuelist:
                    if i not in valid_endpoint_status:
                        raise ValueError(f'{i} must be one of {valid_endpoint_status}')
            elif field == 'ip_list':
                for i in valuelist:
                    if not isinstance(i, str):
                        # TODO - validate the string is an IP address
                        raise ValueError(f'{i} must be a string')
            elif field == 'platform':
                for i in valuelist:
                    if i not in valid_platform:
                        raise ValueError(f'{i} must be one of {valid_platform}')
            elif field == 'isolate':
                for i in valuelist:
                    if i not in valid_isolate:
                        raise ValueError(f'{i} must be one of {valid_isolate}')
            elif field == 'scan_status':
                for i in valuelist:
                    if i not in valid_scan_status:
                        raise ValueError(f'{i} must be one of {valid_scan_status}')
        else:
            if field not in ['first_seen', 'last_seen']:
                raise ValueError(
                    f'When using Operator {operator}, the only valid keywords are [first_seen, last_seen].')

        self.filter.append({'field': field, 'operator': operator, 'value': valuelist})

    def get_endpoint(self):
        self.call_name = '/get_endpoint'
        self.params = {
            'request_data': {
                'search_from': self.search_from,
                'search_to': self.search_to,
                'sort': {
                    'field': self.sort_field,
                    'keyword': self.keyword
                },
                'filters': self.filter
            }
        }
        return self.get()

    def get_violations(self):
        self.api_name = '/device_control'
        self.call_name = '/get_violations'
        self.params = {
            'request_data': {
                'search_from': self.search_from,
                'search_to': self.search_to,
                'sort': {
                    'field': self.sort_field,
                    'keyword': self.keyword
                },
                'filters': self.filter
            }
        }
        return self.get()

def raw_date(date, format):
    """
    Taka a date that has a suffix of th, st or rd on a number and remove it.
    :param date:
    :return: The date in unixtime
    """
    BadDateList = date.split(' ')
    newDate = []
    for i in BadDateList:
        if i.endswith('th'):
            newDate.append(i.strip('th'))
        elif i.endswith('st'):
            newDate.append(i.strip('st'))
        elif i.endswith('rd'):
            newDate.append(i.strip('rd'))
        else:
            newDate.append(i)
    GoodDate = datetime.strptime(' '.join(newDate), format)
    return int(GoodDate.timestamp()) * 1000
