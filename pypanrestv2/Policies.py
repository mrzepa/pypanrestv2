from typing import Optional, Dict, Any, Tuple, Union, List, Protocol, Set, TypeVar
from . import ApplicationHelper
from . import Exceptions
import pycountry
import ipaddress
import builtins
import time
import re
from datetime import datetime
from icecream import ic
import sys
import xmltodict
import dns.resolver
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
import xml.etree.ElementTree as ET
from pypanrestv2.Base import Base, PAN, Panorama, Firewall
import pypanrestv2.Objects
logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Policy(Base, PAN):
    """
    Base class for all policies
    """
    valid_policies: List[str] = ['Security', 'NAT', 'QoS', 'PolicyBasedForwarding', 'Decryption',
                                 'TunnelInspection', 'ApplicationOverride', 'Authentication', 'DoS', 'SDWAN']

    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        Base.__init__(self, PANDevice, **kwargs)
        PAN.__init__(self, PANDevice.base_url, api_key=PANDevice.api_key)
        self.endpoint: str = 'Policies'
        self._pre_post: str = kwargs.get('pre_post', None)
        self.disabled: str = kwargs.get('disabled', 'no')
        self.group_tag: str = kwargs.get('group_tag')
        self.from_: Dict[str, List[str]] = kwargs.get('from_zone', {'member': []})
        self.to: Dict[str, List[str]] = kwargs.get('to', {'member': []})
        self.source: Dict[str, List[str]] = kwargs.get('source', {'member': []})
        self.source_user: Dict[str, List[str]] = kwargs.get('source_user', {'member': []})
        self.destination: Dict[str, List[str]] = kwargs.get('destination', {'member': []})
        self.service: Dict[str, List[str]] = kwargs.get('service', {'member': []})
        self.application: Dict[str, List[str]] = kwargs.get('application', {'member': []})
        self.source_hip: Dict[str, List[str]] = kwargs.get('source_hip', {'member': []})
        self.destination_hip: Dict[str, List[str]] = kwargs.get('destination_hip', {'member': []})
        self.category: Dict[str, List[str]] = kwargs.get('category', {'member': []})
        self.schedule: str = kwargs.get('schedule')
        self.negate_source: str = kwargs.get('negate_source', 'no')
        self.negate_destination: str = kwargs.get('negate_destination', 'no')
        self.target: Dict[Dict, Dict, Str] = kwargs.get('target')

    @property
    def target(self) -> Dict:
        return self._target

    @target.setter
    def target(self, value: Dict):
        if value:
            if not isinstance(self.PANDevice, Panorama):
                raise TypeError("Target attribute can only be set for Panorama devices.")

            if not isinstance(value, dict):
                raise ValueError("The target value must be a dictionary.")

            # Validate 'devices' key
            if 'devices' not in value or not isinstance(value['devices'], dict) or 'entry' not in value['devices']:
                raise ValueError("The 'devices' key must be a dictionary containing the 'entry' key.")

            for entry in value['devices']['entry']:
                if not isinstance(entry, dict) or '@name' not in entry:
                    raise ValueError("Each entry in 'devices' must be a dictionary with an '@name' key.")
                if 'vsys' in entry and not (isinstance(entry['vsys'], dict) and 'entry' in entry['vsys']):
                    raise ValueError("If 'vsys' is provided, it must be a dictionary containing the 'entry' key.")

            # Validate 'tags' key if provided
            if 'tags' in value:
                if not isinstance(value['tags'], dict) or 'member' not in value['tags'] or not isinstance(
                        value['tags']['member'], list):
                    raise ValueError("If 'tags' is provided, it must be a dictionary with a 'member' list.")
                if not all(isinstance(tag, str) for tag in value['tags']['member']):
                    raise ValueError("All members in the 'tags' list must be strings.")

            # Validate and set 'negate' key, default to 'no' if not provided
            negate = value.get('negate', 'no')
            if negate not in ['yes', 'no']:
                raise ValueError("The 'negate' key must be either 'yes' or 'no'.")

            # Set the target attribute if all validations pass
            self._target = {
                'devices': value['devices'],
                'tags': value.get('tags', {'member': []}),
                'negate': negate
            }
            self.entry.update({'target': self._target})

    @property
    def from_(self) -> Dict[str, List[str]]:
        return self._from_

    @from_.setter
    def from_(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'from_zone')
        self._from_ = value
        self.entry.update({'from': value})

    @property
    def to(self) -> Dict[str, List[str]]:
        return self._to

    @to.setter
    def to(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'to')
        self._to = value
        self.entry.update({'to': value})

    @property
    def source(self) -> Dict[str, List[str]]:
        return self._source

    @source.setter
    def source(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'source')
        self._source = value
        self.entry.update({'source': value})

    @property
    def source_user(self) -> Dict[str, List[str]]:
        return self._source_user

    @source_user.setter
    def source_user(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'source_user')
        self._source_user = value
        self.entry.update({'source-user': value})

    @property
    def destination(self) -> Dict[str, List[str]]:
        return self._destination

    @destination.setter
    def destination(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'destination')
        self._destination = value
        self.entry.update({'destination': value})

    @property
    def service(self) -> Dict[str, List[str]]:
        return self._service

    @service.setter
    def service(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'service')
        self._service = value
        self.entry.update({'service': value})

    @property
    def application(self) -> Dict[str, List[str]]:
        return self._application

    @application.setter
    def application(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'application')
        self._application = value
        self.entry.update({'application': value})

    @property
    def source_hip(self) -> Dict[str, List[str]]:
        return self._source_hip

    @source_hip.setter
    def source_hip(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'source_hip')
        self._source_hip = value
        self.entry.update({'source-hip': value})

    @property
    def destination_hip(self) -> Dict[str, List[str]]:
        return self._destination_hip

    @destination_hip.setter
    def destination_hip(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'destination_hip')
        self._destination_hip = value
        self.entry.update({'destination-hip': value})

    @property
    def schedule(self) -> str:
        return self._schedule

    @schedule.setter
    def schedule(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("Schedule must be a string.")
            self._schedule = value
            self.entry.update({'schedule': value})

    @property
    def negate_source(self) -> str:
        return self._negate_source

    @negate_source.setter
    def negate_source(self, value: str = 'no') -> None:
        if value not in ['yes', 'no']:
            raise ValueError("negate_source must be either 'yes' or 'no'.")
        self._negate_source = value
        self.entry.update({'negate-source': value})

    @property
    def negate_destination(self) -> str:
        return self._negate_destination

    @negate_destination.setter
    def negate_destination(self, value: str = 'no') -> None:
        if value not in ['yes', 'no']:
            raise ValueError("negate_destination must be either 'yes' or 'no'.")
        self._negate_destination = value
        self.entry.update({'negate-destination': value})

    @property
    def category(self) -> str:
        return self._category

    @category.setter
    def category(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'category')
        self._category = value
        self.entry.update({'category': value})

    @property
    def disabled(self) -> str:
        return self._disabled

    @disabled.setter
    def disabled(self, value: str = 'no') -> None:
        if value not in ['yes', 'no']:
            raise ValueError("disabled must be either 'yes' or 'no'.")
        self._disabled = value
        self.entry.update({'disabled': value})

    @property
    def group_tag(self) -> str:
        return self._group_tag

    @group_tag.setter
    def group_tag(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("group_tag must be a string.")
            if len(value) > 127:
                raise ValueError("group_tag cannot exceed 127 characters in length.")
            self._group_tag = value
            self.entry.update({'group-tag': value})

    @property
    def pre_post(self) -> str:
        return self._pre_post

    @pre_post.setter
    def pre_post(self, value: str) -> None:
        if isinstance(self.PANDevice, Panorama):
            formatted_value = value.capitalize()  # This will make the first letter uppercase and the rest lowercase

            if formatted_value not in ['Pre', 'Post']:
                raise ValueError("pre_post must be either 'Pre' or 'Post'.")

            self._pre_post = formatted_value
        else:
            self._pre_post = None

class SecurityRules(Policy):
    VALID_ACTIONS = ["deny", "allow", "drop", "reset-client", "reset-server", "reset-both"]

    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)
        self.action: str = kwargs.get('action', 'allow')
        self.icmp_unreachable: str = kwargs.get('icmp_unreachable', 'no')
        self.disable_inspect: str = kwargs.get('disable_inspect', 'no')
        self.rule_type: str = kwargs.get('rule_type', 'universal')
        self.option: dict = kwargs.get('option', {'disable-server-response-inspection': 'no'})
        self.log_setting: str = kwargs.get('log_setting', '')
        self.log_start: str = kwargs.get('log_start', 'no')
        self.log_end: str = kwargs.get('log_end', 'yes')
        self.profile_setting: dict = kwargs.get('profile_setting', {})
        self.qos: dict = kwargs.get('qos')

    @property
    def action(self) -> str:
        return self._action

    @action.setter
    def action(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Action must be a string.")

        if value not in self.VALID_ACTIONS:
            raise ValueError(f"Invalid action: {value}. Valid actions are: {', '.join(self.VALID_ACTIONS)}")

        self._action = value
        self.entry.update({'action': value})

    @property
    def icmp_unreachable(self) -> str:
        return self._icmp_unreachable

    @icmp_unreachable.setter
    def icmp_unreachable(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("icmp_unreachable must be a string.")

        if value.lower() not in ['yes', 'no']:
            raise ValueError("icmp_unreachable must be either 'yes' or 'no'.")

        self._icmp_unreachable = value.lower()
        self.entry.update({'icmp-unreachable': value})

    @property
    def disable_inspect(self) -> str:
        return self._disable_inspect

    @disable_inspect.setter
    def disable_inspect(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("disable_inspect must be a string.")

        value_lower = value.lower()
        if value_lower not in ['yes', 'no']:
            raise ValueError("disable_inspect must be either 'yes' or 'no'.")

        self._disable_inspect = value_lower
        self.entry.update({'disable-inspect':value})

    @property
    def rule_type(self) -> str:
        return self._rule_type

    @rule_type.setter
    def rule_type(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("rule_type must be a string.")

        value_lower = value.lower()
        valid_types = ["universal", "intrazone", "interzone"]
        if value_lower not in valid_types:
            raise ValueError(f"rule_type must be one of: {', '.join(valid_types)}")

        self._rule_type = value_lower
        self.entry.update({'rule-type': value_lower})

    @property
    def option(self) -> dict:
        return self._option

    @option.setter
    def option(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("option must be a dictionary.")

        # Defaulting to 'no' if not specified
        dsri = value.get('disable-server-response-inspection', 'no').lower()

        if dsri not in ['yes', 'no']:
            raise ValueError("disable-server-response-inspection must be 'yes' or 'no'.")

        # Update the dictionary with the validated value
        value['disable-server-response-inspection'] = dsri

        self._option = value
        self.entry.update({'option': value})

    @property
    def log_setting(self) -> str:
        return self._log_setting

    @log_setting.setter
    def log_setting(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("log_setting must be a string.")

        if len(value) > 63:
            raise ValueError("log_setting cannot exceed 63 characters.")

        self._log_setting = value
        self.entry.update({'log-setting': value})

    @property
    def log_start(self) -> str:
        return self._log_start

    @log_start.setter
    def log_start(self, value: str) -> None:
        if value not in ['yes', 'no']:
            raise ValueError("log_start must be 'yes' or 'no'.")

        self._log_start = value
        # Updating the entry dictionary with key 'log-start'
        self.entry.update({'log-start': value})

    @property
    def log_end(self) -> str:
        return self._log_end

    @log_end.setter
    def log_end(self, value: str) -> None:
        if value not in ['yes', 'no']:
            raise ValueError("log_end must be either 'yes' or 'no'.")
        self._log_end = value
        # Updating the entry dictionary with key 'log-end'
        self.entry.update({'log-end': value})

    @property
    def profile_setting(self) -> dict:
        return self._profile_setting

    @profile_setting.setter
    def profile_setting(self, value: dict) -> None:
        if value:
            if not isinstance(value, dict):
                raise TypeError("profile_setting must be a dictionary.")

            if 'profiles' in value:
                self._validate_profiles(value['profiles'])
            elif 'group' in value:
                self._validate_group(value['group'])
            else:
                raise ValueError("profile_setting must have either 'profiles' or 'group' as keys.")

            self._profile_setting = value
            self.entry.update({'profile-setting': value})

    @staticmethod
    def _validate_profiles(profiles: dict) -> None:
        valid_profile_keys = ['url-filtering', 'data-filtering', 'file-blocking',
                              'wildfire-analysis', 'virus', 'spyware', 'vulnerability']
        for key, profile in profiles.items():
            if key not in valid_profile_keys:
                raise ValueError(f"Invalid profile key: {key}.")
            if not isinstance(profile, dict) or 'member' not in profile or not isinstance(profile['member'], list):
                raise ValueError(
                    f"Each profile in profiles must be a dictionary with a 'member' list. Issue found in {key}.")
            if not all(isinstance(item, str) for item in profile['member']):
                raise ValueError(f"All items in the 'member' list of {key} must be strings.")

    @staticmethod
    def _validate_group(group: dict) -> None:
        if not isinstance(group, dict) or 'member' not in group or not isinstance(group['member'], list):
            raise ValueError("group must be a dictionary with a 'member' list.")
        if not all(isinstance(item, str) for item in group['member']):
            raise ValueError("All items in the 'member' list of group must be strings.")

    @property
    def qos(self) -> dict:
        return self._qos

    @qos.setter
    def qos(self, value: dict) -> None:
        if value:
            if not isinstance(value, dict):
                raise TypeError("qos must be a dictionary.")

            if 'marking' not in value or not isinstance(value['marking'], dict):
                raise ValueError("qos must contain a 'marking' dictionary.")

            marking = value['marking']
            valid_keys = ['ip-dscp', 'ip-precedence', 'follow-c2s-flow']
            if len(marking) != 1 or not set(marking.keys()).issubset(set(valid_keys)):
                raise ValueError(f"marking must contain exactly one of the following keys: {', '.join(valid_keys)}")

            if 'ip-dscp' in marking and not isinstance(marking['ip-dscp'], str):
                raise ValueError("The value for 'ip-dscp' must be a string.")
            if 'ip-precedence' in marking and not isinstance(marking['ip-precedence'], str):
                raise ValueError("The value for 'ip-precedence' must be a string.")
            if 'follow-c2s-flow' in marking and marking['follow-c2s-flow'] != {}:
                raise ValueError("The value for 'follow-c2s-flow' must be an empty dictionary.")

            self._qos = value
            self.entry.update({'qos': value})

class NatRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)
        self.destination_translation: dict = kwargs.get('destination_translation')
        self.dynamic_destination_translation: dict = kwargs.get('dynamic_destination_translation')
        self.active_active_device_binding: str = kwargs.get('active_active_device_binding')
        self.service: str = kwargs.get('service', 'any')
        self.nat_type: str = kwargs.get('nat_type', 'ipv4')
        self.to_interface: str = kwargs.get('to_interface', 'any')
        self.source_translation: dict = kwargs.get('source_translation')

    @staticmethod
    def _validate_translation(value: Dict, keys: List[str]) -> None:
        for key in keys:
            if key == 'translated-address' and key not in value:
                raise ValueError(f"'{key}' is required in the translation dictionary.")
            if key == 'translated-port' and key in value:
                if not (1 <= value['translated-port'] <= 65535):
                    raise ValueError("translated-port must be between 1 and 65535.")

    @property
    def destination_translation(self) -> Optional[Dict]:
        return self._destination_translation

    @destination_translation.setter
    def destination_translation(self, value: Dict) -> None:
        if value:
            if self._dynamic_destination_translation is not None:
                raise ValueError("Cannot set destination_translation when dynamic_destination_translation is already set.")
            if not isinstance(value, dict):
                raise TypeError("destination_translation must be a dictionary.")

            # Validate the keys and their values
            self._validate_translation(value, ['translated-address', 'translated-port'])

            if 'dns-rewrite' in value:
                if 'direction' not in value['dns-rewrite'] or value['dns-rewrite']['direction'] not in ['reverse',
                                                                                                        'forward']:
                    raise ValueError("Invalid 'direction' value in 'dns-rewrite'.")

            self._destination_translation = value
            self.entry.update({'destination-translation': value})

    @property
    def dynamic_destination_translation(self) -> Optional[Dict]:
        return self._dynamic_destination_translation

    @dynamic_destination_translation.setter
    def dynamic_destination_translation(self, value: Dict) -> None:
        if value:
            if self._destination_translation is not None:
                raise ValueError("Cannot set dynamic_destination_translation when destination_translation is already set.")
            if not isinstance(value, dict):
                raise TypeError("dynamic_destination_translation must be a dictionary.")

            # Validate the keys and their values
            self._validate_translation(value, ['translated-address', 'translated-port'])

            if 'distribution' in value and value['distribution'] not in ["round-robin", "source-ip-hash", "ip-modulo",
                                                                         "ip-hash", "least-sessions"]:
                raise ValueError("Invalid 'distribution' value.")

            self._dynamic_destination_translation = value
            self.entry.update({'dynamic-destination-translation': value})

    @property
    def active_active_device_binding(self) -> str:
        return self._active_active_device_binding

    @active_active_device_binding.setter
    def active_active_device_binding(self, value: str) -> None:
        if value:
            if value not in ["primary", "both", "0", "1"]:
                raise ValueError("active_active_device_binding must be one of 'primary', 'both', '0', or '1'.")
            self._active_active_device_binding = value
            self.entry.update({'active-active-device-binding': value})

    @property
    def service(self) -> str:
        return self._service

    @service.setter
    def service(self, value: str) -> None:
        if value == 'any':
            self._service = 'any'
        else:
            check_service = Services(self.PANDevice, name=value, location=self.location, device_group=self.device_group)
            if check_service.get(ANYLOCATION=True, IsSearch=True):
                self._service = value
            else:
                raise ValueError(f"The service '{value}' does not exist.")

        # Update the entry dictionary
        self.entry.update({'service': self._service})

    @property
    def nat_type(self) -> str:
        return self._nat_type

    @nat_type.setter
    def nat_type(self, value: str) -> None:
        valid_types = ["ipv4", "nat64", "nptv6"]
        if value not in valid_types:
            raise ValueError(f"Invalid nat_type: {value}. Must be one of: {', '.join(valid_types)}")

        self._nat_type = value
        # Update the entry dictionary to reflect the change
        self.entry.update({'nat-type': self._nat_type})

    @property
    def to_interface(self) -> str:
        return self._to_interface

    @to_interface.setter
    def to_interface(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("to_interface must be a string.")

        self._to_interface = value
        # Update the entry dictionary to reflect the change
        self.entry.update({'to-interface': self._to_interface})

    @property
    def source_translation(self) -> dict:
        return self._source_translation

    @source_translation.setter
    def source_translation(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("source_translation must be a dictionary.")

        # Validate the keys of the main dict
        valid_keys = ['dynamic-ip-and-port', 'dynamic-ip', 'static-ip']
        if all(key not in valid_keys for key in value.keys()):
            raise ValueError(f"Invalid key in source_translation. Must be one of: {', '.join(valid_keys)}")

        keys_present = [key for key in valid_keys if key in value]
        if len(keys_present) > 1:
            raise ValueError("Only one of 'dynamic-ip-and-port', 'dynamic-ip', or 'static-ip' can be set at a time.")

        if 'dynamic-ip-and-port' in value:
            self._validate_dynamic_ip_and_port(value['dynamic-ip-and-port'])
        elif 'dynamic-ip' in value:
            self._validate_dynamic_ip(value['dynamic-ip'])
        elif 'static-ip' in value:
            self._validate_static_ip(value['static-ip'])

        # Update the entry dictionary to reflect the change
        self._source_translation = value
        self.entry.update({'source-translation': self._source_translation})

    def _validate_dynamic_ip_and_port(self, value: dict) -> None:
        valid_sub_keys = ['translated-addresses', 'interface-address']
        if all(sub_key not in valid_sub_keys for sub_key in value.keys()):
            raise ValueError(f"Invalid key in dynamic-ip-and-port. Must be one of: {', '.join(valid_sub_keys)}")

        # Validate 'translated-addresses'
        if 'translated-addresses' in value:
            if not isinstance(value['translated-addresses'], dict) or 'member' not in value['translated-addresses']:
                raise ValueError("translated-addresses must be a dict with a 'member' key.")
            if not all(isinstance(item, str) for item in value['translated-addresses']['member']):
                raise ValueError("All items in 'member' list of translated-addresses must be strings.")

        # Validate 'interface-address'
        if 'interface-address' in value:
            self._validate_interface_address(value['interface-address'])

    def _validate_interface_address(self, value: dict) -> None:
        valid_ip_keys = ['ip', 'floating-ip']
        if all(ip_key not in valid_ip_keys for ip_key in value.keys()):
            raise ValueError(f"Invalid key in interface-address. Must be one of: {', '.join(valid_ip_keys)}")

        # Validate 'ip' key
        if 'ip' in value:
            self._validate_ip_or_floating_ip(value['ip'], 'ip')

        # Validate 'floating-ip' key
        if 'floating-ip' in value:
            self._validate_ip_or_floating_ip(value['floating-ip'], 'floating-ip')

    @staticmethod
    def _validate_ip_or_floating_ip(value: dict, key: str) -> None:
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be a dictionary.")

        # Interface is required
        if 'interface' not in value or not isinstance(value['interface'], str) or len(value['interface']) > 31:
            raise ValueError(f"interface in {key} is required and must be a string up to 31 characters long.")

        # IP or floating-ip is optional
        if key in value and (not isinstance(value[key], str) or not value[key]):
            raise ValueError(f"{key} must be a non-empty string if provided.")

    def _validate_dynamic_ip(self, value: dict) -> None:
        required_keys = ['translated-addresses']
        for key in required_keys:
            if key not in value:
                raise ValueError(f"'{key}' is required in 'dynamic-ip'.")

        # Validate 'translated-addresses' in 'dynamic-ip'
        if 'translated-addresses' in value:
            if not isinstance(value['translated-addresses'], dict) or 'member' not in value['translated-addresses']:
                raise ValueError("'translated-addresses' must be a dict with a 'member' key.")
            if not all(isinstance(item, str) for item in value['translated-addresses']['member']):
                raise ValueError("All items in 'member' list of 'translated-addresses' must be strings.")

        # Validate 'fallback' in 'dynamic-ip'
        if 'fallback' in value:
            if not isinstance(value['fallback'], dict):
                raise ValueError("'fallback' in 'dynamic-ip' must be a dictionary.")
            for fallback_key, fallback_val in value['fallback'].items():
                if fallback_key not in ['translated-addresses', 'interface-address']:
                    raise ValueError(f"Invalid key in 'fallback': {fallback_key}")
                if fallback_key == 'translated-addresses':
                    self._validate_translated_addresses(fallback_val)
                elif fallback_key == 'interface-address':
                    self._validate_interface_address(fallback_val)

    @staticmethod
    def _validate_translated_addresses(value: dict) -> None:
        if not isinstance(value, dict) or 'member' not in value:
            raise ValueError("'translated-addresses' must be a dict with a 'member' key.")
        if not all(isinstance(item, str) for item in value['member']):
            raise ValueError("All items in 'member' list of 'translated-addresses' must be strings.")

    def _validate_static_ip(self, value: dict) -> None:
        if 'translated-address' not in value:
            raise ValueError("translated-address is required in static-ip.")

        # Validate 'translated-address'
        if not isinstance(value['translated-address'], str):
            raise ValueError("translated-address in static-ip must be a string.")

        # Ensure 'bi-directional' key exists, default to 'no'
        bi_directional = value.get('bi-directional', 'no')
        # Validate 'bi-directional'
        if bi_directional not in self.yes_no:
            raise ValueError("bi-directional in static-ip must be 'yes' or 'no'.")

        # Set the validated value back in case it was missing
        value['bi-directional'] = bi_directional

class QoSRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class PolicyBasedForwardingRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class DecryptionRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class NetworkPacketBrokerRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class TunnelInspectionRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class ApplicationOverrideRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class AuthenticationRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class DoSRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)

class SDWANRules(Policy):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=63, max_description_length=1024, **kwargs)