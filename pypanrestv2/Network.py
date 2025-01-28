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

class Network(Base, PAN):
    allowed_name_pattern = re.compile(r"[0-9a-zA-Z._-]+", re.IGNORECASE)

    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        self.PANDevice = PANDevice
        self.PANDevice.valid_location.extend(['template', 'template-stack'])
        Base.__init__(self, PANDevice,  **kwargs)
        PAN.__init__(self, PANDevice.base_url, api_key=PANDevice.api_key)
        self.endpoint = 'Network'

    def _build_params(self) -> Dict[str, str]:
        """
        Builds the parameter dictionary for the API request based on the object's state.

        Returns:
            Dict[str, str]: The parameters for the API request.
        """
        params = {'location': self.location} if self.location else {}
        if self.name:
            params['name'] = self.name
        if self.location == 'template':
            params.update({self.location: self.template})
        if self.location == 'template-stack':
            params.update({self.location: self.template_stack})
        if self.location == 'vsys':
            params.update({self.location: self.vsys})
        if type(self).__name__ == 'Zones' and hasattr(self, 'vsys'):
            params['vsys'] = self.vsys

        return params

    def _update_entry_with_address(self, address: str) -> None:
        if 'ip' not in self.entry:
            self.entry['ip'] = {'entry': []}
        self.entry['ip']['entry'].append({'@name': address})

    def _validate_and_append_address(self, address: str) -> None:
        try:
            ipaddress.IPv4Interface(address)
            self._ip_address.append(address)
            self._update_entry_with_address(address)
        except AddressValueError:
            if address.startswith('$'):
                self._ip_address.append(address)
                self._update_entry_with_address(address)
            else:
                if am_i_an_address_object.refresh():
                    self._ip_address.append(am_i_an_address_object.value)
                    self._update_entry_with_address(am_i_an_address_object.value)
                else:
                    raise AddressValueError(f"{address} is not a valid IP address, variable, or address object.")

    def set_interface_addresses(self, value: Union[str, List[str]]) -> None:
        """
        Set interface addresses with validation for IP addresses, variables, or address objects.
        """
        if isinstance(value, str):
            self._validate_and_append_address(value)
        elif isinstance(value, list):
            for addr in value:
                self._validate_and_append_address(addr)
        else:
            raise TypeError("Value must be a string or a list of strings.")

    @staticmethod
    def _validate_interface_address(ip: str) -> bool:
        # If the IP address starts with '$', it's considered a valid Palo Alto variable
        if ip.startswith('$'):
            return True

        # Validate the IP address
        try:
            ipaddress.ip_interface(ip)
            return True
        except ValueError:
            try:
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                return False

    @staticmethod
    def _validate_ip_address(ip: str) -> bool:
        # If the IP address starts with '$', it's considered a valid Palo Alto variable
        if ip.startswith('$'):
            return True

        # Validate the IP address
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _validate_interface_address(ip: str) -> bool:
        # If the IP address starts with '$', it's considered a valid Palo Alto variable
        if ip.startswith('$'):
            return True

        # Validate the IP address
        try:
            ipaddress.ip_interface(ip)
            return True
        except ValueError:
            return False
    @staticmethod
    def _validate_subnet_mask(mask):
        # If the IP address starts with '$', it's considered a valid Palo Alto variable
        if ip.startswith('$'):
            return True
        try:
            # Convert the subnet mask to an IP address to check its validity
            ipaddress.ip_address(mask)
            return True
        except ValueError:
            return False
class Zones(Network):
    valid_network = ['tap', 'virtual-wire', 'layer2', 'layer3', 'tunnel', 'external']

    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)
        self.enable_user_identification: str = kwargs.get('enable_user_identification', 'no')
        self.enable_device_identification: str = kwargs.get('enable_device_identification', 'no')
        self.network: dict = kwargs.get('network')
        self.user_acl: dict = kwargs.get('user_acl')
        self.device_acl: dict = kwargs.get('device_acl')

    @property
    def network(self):
        return self._network

    @network.setter
    def network(self, value: dict):
        if value:
            if not isinstance(value, dict):
                raise ValueError("Network must be a dictionary.")

            required_keys = ['zone-protection-profile', 'enable-packet-buffer-protection', 'log-setting']
            if not all(key in value for key in required_keys):
                raise KeyError(f"Network dictionary must contain the keys: {', '.join(required_keys)}")

            if value.get('enable-packet-buffer-protection', 'yes') not in self.yes_no:
                raise ValueError("enable-packet-buffer-protection must be 'yes' or 'no'")

            if len(value.get('log-setting', '')) > 63:
                raise ValueError("log-setting value must be 63 characters or fewer")

            network_keys = [key for key in value.keys() if key in self.valid_network]
            if len(network_keys) != 1:
                raise ValueError("Network dictionary must contain exactly one key from valid_network")

            network_key = network_keys[0]
            if network_key != 'tunnel' and not isinstance(value[network_key].get('member', []), list):
                raise ValueError(
                    f"The value for '{network_key}' must be a dictionary with a 'member' key containing a list of strings.")
            elif network_key == 'tunnel' and value[network_key]:
                raise ValueError("'tunnel' key must be associated with an empty dictionary")

            self._network = value
            self.entry.update({'network': value})

    @property
    def enable_user_identification(self):
        return self._enable_user_identification

    @enable_user_identification.setter
    def enable_user_identification(self, value: str):
        if value not in self.yes_no:
            raise ValueError("enable_user_identification must be 'yes' or 'no'")
        self._enable_user_identification = value
        self.entry.update({'enable-user-identification': value})

    @property
    def enable_device_identification(self):
        return self._enable_device_identification

    @enable_device_identification.setter
    def enable_device_identification(self, value: str):
        if value not in self.yes_no:
            raise ValueError("enable_device_identification must be 'yes' or 'no'")
        self._enable_device_identification = value
        self.entry.update({'enable-device-identification': value})

    @property
    def user_acl(self):
        return self._user_acl

    @user_acl.setter
    def user_acl(self, value: dict):
        if value:
            self._validate_acl_structure(value, 'user_acl')
            self._user_acl = value
            self.entry.update({'user-acl': value})

    @property
    def device_acl(self):
        return self._device_acl

    @device_acl.setter
    def device_acl(self, value: dict):
        if value:
            self._validate_acl_structure(value, 'device_acl')
            self._device_acl = value
            self.entry.update({'device-acl': value})

    @staticmethod
    def _validate_acl_structure(acl_dict: dict, acl_type: str):
        if not isinstance(acl_dict, dict) or 'include-list' not in acl_dict or 'exclude-list' not in acl_dict:
            raise ValueError(f"{acl_type} must be a dictionary with 'include-list' and 'exclude-list' keys.")

        for key in ['include-list', 'exclude-list']:
            if key in acl_dict:
                if not isinstance(acl_dict[key], dict) or 'member' not in acl_dict[key]:
                    raise ValueError(f"'{key}' in {acl_type} must be a dictionary with a 'member' key.")
                if not isinstance(acl_dict[key]['member'], list):
                    raise ValueError(f"'member' in '{key}' of {acl_type} must be a list.")
                if not all(isinstance(item, str) for item in acl_dict[key]['member']):
                    raise ValueError(f"All items in 'member' of '{key}' in {acl_type} must be strings.")

                # Pop the key if the member list is empty
                if not acl_dict[key]['member']:
                    acl_dict.pop(key)

class DHCPServers(Network):
    """
    Special note about the name attribute. For DHCP servers, the name is the interface the DHCP server is attached too.
    """
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)
        self.name: str = kwargs.get('name')
        self.probe_ip: str = kwargs.get('probe_ip', 'no')
        self.option: dict = kwargs.get('option')
        self.ip_pool: dict = kwargs.get('ip_pool')
        self.reserved: dict = kwargs.get('reserved')
        self.mode: dict = kwargs.get('mode')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if value:
            if value.startswith("ethernet"):
                # Expecting format: ethernetX/Y where X and Y are digits
                if not self._validate_ethernet_name(value):
                    raise ValueError("Invalid ethernet format. Expected format: ethernetX/Y.")
            elif value.startswith("vlan"):
                # Expecting format: vlan.X where X is a digit
                if not self._validate_vlan_name(value):
                    raise ValueError("Invalid vlan format. Expected format: vlan.X.")
            else:
                raise ValueError("Name must start with 'ethernet' or 'vlan'.")

        self._name = value
        self.entry.update({'@name': value})

    @staticmethod
    def _validate_ethernet_name(name):
        # Check if name follows the ethernetX/Y format
        pattern = r"^ethernet\d+/\d+(\.\d+)?$"
        return re.match(pattern, name) is not None

    @staticmethod
    def _validate_vlan_name(name):
        # Check if name follows the vlan.X format
        pattern = r"^vlan\.\d+$"
        return re.match(pattern, name) is not None

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        if value:
            if isinstance(value, dict) and 'text' in value:
                determined_value = value['text']
            else:
                determined_value = value
            if determined_value not in ['enabled', 'disabled', 'auto']:
                raise AttributeError(f'The mode attribute must be one of enabled, '
                                     f'disabled or auto.')
            self._mode = determined_value
            self.entry.update({'mode': determined_value})
        else:
            self._mode = None

    @property
    def probe_ip(self):
        return self._probeIP

    @probe_ip.setter
    def probe_ip(self, value):
        if value:
            if isinstance(value, dict) and 'text' in value:
                determined_value = value['text']
            else:
                determined_value = value
            if determined_value not in self.yes_no:
                raise AttributeError(f'The ip_probe attribute must be one of {self.yes_no}')
            self._probeIP = determined_value
            self.entry.update({'probe-ip': determined_value})

    @property
    def ip_pool(self):
        return self._ipPool

    @ip_pool.setter
    def ip_pool(self, value):
        if value:
            if not isinstance(value, dict) or 'member' not in value or not isinstance(value['member'], list):
                raise TypeError("ip_pool must be a dictionary with a 'member' key pointing to a list.")

            for member in value['member']:
                if '-' in member:
                    # Handle IP range
                    ip_range = member.split('-')
                    if len(ip_range) != 2:
                        raise ValueError(f"{member} is not a valid IP address range.")

                    start_ip, end_ip = ip_range
                    try:
                        ipaddress.IPv4Address(start_ip)
                        ipaddress.IPv4Address(end_ip)
                    except ipaddress.AddressValueError:
                        raise ValueError(f"{member} is not a valid IP address range.")
                else:
                    # Handle individual IP
                    try:
                        ipaddress.IPv4Address(member)
                    except ipaddress.AddressValueError:
                        raise ValueError(f"{member} is not a valid IP address.")

            self._ipPool = value
            self.entry.update({'ip-pool': value})

    @property
    def reserved(self):
        return self._reserved

    @reserved.setter
    def reserved(self, value):
        if value:
            if not isinstance(value, dict) or 'entry' not in value:
                raise TypeError("The 'reserved' attribute must be a dictionary containing an 'entry' key.")

            if not isinstance(value['entry'], list):
                raise TypeError("The 'entry' key must map to a list.")

            for item in value['entry']:
                if not isinstance(item, dict) or not all(key in item for key in ['@name', 'mac', 'description']):
                    raise ValueError(
                        "Each item in 'entry' must be a dictionary with '@name', 'mac', and 'description' keys.")

                # Validate @name as IPv4
                try:
                    ipaddress.IPv4Address(item['@name'])
                except ipaddress.AddressValueError:
                    raise ValueError(f"{item['@name']} is not a valid IPv4 address.")

                # Validate MAC address format
                if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", item['mac']):
                    raise ValueError(f"{item['mac']} is not a valid MAC address.")

                # Validate description length
                if not isinstance(item['description'], str) or len(item['description']) > 255:
                    raise ValueError("The 'description' must be a string with 255 characters or fewer.")

            self._reserved = value
            self.entry.update({'reserved': value})

    @property
    def option(self):
        return self._option

    @option.setter
    def option(self, value):
        if value:
            if not isinstance(value, dict):
                raise TypeError("Option must be a dictionary.")

            # Validate 'lease'
            if 'lease' not in value or not isinstance(value['lease'], dict):
                raise ValueError("Lease must be present and a dictionary.")

            lease_keys = value['lease'].keys()
            if len(lease_keys) != 1 or (lease_keys[0] not in ['unlimited', 'timeout']):
                raise ValueError("Lease must contain exactly one key: either 'unlimited' or 'timeout'.")

            if 'unlimited' in lease_keys and value['lease']['unlimited'] != {}:
                raise ValueError("Unlimited must be an empty dictionary.")

            if 'timeout' in lease_keys:
                timeout = value['lease']['timeout']
                if not (isinstance(timeout, int) and 0 <= timeout <= 1000000):
                    raise ValueError("Timeout must be an integer between 0 and 1,000,000.")

            # Validate 'inheritance'
            if 'inheritance' in value and 'source' not in value['inheritance']:
                raise ValueError("Inheritance dictionary must have a 'source' key.")

            # Validate IP addresses for gateway, dns, wins, nis, ntp
            for key in ['gateway', 'dns', 'wins', 'nis', 'ntp']:
                if key in value:
                    if key == 'gateway':
                        if not self._validate_ip_address(value[key]):
                            raise ValueError(f"{key} must be a valid IP address.")
                    else:
                        for sub_key in ['primary', 'secondary']:
                            if sub_key in value[key] and not self._validate_ip_address(value[key][sub_key]):
                                raise ValueError(f"{key}.{sub_key} must be a valid IP address.")

            # Validate 'subnet-mask'
            if 'subnet-mask' in value and not self._validate_subnet_mask(value['subnet-mask']):
                raise ValueError("subnet-mask must be a valid subnet mask.")

            if 'dns-suffix' in value:
                if not isinstance(value['dns-suffix'], str):
                    raise ValueError("dns-suffix must be a string.")
            self._option = value
            self.entry.update({'option': value})

    def add_reserved_entry(self, name, mac, description=None):
        if not hasattr(self, '_reserved'):
            self.reserved = {'entry': []}
        # Validate the inputs
        if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac):
            raise ValueError(f"{mac} is not a valid MAC address.")
        try:
            ipaddress.IPv4Address(name)
        except ipaddress.AddressValueError:
            raise ValueError(f"{name} is not a valid IPv4 address.")
        if description and (not isinstance(description, str) or len(description) > 255):
            raise ValueError("The 'description' must be a string with 255 characters or fewer.")

        # Add the new entry
        new_entry = {'@name': name, 'mac': mac}
        if description:
            new_entry['description'] = description

        if 'entry' not in self.reserved:
            self.reserved['entry'] = []

        self.reserved['entry'].append(new_entry)
        self.entry.update({'reserved': self.reserved})

    def remove_reserved_entry(self, name, mac):
        if 'entry' not in self.reserved or not isinstance(self.reserved['entry'], list):
            raise ValueError("No reserved entries to remove.")

        # Find and remove the entry
        entry_to_remove = None
        for entry in self.reserved['entry']:
            if entry['@name'] == name and entry['mac'] == mac:
                entry_to_remove = entry
                break

        if entry_to_remove:
            self.reserved['entry'].remove(entry_to_remove)
            self.entry.update({'reserved': self.reserved})
        else:
            raise ValueError(f"No entry found with name {name} and MAC {mac}.")

class Interfaces(Network):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, **kwargs)
        self.df_ignore: str = kwargs.get('df_ignore', 'no')
        self.mtu: int = kwargs.get('mtu', 1500)
        self.ip: dict = kwargs.get('ip')
        self.ipv6: dict = kwargs.get('ipv6')
        self.bonjour: dict = kwargs.get('bonjour')
        self.interface_management_profile: str = kwargs.get('interface_management_profile')
        self.netflow_profile: str = kwargs.get('netflow_profile')
        self.comment: str = kwargs.get('comment')

    @property
    def df_ignore(self):
        return self._df_ignore

    @df_ignore.setter
    def df_ignore(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("df_ignore must be a string.")
        value = value.lower()
        if value not in self.yes_no:
            raise ValueError("df_ignore must be 'yes' or 'no'.")

        self._df_ignore = value
        self.entry.update({'df-ignore': value})

    @property
    def mtu(self):
        return self._mtu

    @mtu.setter
    def mtu(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("MTU must be an integer.")
        if not 576 <= value <= 9216:
            raise ValueError("MTU must be between 576 and 9216.")
        self._mtu = value
        self.entry.update({'mtu': value})

    @property
    def bonjour(self):
        return self._bonjour

    @bonjour.setter
    def bonjour(self, value: str) -> None:
        if value is not None:
            if not isinstance(value, dict):
                raise TypeError("Bonjour must be a dictionary or None.")

            # Initialize with default values
            bonjour_dict = {'enable': 'no', 'ttl-check': 'no', 'group-id': 0}

            # Validate and update 'enable' key if present
            if 'enable' in value:
                if value['enable'] not in self.yes_no:
                    raise ValueError("Bonjour 'enable' must be 'yes' or 'no'.")
                bonjour_dict['enable'] = value['enable']

            # Validate and update 'ttl-check' key if present
            if 'ttl-check' in value:
                if value['ttl-check'] not in self.yes_no:
                    raise ValueError("Bonjour 'ttl-check' must be 'yes' or 'no'.")
                bonjour_dict['ttl-check'] = value['ttl-check']

            # Validate and update 'group-id' key if present
            if 'group-id' in value:
                if not isinstance(value['group-id'], int) or not 0 <= value['group-id'] <= 16:
                    raise ValueError("Bonjour 'group-id' must be an integer between 0 and 16.")
                bonjour_dict['group-id'] = value['group-id']

            # Update the _bonjour attribute if validations pass
            self._bonjour = bonjour_dict
            self.entry.update({'bonjour': bonjour_dict})
        else:
            self._bonjour = None

    @property
    def ip(self):
        return self._ip

    @ip.setter
    def ip(self, value: str) -> None:
        if value:
            if not isinstance(value, dict):
                raise TypeError("IP must be a dictionary with an 'entry' key.")
            if 'entry' not in value:
                raise ValueError("IP dictionary must contain an 'entry' key.")
            if not isinstance(value['entry'], list):
                raise TypeError("The 'entry' key must map to a list.")

            # Validate each address in the list
            for address in value['entry']:
                if not self._validate_interface_address(address):
                    raise ValueError(f"{address} is not a valid IP address, Palo Alto variable, or interface address.")

            self._ip = value
            self.entry.update({'ip': value})

    @property
    def interface_management_profile(self):
        return self._interface_management_profile

    @interface_management_profile.setter
    def interface_management_profile(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("interface_management_profile must be a string.")

            if len(value) > 31:
                raise ValueError("interface_management_profile cannot be longer than 31 characters.")

            self._interface_management_profile = value
            self.entry.update({'interface-management-profile': value})

    @property
    def netflow_profile(self):
        return self._netflow_profile

    @netflow_profile.setter
    def netflow_profile(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("netflow_profile must be a string.")

            if len(value) > 63:
                raise ValueError("netflow_profile cannot be longer than 63 characters.")

            self._netflow_profile = value
            self.entry.update({'netflow-profile': value})

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("comment must be a string.")

            if len(value) > 1023:
                raise ValueError("comment cannot be longer than 1023 characters.")

            self._comment = value
            self.entry.update({'comment': value})


class EthernetInterfaces(Interfaces):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)
        self._name: str = kwargs.get('name', '')

    def valid_name(self, value: str, max_name_length: int) -> bool:
        """
       Validates if the provided string is a valid name according to the allowed character set and length.

       Parameters:
           value (str): The string to validate.
           max_name_length (int): The maximum length of the name to be validated

       Returns:
           bool: True if the string is valid, otherwise raises a ValueError.

       Raises:
           ValueError: If the string contains invalid characters or exceeds the maximum length.

       """

        # Define the allowed character set using a regular expression.
        # The pattern now ensures the entire string consists of the allowed characters.
        if isinstance(self, EthernetInterfaces):
            pattern = r"^[ 0-9a-zA-Z._/-]+$"
        else:
            pattern = r"^[ 0-9a-zA-Z._-]+$"

        allowed = re.compile(pattern, re.IGNORECASE)

        # Check length first for efficiency
        if len(value) > max_name_length:
            raise ValueError(f"The name exceeds the maximum length of {max_name_length} characters.")
        if not allowed.match(value):
            raise ValueError(
                "The name contains invalid characters. Only alphanumeric characters, spaces, and ._- are allowed.")

        return True

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        if value:
            if not self.valid_name(value, self.max_name_length):
                raise ValueError(f"Provided name '{value}' is invalid.")
            self._name = value
            self.entry.update({'@name': self._name})
        else:
            self._name = None

class AggregateEthernetInterfaces(Interfaces):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)

class VLANInterfaces(Interfaces):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)
        self._name: str = kwargs.get('name')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if value:
            if not isinstance(value, str):
                raise TypeError("Name must be a string.")
            if value:
                if not value.startswith('tunnel.'):
                    raise ValueError("Name must start with 'tunnel.'")

                try:
                    tunnel_number = int(value.split('.')[1])
                except (IndexError, ValueError):
                    raise ValueError("Name must end with a number between 1 and 9999.")

                if not 1 <= tunnel_number <= 9999:
                    raise ValueError("The number following 'tunnel.' must be between 1 and 9999.")

            self._name = value
            self.entry.update({'@name': value})

class VirtualWires(Network):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)
        pass

class LoopbackInterfaces(Interfaces):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)

class TunnelInterfaces(Interfaces):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, **kwargs)
        self._name: str = kwargs.get('name')
        self.link_tag: str = kwargs.get('link_tag')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if value:
            if not isinstance(value, str):
                raise TypeError("Name must be a string.")
            if value:
                if not value.startswith('tunnel.'):
                    raise ValueError("Name must start with 'tunnel.'")

                try:
                    tunnel_number = int(value.split('.')[1])
                except (IndexError, ValueError):
                    raise ValueError("Name must end with a number between 1 and 9999.")

                if not 1 <= tunnel_number <= 9999:
                    raise ValueError("The number following 'tunnel.' must be between 1 and 9999.")

            self._name = value
            self.entry.update({'@name': value})

    @property
    def link_tag(self):
        return self._link_tag

    @link_tag.setter
    def link_tag(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("link_tag must be a string.")

            if len(value) > 127:
                raise ValueError("link_tag cannot be longer than 127 characters.")

            self._link_tag = value
            self.entry.update({'link-tag': value})

class SDWANInterfaces(Network):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, **kwargs)
        self.name: str = kwargs.get('name')
        self.comment: str = kwargs.get('comment')
        self.link_tag: str = kwargs.get('link_tag')
        self.cluster_name: str = kwargs.get('cluster_name')
        self.allow_saas_monitor: str = kwargs.get('allow_saas_monitor', 'no')
        self.metric: int = kwargs.get('metric', 10)
        self.interface: dict = kwargs.get('interface')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not isinstance(value, str):
            raise TypeError("Name must be a string.")

        if not value.startswith('sdwan.'):
            raise ValueError("Name must start with 'sdwan.'")

        try:
            interface_number = int(value.split('.')[1])
        except (IndexError, ValueError):
            raise ValueError("Name must end with a number between 1 and 9999.")

        if not 1 <= interface_number <= 9999:
            raise ValueError("The number following 'sdwan.' must be between 1 and 9999.")

        self._name = value
        self.entry.update({'@name': value})

    @property
    def link_tag(self):
        return self._link_tag

    @link_tag.setter
    def link_tag(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("link_tag must be a string.")

            if len(value) > 127:
                raise ValueError("link_tag cannot be longer than 127 characters.")

            self._link_tag = value
            self.entry.update({'link-tag': value})

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("comment must be a string.")

            if len(value) > 1023:
                raise ValueError("comment cannot be longer than 1023 characters.")

            self._comment = value
            self.entry.update({'comment': value})

    @property
    def interface(self):
        return self._interface

    @interface.setter
    def interface(self, value: dict) -> None:
        if value:
            if not isinstance(value, dict):
                raise TypeError("Interface must be a dictionary.")

            if 'member' not in value:
                raise ValueError("Interface dictionary must contain a 'member' key.")

            if not isinstance(value['member'], list):
                raise TypeError("The 'member' key must map to a list.")

            for item in value['member']:
                if not isinstance(item, str):
                    raise TypeError("Each member in the 'member' list must be a string.")

            self._interface = value
            self.entry.update({'interface': value})

    @property
    def cluster_name(self):
        return self._cluster_name

    @cluster_name.setter
    def cluster_name(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("cluster_name must be a string.")

            if len(value) > 64:
                raise ValueError("cluster_name cannot be longer than 64 characters.")

            self._cluster_name = value
            self.entry.update({'cluster-name': value})

    @property
    def allow_saas_monitor(self):
        return self._allow_saas_monitor

    @allow_saas_monitor.setter
    def allow_saas_monitor(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("allow_saas_monitor must be a string.")

            if value not in self.yes_no:
                raise ValueError("allow_saas_monitor must be 'yes' or 'no'.")

            self._allow_saas_monitor = value
            self.entry.update({'allow-saas-monitor': value})

    @property
    def metric(self):
        return self._metric

    @metric.setter
    def metric(self, value: int) -> None:
        if value:
            if not isinstance(value, int):
                raise TypeError("metric must be an integer.")

            if not 1 <= value <= 65535:
                raise ValueError("metric must be in the range of 1 to 65535.")

            self._metric = value
            self.entry.update({'metric': value})

class AutoKey:
    class ProxyId:
        def __init__(self, **kwargs):
            self.name: str = kwargs.get('name')
            self.local: str = kwargs.get('local')
            self.remote: str = kwargs.get('remote')
            self.protocol: dict = kwargs.get('protocol')

        @property
        def name(self):
            return self._name

        @name.setter
        def name(self, value: str) -> None:
            if not isinstance(value, str):
                raise TypeError("Name must be a string.")

            if len(value) > 31:
                raise ValueError("Name cannot be longer than 31 characters.")

            if not re.match(r"^[0-9a-zA-Z._-]*$", value):
                raise ValueError("Name can only contain alphanumeric characters and . _ -")

            self._name = value

        @staticmethod
        def _validate_ip_or_subnet(value: str) -> bool:
            try:
                # This will validate for both IP address and subnet
                ipaddress.ip_network(value, strict=False)
                return True
            except ValueError:
                raise ValueError("Value must be a valid IP address or subnet.")

        @property
        def local(self):
            return self._local

        @local.setter
        def local(self, value: str) -> None:
            if value:
                self._validate_ip_or_subnet(value)
                self._local = value

        @property
        def remote(self):
            return self._remote

        @remote.setter
        def remote(self, value: str) -> None:
            if value:
                self._validate_ip_or_subnet(value)
                self._remote = value

        @property
        def protocol(self):
            return self._protocol

        @protocol.setter
        def protocol(self, value: dict) -> None:
            if value:
                if not isinstance(value, dict):
                    raise TypeError("Protocol must be a dictionary.")

                if len(value) != 1:
                    raise ValueError("Protocol dictionary must contain exactly one key.")

                key = next(iter(value))  # Get the first key to determine the type.

                if key == 'number':
                    if not isinstance(value[key], int) or not 1 <= value[key] <= 254:
                        raise ValueError("The 'number' key must have an integer value between 1 and 254.")

                elif key == 'any':
                    if value[key] != {}:
                        raise ValueError("The 'any' key must have an empty dictionary as its value.")

                elif key in ['tcp', 'udp']:
                    if not isinstance(value[key], dict):
                        raise ValueError(f"The '{key}' key must have a dictionary as its value.")

                    for port_key in ['local-port', 'remote-port']:
                        if port_key not in value[key]:
                            value[key][port_key] = 0  # Assign default value if not present

                        if not isinstance(value[key][port_key], int) or not 0 <= value[key][port_key] <= 65535:
                            raise ValueError(f"The '{port_key}' must be an integer between 0 and 65535.")

                else:
                    raise ValueError("The protocol key must be one of 'number', 'any', 'tcp', or 'udp'.")

                self._protocol = value

        def to_dict(self) -> dict:
            return {
                '@name': self.name,
                'local': self.local,
                'remote': self.remote,
                'protocol': self.protocol
            }

    def __init__(self, **kwargs):
        self._ike_gateway: dict = kwargs.get('ike_gateway')
        self._ipsec_crypto_profile: str = kwargs.get('ipsec_crypto_profile', 'default')
        self._proxy_id: dict = {'entry': []}
        self._proxy_id_v6: dict = {'entry': []}

    @property
    def proxy_id(self):
        return self._proxy_id

    @proxy_id.setter
    def proxy_id(self, value: dict) -> None:
        if not isinstance(value, dict) or 'entry' not in value or not isinstance(value['entry'], list):
            raise TypeError("proxy_id must be a dictionary with a 'entry' key that is a list.")
        self._proxy_id = value

    def add_proxy_id(self, proxy_id: ProxyId) -> None:
        if not isinstance(proxy_id, AutoKey.ProxyId):
            raise TypeError("proxy_id must be an instance of AutoKey.ProxyId.")
        self._proxy_id['entry'].append(proxy_id.to_dict())

    def remove_proxy_id(self, name: str) -> bool:
        for i, pid in enumerate(self._proxy_id['entry']):
            if pid.get('@name', '') == name:
                del self._proxy_id['entry'][i]
                return True
        return False

    @property
    def proxy_id_v6(self):
        return self._proxy_id_v6

    @proxy_id_v6.setter
    def proxy_id_v6(self, value: dict) -> None:
        if not isinstance(value, dict) or 'entry' not in value or not isinstance(value['entry'], list):
            raise TypeError("proxy_id_v6 must be a dictionary with a 'entry' key that is a list.")
        self._proxy_id_v6 = value

    def add_proxy_id_v6(self, proxy_id: ProxyId) -> None:
        if not isinstance(proxy_id_v6, AutoKey.ProxyId):
            raise TypeError("proxy_id must be an instance of AutoKey.ProxyId.")
        self._proxy_id['entry'].append(proxy_id.to_dict())

    def remove_proxy_id_v6(self, name: str) -> bool:
        for i, pid in enumerate(self._proxy_id_v6['entry']):
            if pid.get('@name', '') == name:
                del self._proxy_id_v6['entry'][i]
                return True
        return False

    @property
    def ipsec_crypto_profile(self):
        return self._ipsec_crypto_profile

    @ipsec_crypto_profile.setter
    def ipsec_crypto_profile(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("ipsec_crypto_profile must be a string.")
        self._ipsec_crypto_profile = value

    @property
    def ike_gateway(self):
        return self._ike_gateway

    @ike_gateway.setter
    def ike_gateway(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("ike_gateway must be a dictionary.")

        if 'entry' not in value:
            raise ValueError("ike_gateway dictionary must contain an 'entry' key.")

        if not isinstance(value['entry'], list):
            raise TypeError("The 'entry' key in ike_gateway must be a list.")

        for item in value['entry']:
            if not isinstance(item, dict):
                raise TypeError("Each item in the 'entry' list must be a dictionary.")

            if '@name' not in item:
                raise ValueError("Each dictionary in the 'entry' list must have an '@name' key.")

            if not isinstance(item['@name'], str):
                raise TypeError("The '@name' key value must be a string.")

            if len(item['@name']) > 63:
                raise ValueError("The value of '@name' must not exceed 63 characters.")

        self._ike_gateway = value

    def to_dict(self) -> dict:
        return {
            'ike-gateway': self.ike_gateway,
            'ipsec-crypto-profile': self.ipsec_crypto_profile,
            'proxy-id': self.proxy_id,
            'proxy-id-v6': self.proxy_id_v6
        }
class IPSecTunnels(Network):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=64, **kwargs)
        self._disabled: str = kwargs.get('disabled', 'no')
        self._comment: str = kwargs.get('comment')
        self._tunnel_interface: str = kwargs.get('tunnel_interface')
        self._anti_replay: str = kwargs.get('anti_replay', 'yes')
        self._anti_replay_window: str = kwargs.get('anti_replay_window', '1024')
        self._copy_tos: str = kwargs.get('copy_tos', 'no')
        self._copy_flow_label: str = kwargs.get('copy_flow_label', 'no')
        self._enable_gre_encapsulation: str = kwargs.get('enable_gre_encapsulation', 'no')
        self.auto_key_arg = kwargs.get('auto_key', {})
        if isinstance(self.auto_key_arg, AutoKey):
            self.auto_key = self.auto_key_arg
        else:
            self.auto_key = AutoKey(**auto_key_arg)

    @property
    def auto_key(self):
        return self._auto_key

    @auto_key.setter
    def auto_key(self, value: AutoKey) -> None:
        if not isinstance(value, AutoKey):
            raise TypeError("auto_key must be an instance of AutoKey.")
        if not self.entry.get('auto-key'):
            self.entry.update({'auto-key': {}})
        if value.ipsec_crypto_profile:
            self.entry['auto-key'].update({'ipsec-crypto-profile': value.ipsec_crypto_profile})
        if value.ike_gateway:
            self.entry['auto-key'].update({'ike-gateway': value.ike_gateway})
        self._auto_key = value

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("comment must be a string.")

        if len(value) > 1023:
            raise ValueError("comment cannot be longer than 1023 characters.")

        self._comment = value
        self.entry.update({'comment': value})

    @property
    def disabled(self) -> str:
        return self._disabled

    @disabled.setter
    def disabled(self, value: str) -> None:
        if value not in self.yes_no:
            raise ValueError("disabled must be either 'yes' or 'no'.")
        self._disabled = value
        self.entry.update({'disabled': value})

    @property
    def anti_replay(self) -> str:
        return self._anti_replay

    @anti_replay.setter
    def anti_replay(self, value: str) -> None:
        if value not in self.yes_no:
            raise ValueError("anti_replay must be either 'yes' or 'no'.")
        self._anti_replay = value
        self.entry.update({'anti-replay': value})

    @property
    def copy_tos(self) -> str:
        return self._copy_tos

    @copy_tos.setter
    def copy_tos(self, value: str) -> None:
        if value not in self.yes_no:
            raise ValueError("copy_tos must be either 'yes' or 'no'.")
        self._copy_tos = value
        self.entry.update({'copy-tos': value})

    @property
    def copy_flow_label(self) -> str:
        return self._copy_flow_label

    @copy_flow_label.setter
    def copy_flow_label(self, value: str) -> None:
        if value not in self.yes_no:
            raise ValueError("copy_flow_label must be either 'yes' or 'no'.")
        self._copy_flow_label = value
        self.entry.update({'copy-flow-label': value})

    @property
    def enable_gre_encapsulation(self) -> str:
        return self._enable_gre_encapsulation

    @enable_gre_encapsulation.setter
    def enable_gre_encapsulation(self, value: str) -> None:
        if value not in self.yes_no:
            raise ValueError("enable_gre_encapsulation must be either 'yes' or 'no'.")
        self._enable_gre_encapsulation = value
        self.entry.update({'enable-gre-encapsulation': value})

    @property
    def anti_replay_window(self):
        return self._anti_replay_window

    @anti_replay_window.setter
    def anti_replay_window(self, value: str) -> None:
        if value not in ["64", "128", "256", "512", "1024", "2048", "4096"]:
            raise ValueError(f"anti_replay_window must be one of {self.valid_anti_replay_window_values}.")
        self._anti_replay_window = value
        self.entry.update({'anti-replay-window': value})

    @property
    def tunnel_interface(self):
        return self._tunnel_interface

    @tunnel_interface.setter
    def tunnel_interface(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("tunnel_interface must be a string.")

        if not value.startswith('tunnel.'):
            raise ValueError("tunnel_interface must start with 'tunnel.'")

        self._tunnel_interface = value
        self.entry.update({'tunnel-interface': value})

class IKEGatewayNetworkProfiles(Network):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=64, **kwargs)
        self._disabled: str = kwargs.get('disabled')
        self._comment: str = kwargs.get('comment')
        self._ipv6: str = kwargs.get('ipv6')
        self._peer_address: dict = kwargs.get('peer_address')
        self._local_address: dict = kwargs.get('local_address')
        self._peer_id: dict = kwargs.get('peer_id')
        self._local_id: dict = kwargs.get('local_id')
        self._authentication: dict = kwargs.get('authentication')
        self._protocol: dict = kwargs.get('protocol')
        self._protocol_common: dict = kwargs.get('protocol_common')

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("comment must be a string.")

        if len(value) > 1023:
            raise ValueError("comment cannot be longer than 1023 characters.")

        self._comment = value
        self.entry.update({'comment': value})

    @property
    def disabled(self) -> str:
        return self._disabled

    @disabled.setter
    def disabled(self, value: str) -> None:
        if value not in self.yes_no:
            raise ValueError("disabled must be either 'yes' or 'no'.")
        self._disabled = value
        self.entry.update({'disabled': value})

    @property
    def ipv6(self) -> str:
        return self._ipv6

    @ipv6.setter
    def ipv6(self, value: str) -> None:
        if value not in self.yes_no:
            raise ValueError("disabled must be either 'yes' or 'no'.")
        self._ipv6 = value
        self.entry.update({'ipv6': value})

    @property
    def peer_address(self) -> dict:
        return self._peer_address

    @peer_address.setter
    def peer_address(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("peer_address must be a dictionary.")

        if len(value) != 1:
            raise ValueError("peer_address dictionary must contain exactly one key.")

        key = next(iter(value))  # Get the first key to determine the type.

        if key == 'ip':
            if not isinstance(value[key], str):
                raise ValueError("The 'ip' key must be a string.")
            if self._validate_ip_address(value[key]) is False:
                raise ValueError("The 'ip' key must be a valid IP address.")

        elif key == 'fqdn':
            if not isinstance(value[key], str) and len(value[key]) <= 255:
                raise ValueError("The 'fqdn' key must be a string <= 255 characters.")

        elif key == 'dynamic':
            if not isinstance(value[key], dict) or len(value[key]) > 0:
                raise ValueError("The 'dynamic' key must be an empty dict.")
        self._peer_address = value
        self.entry.update({'peer-address': value})

    @property
    def local_address(self) -> dict:
        return self._local_address

    @local_address.setter
    def local_address(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("local_address must be a dictionary.")

        if len(value) != 2:
            raise ValueError(
                "local_address dictionary must contain exactly two keys: 'ip'/'floating-ip' and 'interface'.")

        ip_keys = ['ip', 'floating-ip']
        if not any(key in value for key in ip_keys):
            raise ValueError("local_address dictionary must contain either 'ip' or 'floating-ip' key.")

        if 'ip' in value and 'floating-ip' in value:
            raise ValueError("local_address dictionary must not contain both 'ip' and 'floating-ip' keys.")

        if 'interface' not in value:
            raise ValueError("local_address dictionary must contain an 'interface' key.")

        ip_key = 'ip' if 'ip' in value else 'floating-ip'
        if not isinstance(value[ip_key], str) or not self._validate_interface_address(value[ip_key]):
            raise ValueError(f"The '{ip_key}' key must be a valid IP address string.")

        if not isinstance(value['interface'], str):
            raise ValueError("The 'interface' key must be a string.")

        self._local_address = value
        self.entry.update({'local-address': value})

    @property
    def peer_id(self) -> dict:
        return self._peer_id

    @peer_id.setter
    def peer_id(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("peer_id must be a dictionary.")

        required_keys = {'type'}
        if not required_keys.issubset(value.keys()):
            raise ValueError(f"peer_id dictionary must contain keys: {required_keys}")

        if not isinstance(value['type'], str):
            raise TypeError("'type' key in peer_id must be a string.")

        if not isinstance(value['id'], str) or not 1 <= len(value['id']) <= 1024:
            raise ValueError(
                "'id' key in peer_id must be between 1 to 1024 characters long.")

        if value.get('matching'):
            if value['matching'] not in ['exact', 'wildcard']:
                raise ValueError("'matching' key in peer_id must be either 'exact' or 'wildcard'.")

        self._peer_id = value
        self.entry.update({'peer-id': value})

    @property
    def local_id(self) -> dict:
        return self._local_id

    @local_id.setter
    def local_id(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("local_id must be a dictionary.")

        required_keys = {'type'}
        if not required_keys.issubset(value.keys()):
            raise ValueError(f"local_id dictionary must contain keys: {required_keys}")

        if not isinstance(value['type'], str):
            raise TypeError("'type' key in local_id must be a string.")

        if not isinstance(value['id'], str) or not 1 <= len(value['id']) <= 1024:
            raise ValueError(
                "'id' key in local_id must be a string that matches the specified pattern and is between 1 to 1024 characters long.")

        self._local_id = value
        self.entry.update({'local-id': value})

    @property
    def authentication(self) -> dict:
        return self._authentication

    @authentication.setter
    def authentication(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("Authentication must be a dictionary.")

        keys = value.keys()
        if not ('pre-shared-key' in keys) ^ ('certificate' in keys):
            raise ValueError(
                "Authentication dictionary must contain either 'pre-shared-key' or 'certificate', but not both.")

        if 'pre-shared-key' in keys:
            psk = value['pre-shared-key']
            if not isinstance(psk, dict):
                raise TypeError("'pre-shared-key' must be a dictionary.")

            if 'key' not in psk:
                raise ValueError("'pre-shared-key' dictionary must contain a 'key'.")

            if not isinstance(psk['key'], str) or len(psk['key']) > 255:
                raise ValueError(
                    "The 'key' in 'pre-shared-key' must be a string with a maximum length of 255 characters.")

        # For 'certificate', more validation logic will be added later as its structure is defined.
        if 'certificate' in keys:
            # Placeholder for future certificate validation
            pass

        self._authentication = value
        self.entry.update({'authentication': value})

    @property
    def protocol(self) -> dict:
        return self._protocol

    @protocol.setter
    def protocol(self, value: dict) -> None:
        if not value or not isinstance(value, dict):
            raise TypeError("Protocol must be a dictionary.")

        # Validate 'version'
        version = value.get('version', 'ikev1')
        if version not in ["ikev1", "ikev2", "ikev2-preferred"]:
            raise ValueError("The 'version' key must be one of 'ikev1', 'ikev2', 'ikev2-preferred'.")
        value['version'] = version

        # Validate 'ikev1'
        ikev1 = value.get('ikev1')
        if ikev1:
            if not isinstance(ikev1, dict):
                raise TypeError("'ikev1' must be a dictionary.")

            exchange_mode = ikev1.get('exchange-mode', 'auto')
            if exchange_mode not in ['auto', 'main', 'aggressive']:
                raise ValueError("'exchange-mode' must be one of 'auto', 'main', 'aggressive'.")
            ikev1['exchange-mode'] = exchange_mode

            ike_crypto_profile = ikev1.get('ike-crypto-profile', 'default')
            if not isinstance(ike_crypto_profile, str):
                raise TypeError("'ike-crypto-profile' must be a string.")
            ikev1['ike-crypto-profile'] = ike_crypto_profile

            self.validate_dpd(ikev1.get('dpd', {'enable': 'yes', 'interval': 5}), include_retry=True)
            value['ikev1'] = ikev1

        # Validate 'ikev2'
        ikev2 = value.get('ikev2')
        if ikev2:
            if not isinstance(ikev2, dict):
                raise TypeError("'ikev2' must be a dictionary.")

            ikev2_crypto_profile = ikev2.get('ike-crypto-profile', 'default')
            if not isinstance(ikev2_crypto_profile, str):
                raise TypeError("'ike-crypto-profile' for ikev2 must be a string.")
            ikev2['ike-crypto-profile'] = ikev2_crypto_profile

            required_cookie = ikev2.get('required-cookie')
            if required_cookie:
                if required_cookie not in self.yes_no:
                    raise ValueError("'required-cookie' must be 'yes' or 'no'.")
                ikev2['required-cookie'] = required_cookie

            self.validate_dpd(ikev2.get('dpd', {'enable': 'yes', 'interval': 5}), include_retry=False)
            ikev2['dpd'] = ikev2.get('dpd', {'enable': 'yes'})
            value['ikev2'] = ikev2

        self._protocol = value
        self.entry.update({'protocol': value})

    def validate_dpd(self, dpd_dict: dict, include_retry: bool) -> None:
        if not isinstance(dpd_dict, dict):
            raise TypeError("DPD must be a dictionary.")

        dpd_keys = ['enable', 'interval'] + (['retry'] if include_retry else [])
        if not all(key in dpd_dict for key in dpd_keys):
            raise ValueError(f"DPD dictionary must contain the keys: {dpd_keys}")

        if dpd_dict['enable']:
            if dpd_dict['enable'] not in self.yes_no:
                raise ValueError("'enable' must be 'yes' or 'no'.")
        else:
            dpd_dict['enable'] = 'yes'

        if dpd_dict['interval']:
            if not (2 <= dpd_dict['interval'] <= 100 and isinstance(dpd_dict['interval'], int)):
                raise ValueError("'interval' must be an integer between 2 and 100.")
        else:
            dpd_dict['interval'] = 5

        if include_retry:
            if dpd_dict['retry']:
                if include_retry and not (2 <= dpd_dict['retry'] <= 100 and isinstance(dpd_dict['retry'], int)):
                    raise ValueError("'retry' must be an integer between 2 and 100.")
            else:
                dpd_dict['retry'] = 5

    @property
    def protocol_common(self) -> dict:
        return self._protocol_common

    @protocol_common.setter
    def protocol_common(self, value: dict) -> None:
        if not value or not isinstance(value, dict):
            raise TypeError("protocol_common must be a dictionary.")

        # Validate 'nat-traversal'
        nat_traversal = value.get('nat-traversal')
        if not isinstance(nat_traversal, dict):
            raise TypeError("'nat-traversal' must be a dictionary.")

        nat_traversal['enable'] = nat_traversal.get('enable', 'no')
        if nat_traversal['enable'] not in self.yes_no:
            raise ValueError("'enable' in 'nat-traversal' must be 'yes' or 'no'.")

        if nat_traversal.get('keep-alive-interval'):
            nat_traversal['keep-alive-interval'] = int(nat_traversal.get('keep-alive-interval'))
            if not 10 <= nat_traversal['keep-alive-interval'] <= 3600:
                raise ValueError("'keep-alive-interval' in 'nat-traversal' must be between 10 and 3600.")

        if nat_traversal.get('udp-checksum-enable'):
            nat_traversal['udp-checksum-enable'] = nat_traversal.get('udp-checksum-enable', 'no')
            if nat_traversal['udp-checksum-enable'] not in self.yes_no:
                raise ValueError("'udp-checksum-enable' in 'nat-traversal' must be 'yes' or 'no'.")

        value['nat-traversal'] = nat_traversal

        # Validate 'passive-mode'
        value['passive-mode'] = value.get('passive-mode', 'no')
        if value['passive-mode'] not in self.yes_no:
            raise ValueError("'passive-mode' must be 'yes' or 'no'.")

        # Validate 'fragmentation'
        fragmentation = value.get('fragmentation', {'enable': 'no'})
        if fragmentation:
            if not isinstance(fragmentation, dict):
                raise TypeError("'fragmentation' must be a dictionary.")

            fragmentation['enable'] = fragmentation.get('enable', 'no')
            if fragmentation['enable'] not in self.yes_no:
                raise ValueError("'enable' in 'fragmentation' must be 'yes' or 'no'.")

            value['fragmentation'] = fragmentation

        self._protocol_common = value
        self.entry.update({'protocol-common': value})

class VirtualRouters(Network):
    """
    Initialize a VirtualRouters instance.

    :param PANDevice: A Panorama or Firewall instance.
    :param kwargs: Additional keyword arguments including interface, routing_table, multicast,
                   protocol, admin_dists, and ecmp, which are dictionaries representing different
                   aspects of the virtual router's configuration.
    """
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)
        self.interface: dict = kwargs.get('interface')
        # self.routing_table: dict = kwargs.get('routing_table')
        # self.multicast: dict = kwargs.get('multicast')
        # self.protocol: dict = kwargs.get('protocol')
        self._admin_dists = {
            'static': 10,
            'static-ipv6': 10,
            'ospf-int': 30,
            'ospf-ext': 110,
            'ospfv3-int': 30,
            'ospfv3-ext': 110,
            'ibgp': 200,
            'ebgp': 20,
            'rip': 120
        }
        self.admin_dists = kwargs.get('admin_dists')
        # self.ecmp: dict = kwargs.get('ecmp')

    @property
    def admin_dists(self) -> dict:
        return self._admin_dists

    @admin_dists.setter
    def admin_dists(self, value: dict):
        if value:
            if not isinstance(value, dict):
                raise TypeError("admin_dists must be a dictionary.")

            expected_keys = {
                'static', 'static-ipv6', 'ospf-int', 'ospf-ext',
                'ospfv3-int', 'ospfv3-ext', 'ibgp', 'ebgp', 'rip'
            }
            # Check for any unexpected keys
            extra_keys = value.keys() - expected_keys
            if extra_keys:
                raise KeyError(f"Unexpected keys in admin_dists: {extra_keys}")

            for key, default_value in self._admin_dists.items():
                if key in value:
                    if not isinstance(value[key], int):
                        raise TypeError(f"Value for '{key}' must be an integer.")
                    if not 10 <= value[key] <= 240:
                        raise ValueError(f"Value for '{key}' must be between 10 and 240.")
                    self._admin_dists[key] = value[key]
                else:
                    self._admin_dists[key] = default_value
            self.entry.update({'admin-dists': self._admin_dists})

    @property
    def interface(self) -> dict:
        return self._interface

    @interface.setter
    def interface(self, value: dict):
        if value:
            if not isinstance(value, dict):
                raise TypeError("Interface must be a dictionary.")
            if 'member' not in value:
                raise ValueError("The 'member' key is missing in the interface dictionary.")
            if not isinstance(value['member'], list) or not all(isinstance(item, str) for item in value['member']):
                raise ValueError("The 'member' key must be associated with a list of strings.")
            self._interface = value
            self.entry.update({'interface': self._interface})

class DNSProxies(Network):
    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        super().__init__(PANDevice, max_name_length=32, **kwargs)