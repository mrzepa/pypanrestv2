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
logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Object(Base, PAN):
    """
    Base class for all objects
    """
    valid_objects: List[str] = [
        'Addresses', 'AddressGroups', 'Regions', 'DynamicUserGroups', 'Applications',
        'ApplicationGroups', 'ApplicationFilters', 'Services', 'ServiceGroups', 'Tags',
        'ExternalDynamicLists', 'CustomURLCategories']
    allowed_name_pattern = re.compile(r"[0-9a-zA-Z._-]+", re.IGNORECASE)

    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        Base.__init__(self, PANDevice, **kwargs)
        PAN.__init__(self, PANDevice.base_url, api_key=PANDevice.api_key)
        self.endpoint: str = 'Objects'
        self.disable_override: str = kwargs.get('disable-override', 'no')
        self.has_tags: bool = kwargs.get('has_tags', False)
        self.pan_objects: Dict[str, Any] = {}

    @property
    def disable_override(self) -> str:
        return self._disable_override

    @disable_override.setter
    def disable_override(self, val: str) -> None:
        # Normalize the value to lowercase if it's a string
        val = val.lower() if isinstance(val, str) else val

        # Validate the value
        if val not in ['yes', 'no', None]:
            raise ValueError(f"'disable_override' value must be 'yes', 'no', or None, not {val}.")

        # For 'shared' location, 'disable_override' should be None
        if self.location == 'shared':
            self._disable_override = None
        else:
            # Default to 'no' if the value is None and location is not 'shared'
            self._disable_override = val if val is not None else 'no'

        # Update the entry dictionary if not in 'shared' location and if PANDevice is not a Firewall
        if self.location != 'shared' and not isinstance(self.PANDevice, Firewall):
            self.entry.update({'disable-override': self._disable_override})

    def get(self, **kwargs) -> Union[bool, List]:
        """
        Get an "Object" item from the firewall or panorama.
        ANYLOCATION: Bool: If true, search all valid locations for the object
        IsSearch: Bool: Don't bother logging output if we are just seearching to see if it is there.
        :return: Object or list of all objects is name is none
        """
        # Built in regions are not enumerable via the API
        if pycountry.countries.get(alpha_2=self.name):
            return [pycountry.countries.get(alpha_2=self.name)]

        IsSearch = kwargs.get('IsSearch') or False
        ANYLOCATION = kwargs.get('ANYLOCATION') or False
        params = {'name': self.name,
                  'location': self.location}
        if isinstance(self.PANDevice, Panorama):
            if self.location != 'shared':
                params.update({'device-group': self.loc})
        else:
            params.update({'vsys': self.loc})

        # We can't use the PAN base class method rest_request because we need the error codes from the device
        # to determine how we should search for a named object.
        url = f"{self.base_url}/restapi/{self.ver}/{self.endpoint}/{self.__class__.__name__}"
        response = self.session.request('GET', url, params=params).json()

        if response.get('code') == 3:
            if response.get('message').startswith('Invalid Query Parameter: location'):
                # the object could be in a different location
                for location in self.valid_location:
                    params.update({
                        'location': location,
                    })
                    response = self.rest_request('GET', params=params)
                    if response.get('@status') == 'success':
                        return response.get('result', {}).get('entry')
                # Could not find object
                if not IsSearch:
                    logger.error(
                        f'Could not find object {self.name} in any location on the device {self.PANDevice.hostname}')
                return False
            else:
                if not IsSearch:
                    logger.error(f'Could not get object {self.name} from device {self.PANDevice.hostname}')
                return False
        if response.get('code') == 5:
            if ANYLOCATION and self.location != 'shared':
                if response.get('message') == 'Object Not Present':
                    # the object could be in a different location
                    if isinstance(self.PANDevice, Panorama):
                        # If this is a device group in Panorama, the object we are looking for can be in any
                        # parent device group within the device group hierarchy.
                        parent = self.PANDevice.device_groups_list.get(self.loc, {}).get('parent')
                        while True:
                            if parent == 'shared':
                                params.update({'location': parent})
                                if params.get('device-group'):
                                    params.pop('device-group')
                            else:
                                params.update({'device-group': parent})
                            response = self.rest_request('GET', params=params)
                            if response.get('@status') == 'success':
                                logger.info(
                                    f'Could not find {self.name} in location {self.loc}, however we did '
                                    f'find it in {parent}.')
                                return response.get('result', {}).get('entry')
                            if parent == 'shared':
                                # There are no more parent device groups to search
                                if not IsSearch:
                                    logger.warning(f'Could not find {self.name} in any device group on '
                                                   f'{self.PANDevice.IP}.')
                                break
                            else:
                                parent = self.PANDevice.device_groups_list.get(parent, {}).get('parent')
                    else:
                        for location in self.valid_location:
                            params.update({
                                'location': location,
                            })
                            response = self.rest_request('GET', params=params)
                            if response.get('@status') == 'success':
                                logger.info(
                                    f'Could not find {self.name} in location {self.loc}, however we did '
                                    f'find it in {self.location} : {location or self.loc} ')
                                return response.get('result', {}).get('entry')
                        # Could not find object
                        if not IsSearch:
                            logger.error(
                                f'Could not find object {self.name} in any location on the device {self.PANDevice.hostname}')
                        return False
            else:
                if not IsSearch:
                    logger.warning(
                        f'The {self.__class__.__name__} object {self.name} not found on device {self.PANDevice.hostname}')
                return False
        if response.get('@status') == 'success':
            return response.get('result', {}).get('entry')
        else:
            if not IsSearch:
                logger.warning(f'Could not get object {self.name} from device {self.PANDevice.hostname}')
            return False

    def refresh(self) -> bool:
        """
        Retrieves live data from a device and updates the instance attributes based on the data.
        Ensures that only one entry is returned from the data retrieval call and dynamically sets
        the instance attributes based on the data keys, modifying them if necessary.

        :return: True if the refresh is successful and instance attributes are updated, False otherwise.
        """
        if not self.name:
            logger.error('The name attribute must be available to do a refresh.')
            return False

        entry: List[Dict[str, Any]] = self.get(ANYLOCATION=True, IsSearch=True)
        if not entry:
            return False

        if len(entry) > 1:
            error_message: str = 'More than one entry returned; cannot refresh.'
            logger.error(error_message)
            raise ValueError(error_message)

        updated = False
        for key, value in entry[0].items():
            if key == '@name':
                setattr(self, 'name', value)
                updated = True
                continue

            # need to replace any - with _ so it can be used as an attribute
            modified_key: str = key.replace('-', '_')
            # Append an underscore if the key is a Python built-in name
            if modified_key in dir(builtins):
                modified_key += '_'

            if modified_key.startswith('@'):
                setattr(self, modified_key.lstrip('@'), value)
                updated = True
                continue
            # Check if the attribute exists in the instance before setting it
            if hasattr(self, modified_key):
                setattr(self, modified_key, value)
                updated = True
            else:
                # If the key doesn't match any attribute, update self.entry directly
                self.entry[key] = value
                updated = True

        return updated

    def compare(self, obj2: 'ObjectTab') -> bool:
        """
        Compare two objects to see if their values are the same based on CompareAttributeList.
        """
        if not isinstance(obj2, type(self)):
            raise ValueError(f'Expected object of type {type(self).__name__}, got {type(obj2).__name__} instead.')

        return all(
            getattr(self, attr, "").lower() == getattr(obj2, attr, "").lower() if isinstance(getattr(self, attr, None),
                                                                                             str)
            else getattr(self, attr) == getattr(obj2, attr)
            for attr in self.CompareAttributeList
        )


class Addresses(Object):
    """
    Manages address objects that allow you to reuse the same object as a source or destination address across all the
    policy rulebases without having to add the address manually each time. An address object is an entity in which you
    can include IPv4 addresses, IPv6 addresses (a single IP address, a range of addresses, or a subnet) or FQDNs.
    """
    address_types = ['ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn']
    # This is a list of attributes that need to be compared to determine if 2 objects are the same.
    CompareAttributeList = ['value'].extend(address_types)

    def __init__(self, PANDevice: Panorama | Firewall, **kwargs):
        self._ip_netmask = None
        self._ip_range = None
        self._ip_wildcard = None
        self._fqdn = None
        # Preprocess kwargs to identify and handle address type
        addr_type_key = next((key for key in self.address_types if key in kwargs), 'ip-netmask')
        addr_type_value = kwargs.pop(addr_type_key, None)
        super().__init__(PANDevice, max_name_length=64, max_description_length=1024, has_tags=True, **kwargs)
        self.value = addr_type_value if addr_type_value else ''

    def validate_addr_type(self, val: str):
        if val not in self.address_types:
            raise ValueError(f'Invalid type. Must be one of {self.address_types}')

    def validate_value(self, val: str):
        if val:
            try:
                if self.AddrType in ['ip-netmask', 'ip-range']:
                    ipaddress.ip_network(val, strict=False)
                elif self.AddrType == 'ip-wildcard':
                    # Assuming validation logic for wildcard
                    pass
                elif self.AddrType == 'fqdn':
                    if not re.match(r"^[0-9a-zA-Z.-]{,255}$", val):
                        raise ValueError(
                            'Invalid character in name. Only [0-9a-zA-Z.-] are allowed and must be less than 255 characters.')
            except ValueError as e:
                raise ValueError(f'Validation error for {self.AddrType} with value {val}: {e}')

    @property
    def ip_netmask(self):
        return self._ip_netmask

    @ip_netmask.setter
    def ip_netmask(self, value: str):
        self.validate_ip_netmask(value)
        self._set_address_type('ip_netmask', value)

    @property
    def ip_range(self):
        return self._ip_range

    @ip_range.setter
    def ip_range(self, value: str):
        self.validate_ip_range(value)
        self._set_address_type('ip_range', value)

    @property
    def ip_wildcard(self):
        return self._ip_wildcard

    @ip_wildcard.setter
    def ip_wildcard(self, value: str):
        # Add validation for ip_wildcard as needed
        self._set_address_type('ip_wildcard', value)

    @property
    def fqdn(self):
        return self._fqdn

    @fqdn.setter
    def fqdn(self, value: str):
        self.validate_fqdn(value)
        self._set_address_type('fqdn', value)

    def _set_address_type(self, addr_type: str, value: str):
        """
        Sets the address based on the addr_type and clears other address type attributes.

        :param addr_type: The type of address to set ('ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn').
        :param value: The address value to set.
        """
        if addr_type == 'ip_netmask':
            self.validate_ip_netmask(value)
            self._clear_address_attrs()
            setattr(self, f"_{addr_type}", value)
            self.entry.update({'ip-netmask': value})
        elif addr_type == 'ip_range':
            self.validate_ip_range(value)
            self._clear_address_attrs()
            setattr(self, f"_{addr_type}", value)
            self.entry.update({'ip-range': value})
        elif addr_type == 'ip_wildcard':
            # Add validation if necessary
            self._clear_address_attrs()
            setattr(self, f"_{addr_type}", value)
            self.entry.update({'ip-wildcard': value})
        elif addr_type == 'fqdn':
            self.validate_fqdn(value)
            self._clear_address_attrs()
            setattr(self, f"_{addr_type}", value)
            self.entry.update({'fqdn': value})
        else:
            raise ValueError(f"Invalid address type: {addr_type}")

    def _clear_address_attrs(self):
        """Clears all address type attributes."""
        for attr in ['_ip_netmask', '_ip_range', '_ip_wildcard', '_fqdn']:
            setattr(self, attr, None)
        for address_type in self.address_types:
            # Remove the address type from the entry if it exists
            self.entry.pop(address_type, None)

    def validate_ip_netmask(self, value: str):
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"Invalid ip-netmask value: {value}")

    def validate_ip_range(self, value: str):
        if '-' not in value:
            raise ValueError("IP range must contain '-' as a separator")
        start, end = value.split('-', 1)
        try:
            ipaddress.ip_address(start)
            ipaddress.ip_address(end)
        except ValueError:
            raise ValueError(f"Invalid IP range: {value}")

    def validate_fqdn(self, value: str):
        if not re.match(r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$', value):
            raise ValueError(f"Invalid FQDN: {value}")

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        self.validate_value(val)
        self._value = val


class AddressGroups(Object):
    """
    MemberObj: list of AddressObjects assigned to this list.
    """

    valid_types = ['static', 'dynamic']
    CompareAttributeList = ['member', 'filter'] + valid_types

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=64, max_description_length=1024, has_tags=False, **kwargs)
        # Initialize container for resolved member objects
        self.MemberObj: list = []

        # Start unset; allow instantiation without static/dynamic
        self._static: Optional[Dict[str, List[str]]] = None
        self._dynamic: Optional[Dict[str, str]] = None

        # Optionally accept one of 'static' or 'dynamic' from kwargs
        provided_static = kwargs.get('static')
        provided_dynamic = kwargs.get('dynamic')

        if provided_static is not None and provided_dynamic is not None:
            raise ValueError("Only one of 'static' or 'dynamic' can be provided.")

        if provided_static is not None:
            self.static = provided_static
        elif provided_dynamic is not None:
            self.dynamic = provided_dynamic

    @property
    def static(self):
        return self._static

    @static.setter
    def static(self, value: Optional[dict]):
        """
        Set or clear the 'static' attribute.
        When set, it must be a dict containing key 'member' with a non-empty list.
        Setting 'static' clears 'dynamic' (mutually exclusive).
        """
        if value is None:
            self._static = None
            # Remove from entry if present
            self.entry.pop('static', None)
            return

        if not isinstance(value, dict):
            raise ValueError("The 'static' attribute must be a dictionary.")
        if 'member' not in value:
            raise ValueError("The dictionary must contain the key 'member'.")
        if not isinstance(value['member'], list):
            raise ValueError("The 'member' key must have a list as its value.")
        if len(value['member']) < 1:
            raise ValueError("The list under 'member' key must contain at least one item.")

        # Set static and clear dynamic to ensure mutual exclusivity
        self._static = {'member': list(value['member'])}
        self.entry.update({'static': self._static})
        # Clear dynamic side if set
        self._dynamic = None
        self.entry.pop('dynamic', None)

    @property
    def dynamic(self) -> Optional[dict]:
        """
        The 'dynamic' property getter.
        """
        return self._dynamic

    @dynamic.setter
    def dynamic(self, value: Optional[dict]) -> None:
        """
        Set or clear the 'dynamic' attribute.
        When set, it must be a dict with a key 'filter' whose value is a string of max length 2047.
        Setting 'dynamic' clears 'static' (mutually exclusive).
        """
        if value is None:
            self._dynamic = None
            self.entry.pop('dynamic', None)
            return

        if not isinstance(value, dict):
            raise ValueError("The 'dynamic' attribute must be a dictionary.")
        if 'filter' not in value:
            raise ValueError("The dictionary must contain the key 'filter'.")
        if not isinstance(value['filter'], str):
            raise ValueError("The 'filter' key must have a string as its value.")
        if len(value['filter']) > 2047:
            raise ValueError("The 'filter' value must not exceed 2047 characters.")

        # Set dynamic and clear static to ensure mutual exclusivity
        self._dynamic = {'filter': value['filter']}
        self.entry.update({'dynamic': self._dynamic})
        # Clear static side if set
        self._static = None
        self.entry.pop('static', None)

    @property
    def MemberObj(self):
        return self._MemberObj

    @MemberObj.setter
    def MemberObj(self, val):
        if val is not None:
            if not isinstance(val, list):
                raise TypeError(f'Attribute {sys._getframe().f_code.co_name} must be of type list.')
        self._MemberObj = val

    @MemberObj.deleter
    def MemberObj(self):
        del self._MemberObj

    def add_member(self, member):
        # Ensure we are in static mode
        if self.static is None:
            raise ValueError("Can only add members to a 'static' type AddressGroup")
        members = self._static.setdefault('member', [])
        if isinstance(member, Addresses):
            if member.name not in members:
                members.append(member.name)
                self.MemberObj.append(member)
        elif isinstance(member, str):
            if member not in members:
                members.append(member)
        else:
            raise TypeError("Member must be an Addresses object or a string")
        # Reflect changes into entry
        self.entry.update({'static': self._static})

    def remove_member(self, member):
        # Ensure we are in static mode
        if self.static is None:
            raise ValueError("Can only remove members from a 'static' type AddressGroup")
        members = self._static.get('member', [])
        if isinstance(member, Addresses):
            member_name = member.name
        elif isinstance(member, str):
            member_name = member
        else:
            raise TypeError("Member must be an Addresses object or a string")

        if member_name in members:
            members.remove(member_name)
            self.MemberObj = [obj for obj in self.MemberObj if getattr(obj, 'name', None) != member_name]
            # Reflect changes into entry
            self.entry.update({'static': self._static})

    def set_filter(self, filter_str):
        # Ensure we are in dynamic mode (and set if not yet set)
        if not isinstance(filter_str, str):
            raise TypeError("Filter must be a string")
        if len(filter_str) > 2047:
            raise ValueError("Filter length exceeds the maximum allowed characters (2047)")
        # This will also clear static via the setter
        self.dynamic = {'filter': filter_str}

    def get_object(self, obj_type, name: str, location: str, device_group: str, vsys: str) -> Optional[Any]:
        """
        Attempt to instantiate an object of type `obj_type` with the provided parameters.
        Returns the instantiated object if it exists, None otherwise.
        """
        try:
            obj = obj_type(PANDevice=self.PANDevice, name=name, location=location, device_group=device_group, vsys=vsys)
            if obj.get(ANYLOCATION=True, IsSearch=True):
                return obj
        except Exception as e:
            logger.error(f"Error instantiating object of type {obj_type.__name__}: {e}")
        return None

    def populate(self) -> None:
        """
        Populate the MemberObjs list with Addresses or AddressGroups from the firewall.
        Tries to instantiate Address objects first; if that fails, tries AddressGroups.
        Raises an exception if the static member list is empty or the objects cannot be found.
        """
        members = (self.static or {}).get('member')
        if not members:
            raise ValueError('Cannot populate an empty group.')

        for item in members:
            new_object = self.get_object(Addresses, item, location=self.location, device_group=self.device_group,
                                         vsys=self.vsys)
            if new_object and new_object.refresh():
                self.MemberObj.append(new_object)
            else:
                new_object = self.get_object(AddressGroups, item, location=self.location,
                                             device_group=self.device_group, vsys=self.vsys)
                if new_object and new_object.refresh():
                    self.MemberObj.append(new_object)
                else:
                    logger.error(f'Could not find {item} in {self.PANDevice.IP}')


class Regions(Object):
    CompareAttributeList = ['latitude', 'longitude', 'address']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, has_tags=False, **kwargs)
        self.geo_location = kwargs.get('geo_location')
        self.address = kwargs.get('address')

    @property
    def geo_location(self) -> Union[None, dict]:
        return self.entry.get('geo-location')

    @geo_location.setter
    def geo_location(self, value: Union[None, dict]):
        if value is not None:
            if not isinstance(value, dict):
                raise TypeError('geo_location must be a dictionary.')

            if 'latitude' in value and 'longitude' in value:
                latitude = value['latitude']
                longitude = value['longitude']

                if not isinstance(latitude, float) or not (-90 <= latitude <= 90):
                    raise ValueError('Latitude must be a float between -90 and 90.')

                if not isinstance(longitude, float) or not (-180 <= longitude <= 180):
                    raise ValueError('Longitude must be a float between -180 and 180.')
                self._geo_location = value
                self.entry['geo-location'] = {'latitude': latitude, 'longitude': longitude}
            else:
                raise ValueError('geo_location dictionary must contain both latitude and longitude keys.')

    @property
    def address(self) -> List[str]:
        return self._address

    @address.setter
    def address(self, value: List[str]):
        if value:
            if not isinstance(value, list):
                raise TypeError('The address attribute must be of type list.')
            for addr in value:
                if '/' in addr:
                    try:
                        ipaddress.IPv4Network(addr, strict=False)
                    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                        raise ValueError(f'The IP address {addr} is not valid.')
                elif '-' in addr:
                    left_val, right_val = addr.split('-')
                    try:
                        ipaddress.IPv4Address(left_val)
                        ipaddress.IPv4Address(right_val)
                    except ipaddress.AddressValueError:
                        raise ValueError(f'The IP address range {addr} is not valid.')
                else:
                    try:
                        ipaddress.IPv4Address(addr)
                    except ipaddress.AddressValueError:
                        raise ValueError(f'The IP address {addr} is not valid.')
        self._address = value
        self.entry.update({'address': {'member': value}})


class DynamicUserGroups(Object):
    """
    Manages dynamic user groups. With dynamic user groups, you can use tags to define groups that automatically contain
    users who match the criteria you define. These groups enable you to mitigate risk when the data about a security
    incident contains only a username. They also allow you to link users with information from log forwarding and risk
    assessment applications, providing a more complete view of user behavior than you would see with user directories
    alone.
    """
    CompareAttributeList = ['filter']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=64, max_description_length=1024, has_tags=True,
                         **kwargs)
        self.filter = kwargs.get('Filter')

    @property
    def filter(self) -> str:
        return self._filter

    @filter.setter
    def filter(self, value: str) -> None:
        if value is not None:
            if not isinstance(value, str):
                raise TypeError('The filter attribute must be of type str.')
            if len(value) > 2047:
                raise ValueError('Filter string is too long. Maximum number of characters is 2047.')
        self._filter = value
        if value is not None:
            self.entry.update({'filter': value})
        else:
            self.entry.pop('filter', None)


class Applications(Object):
    valid_types = ['port', 'ident-by-ip-protocol', 'ident-by-icmp-type', 'ident-by-icmp6-type']
    valid_risk = [1, 2, 3, 4, 5]

    # This is a list of attributes that need to be compared to determine if 2 objects are the same.
    CompareAttributeList = ['default', 'subcategory', 'technology', 'risk']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_length=1024, has_tags=False, **kwargs)
        self.default: dict = kwargs.get('default')
        self.category: str = kwargs.get('category')
        self.subcategory: str = kwargs.get('subcategory')
        self.technology: str = kwargs.get('technology')
        self.timeout: int = kwargs.get('timeout')
        self.tcp_timeout: int = kwargs.get('tcp_timeout')
        self.udp_timeout: int = kwargs.get('udp_timeout')
        self.tcp_half_closed_timeout: int = kwargs.get('tcp_half_closed_timeout')
        self.tcp_time_wait_timeout: int = kwargs.get('tcp_time_wait_timeout')
        self.risk: int = kwargs.get('risk')
        self.evasive_behaviour: str = kwargs.get('evasive_behaviour')
        self.consume_big_bandwidth: str = kwargs.get('consume_big_bandwidth')
        self.used_by_malware: str = kwargs.get('used_by_malware')
        self.able_to_transfer_file: str = kwargs.get('able_to_transfer_file')
        self.has_known_vulnerability: str = kwargs.get('has_known_vulnerability')
        self.tunnel_other_application: str = kwargs.get('tunnel_other_application')
        self.tunnel_applications: str = kwargs.get('tunnel_applications')
        self.prone_to_misuse: str = kwargs.get('prone_to_misuse')
        self.pervasive_use: str = kwargs.get('pervasive_use')
        self.file_type_ident: str = kwargs.get('file_type_ident')
        self.virus_ident: str = kwargs.get('virus_ident')
        self.data_ident: str = kwargs.get('data_ident')
        self.no_appid_caching: str = kwargs.get('no_appid_caching')
        self.alg_disable_capability: str = kwargs.get('alg_disable_capability', '')
        self.parent_app: str = kwargs.get('parent_app', '')
        self.signature = [SignatureEntry(**signature) for signature in kwargs.get('signatures', [])]

        # If signatures are provided, add them to the entry dictionary
        if 'signature' in kwargs:
            self.entry.update({'signature': {'entry': [signature.to_dict() for signature in self.signatures]}})

    def set_yes_no_attribute(self, attribute_name: str, value: str):
        if not isinstance(value, str) or value.lower() not in ['yes', 'no']:
            raise ValueError(f"{attribute_name} must be 'yes' or 'no'.")
        setattr(self, f'_{attribute_name}', value.lower())
        self.entry.update({attribute_name.replace('_', '-'): value.lower()})

    @property
    def default(self) -> dict:
        return self._default

    @default.setter
    def default(self, value: dict):
        if not isinstance(value, dict):
            raise TypeError("Default must be a dictionary.")

        for key, val in value.items():
            if key not in self.valid_types:
                raise ValueError(f"Invalid type: {key}. Must be one of: {', '.join(self.valid_types)}")

            if key == 'port':
                if not isinstance(val, dict) or 'member' not in val or not isinstance(val['member'], list):
                    raise ValueError(
                        "For 'port', the value must be a dictionary with a 'member' key containing a list of strings.")
                if not all(isinstance(item, str) for item in val['member']):
                    raise ValueError("All items in the 'member' list for 'port' must be strings.")

            elif key == 'ident-by-ip-protocol':
                if not isinstance(val, str):
                    raise ValueError(f"The value for {key} must be a string.")

            elif key in ['ident-by-icmp-type', 'ident-by-icmp6-type']:
                if not isinstance(val, dict) or 'type' not in val or 'code' not in val:
                    raise ValueError(f"For {key}, the value must be a dictionary with 'type' and 'code' keys.")
                if not isinstance(val['type'], str) or not isinstance(val['code'], str):
                    raise ValueError(f"Both 'type' and 'code' values for {key} must be strings.")

        self._default = value
        self.entry.update({'default': value})

    @property
    def risk(self) -> int:
        return self._risk

    @risk.setter
    def risk(self, value: int):
        if not isinstance(value, int) or not (1 <= value <= 5):
            raise ValueError("Risk must be an integer between 1 and 5.")
        self._risk = value
        self.entry.update({'risk': value})

    @property
    def category(self) -> str:
        return self._category

    @category.setter
    def category(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Category must be a string.")
        self._category = value
        self.entry.update({'category': value})

    @property
    def subcategory(self) -> str:
        return self._subcategory

    @subcategory.setter
    def subcategory(self, value: str):
        if not isinstance(value, str) or len(value) > 63:
            raise ValueError("Subcategory must be a string up to 63 characters long.")
        self._subcategory = value
        self.entry.update({'subcategory': value})

    @property
    def technology(self) -> str:
        return self._technology

    @technology.setter
    def technology(self, value: str):
        if not isinstance(value, str) or len(value) > 63:
            raise ValueError("Technology must be a string up to 63 characters long.")
        self._technology = value
        self.entry.update({'technology': value})

    @property
    def evasive_behavior(self):
        return self._evasive_behavior

    @evasive_behavior.setter
    def evasive_behavior(self, value: str):
        self.set_yes_no_attribute('evasive_behavior', value)

    @property
    def consume_big_bandwidth(self):
        return self._consume_big_bandwidth

    @consume_big_bandwidth.setter
    def consume_big_bandwidth(self, value: str):
        self.set_yes_no_attribute('consume_big_bandwidth', value)

    @property
    def used_by_malware(self):
        return self._used_by_malware

    @used_by_malware.setter
    def used_by_malware(self, value: str):
        self.set_yes_no_attribute('used_by_malware', value)

    @property
    def able_to_transfer_file(self):
        return self._able_to_transfer_file

    @able_to_transfer_file.setter
    def able_to_transfer_file(self, value: str):
        self.set_yes_no_attribute('able_to_transfer_file', value)

    @property
    def has_known_vulnerability(self):
        return self._has_known_vulnerability

    @has_known_vulnerability.setter
    def has_known_vulnerability(self, value: str):
        self.set_yes_no_attribute('has_known_vulnerability', value)

    @property
    def tunnel_other_application(self):
        return self._tunnel_other_application

    @tunnel_other_application.setter
    def tunnel_other_application(self, value: str):
        self.set_yes_no_attribute('tunnel_other_application', value)

    @property
    def tunnel_applications(self):
        return self._tunnel_applications

    @tunnel_applications.setter
    def tunnel_applications(self, value: str):
        self.set_yes_no_attribute('tunnel_applications', value)

    @property
    def prone_to_misuse(self):
        return self._prone_to_misuse

    @prone_to_misuse.setter
    def prone_to_misuse(self, value: str):
        self.set_yes_no_attribute('prone_to_misuse', value)

    @property
    def pervasive_use(self):
        return self._pervasive_use

    @pervasive_use.setter
    def pervasive_use(self, value: str):
        self.set_yes_no_attribute('pervasive_use', value)

    @property
    def file_type_ident(self):
        return self._file_type_ident

    @file_type_ident.setter
    def file_type_ident(self, value: str):
        self.set_yes_no_attribute('file_type_ident', value)

    @property
    def virus_ident(self):
        return self._virus_ident

    @virus_ident.setter
    def virus_ident(self, value: str):
        self.set_yes_no_attribute('virus_ident', value)

    @property
    def data_ident(self):
        return self._data_ident

    @data_ident.setter
    def data_ident(self, value: str):
        self.set_yes_no_attribute('data_ident', value)

    @property
    def no_appid_caching(self):
        return self._no_appid_caching

    @no_appid_caching.setter
    def no_appid_caching(self, value: str):
        self.set_yes_no_attribute('no_appid_caching', value)

    # Assuming alg_disable_capability is a string and not a yes/no field
    @property
    def alg_disable_capability(self):
        return self._alg_disable_capability

    @alg_disable_capability.setter
    def alg_disable_capability(self, value: str):
        if not isinstance(value, str) or len(value) > 127:
            raise ValueError("alg_disable_capability must be a string up to 127 characters long.")
        self._alg_disable_capability = value
        self.entry.update({'alg-disable-capability': value})

    # Assuming parent_app is a string and not a yes/no field
    @property
    def parent_app(self):
        return self._parent_app

    @parent_app.setter
    def parent_app(self, value: str):
        if not isinstance(value, str) or len(value) > 127:
            raise ValueError("parent_app must be a string up to 127 characters long.")
        self._parent_app = value
        self.entry.update({'parent-app': value})


class ApplicationGroups(Object):
    CompareAttributeList = ['members']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=31, has_tags=False, **kwargs)
        self.members: Dict[str, List[str]] = kwargs.get('members', {'member': []})
        self.MemberObj = []

    @property
    def members(self) -> Dict[str, List[str]]:
        return self._members

    @members.setter
    def members(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'members')
        self._members = value
        self.entry.update({'members': value})


class ApplicationFilters(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, MaxNameLength=31, HasTags=True, **kwargs)


class Services(Object):
    """
    Manages service objects, which are used to identify network services that applications can or can not use.
    Network services can be defined based on protocols and/or ports. You can also use service objects to define session
    timeout values.
    """
    valid_types = ['tcp', 'udp']

    # This is a list of attributes that need to be compared to determine if 2 objects are the same.
    CompareAttributeList = ['protocol']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=64, max_description_length=1024, has_tags=True, **kwargs)
        self.protocol: Dict = kwargs.get('protocol')

    @property
    def protocol(self) -> dict:
        return self._protocol

    @protocol.setter
    def protocol(self, value: dict) -> None:
        if value:
            if not isinstance(value, dict):
                raise TypeError("Protocol must be a dictionary.")

            validated_protocols = {}
            for protocol, settings in value.items():
                if protocol not in self.valid_types:
                    raise ValueError(f"Invalid protocol: {protocol}. Must be one of: {', '.join(self.valid_types)}")

                if 'port' not in settings:
                    raise ValueError(f"'port' key is required for {protocol}.")

                protocol_settings = {'port': settings['port']}  # 'port' is mandatory

                # Validate and include optional 'source-port'
                if 'source-port' in settings and isinstance(settings['source-port'], str):
                    protocol_settings['source-port'] = settings['source-port']

                # Initialize 'override' if it's valid
                if 'override' in settings and isinstance(settings['override'], dict):
                    override_settings: dict = {}
                    for override_key, override_value in settings['override'].items():
                        if override_key not in ['no', 'yes']:
                            raise ValueError(f"Invalid override key: {override_key}. Must be 'no' or 'yes'.")

                        if override_key == 'yes' and isinstance(override_value, dict):
                            # Validate and include timeout settings
                            for timeout_key in ['timeout', 'halfclose_timeout', 'timewait_timeout']:
                                if timeout_key in override_value and isinstance(override_value[timeout_key], int):
                                    if (timeout_key == 'timewait_timeout' and 1 <= override_value[
                                        timeout_key] <= 600) or \
                                            (timeout_key != 'timewait_timeout' and 1 <= override_value[
                                                timeout_key] <= 604800):
                                        # Replace underscore with dash in the timeout key
                                        formatted_timeout_key = timeout_key.replace('_', '-')
                                        override_settings[formatted_timeout_key] = override_value[timeout_key]

                            if override_settings:
                                protocol_settings['override'] = {'yes': override_settings}
                        elif override_key == 'no':
                            protocol_settings['override'] = {'no': {}}

                validated_protocols[protocol] = protocol_settings

            # Replace underscores with dashes for keys in self.entry
            formatted_protocols = {k.replace('_', '-'): v for k, v in validated_protocols.items()}

            self._protocol = validated_protocols
            self.entry.update({'protocol': formatted_protocols})

class ServiceGroups(Object):
    """
    Manages service groups. To simplify creation of security policies, service objects can be grouped.
    Add service objects to a group using the object's name.
    """
    CompareAttributeList = ['members']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, MaxNameLength=64, HasTags=True, **kwargs)
        self.members: Dict[str, List[str]] = kwargs.get('members', {'member': []})

    @property
    def members(self) -> Dict[str, List[str]]:
        return self._members

    @members.setter
    def members(self, value: Dict[str, List[str]]) -> None:
        self.validate_member_dict(value, 'members')
        self._members = value
        self.entry.update({'members': value})

class Tags(Object):
    valid_colors: List[str] = ['color1', 'color2', 'color3', 'color4', 'color5', 'color6', 'color7', 'color8', 'color9',
                               'color10',
                               'color11', 'color12', 'color13', 'color14', 'color15', 'color16', 'color17', 'color18',
                               'color19',
                               'color20', 'color21', 'color22', 'color23', 'color24', 'color25', 'color26', 'color27',
                               'color28',
                               'color29', 'color30', 'color31', 'color32', 'color33', 'color34', 'color35', 'color36',
                               'color37',
                               'color38', 'color39', 'color40', 'color41', 'color42']

    CompareAttributeList = ['name']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=128, has_tags=False, **kwargs)
        self.color: str = kwargs.get('color', None)
        self.comments: str = kwargs.get('comments', '')

    @property
    def comments(self):
        return self._comments

    @comments.setter
    def comments(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f'Attribute comments must be of type str, not {type(value).__name__}.')
        if len(value) > 1023:
            raise ValueError(
                f'Comment cannot exceed 1023 characters; provided comment is {len(value)} characters long.')
        self._comments = value
        self.entry.update({'comments': value})

    @property
    def color(self):
        return self._color

    @color.setter
    def color(self, value: str) -> None:
        if value is not None:
            if not isinstance(value, str):
                raise TypeError(f'Attribute color must be of type str, not {type(value).__name__}.')
            if value not in self.valid_colors:
                raise ValueError(f'Invalid color: {value}. Must be one of: {", ".join(self.valid_colors)}.')
            self._color = value
            self.entry.update({'color': value})
        else:
            self._color = None

class ExternalDynamicLists(Object):
    CompareAttributeList = ['type']
    predefined_lists = ['panw-torexit-ip-list', 'panw-bulletproof-ip-list',
                        'panw-highrisk-ip-list', 'panw-known-ip-list',
                        'panw-auth-portal-exclude-list']
    valid_types = ['predefined-ip', 'predefined-url', 'ip', 'domain', 'url', 'imsi', 'imei']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=64, max_description_length=256, has_tags=False,
                         **kwargs)
        self.type_: Dict = kwargs.get('type', {})

    @property
    def type_(self) -> Optional[Dict]:
        return self._type_

    @type_.setter
    def type_(self, value: Dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("Type must be a dictionary.")

        for key, val in value.items():
            if key not in self.valid_types:
                raise ValueError(f"Invalid type: {key}. Must be one of: {', '.join(self.valid_types)}")

            if key in ['predefined-ip', 'predefined-url']:
                self._validate_predefined_type(val, key)
            elif key in ['ip', 'domain', 'url', 'imsi', 'imei']:
                self._validate_dynamic_type(val, key)

        self._type_ = value
        self.entry.update({'type': self._type_})

    def _validate_predefined_type(self, val: Dict, type_key: str) -> None:
        required_keys = ['exception-list', 'description', 'url']
        for key in required_keys:
            if key not in val:
                raise ValueError(f"Missing '{key}' in '{type_key}' type")

        # Add specific validation for each key as needed...

    def _validate_dynamic_type(self, val: Dict, type_key: str) -> None:
        # For 'ip', 'domain', 'url', 'imsi', 'imei', only 'url' and 'recurring' are required
        if 'url' not in val:
            raise ValueError(f"'url' is required for '{type_key}' type")

        if 'recurring' not in val:
            raise ValueError(f"'recurring' is required for '{type_key}' type")

        # Validate URL
        if not isinstance(val['url'], str) or not re.match(r'^https?://', val['url']):
            raise ValueError("Invalid 'url' format.")

            # Validate 'exception-list' if present
        if 'exception-list' in val:
            if not isinstance(val['exception-list'], dict) or 'member' not in val['exception-list']:
                raise ValueError("Invalid 'exception-list' format.")
            if not all(isinstance(item, str) for item in val['exception-list']['member']):
                raise ValueError("All items in 'exception-list' must be strings.")

            # Validate 'description' if present
        if 'description' in val:
            if not isinstance(val['description'], str) or len(val['description']) > 255:
                raise ValueError("Invalid 'description' format.")

            # Validate 'certificate-profile' if present
        if 'certificate-profile' in val:
            if not isinstance(val['certificate-profile'], str):
                raise ValueError("Invalid 'certificate-profile' format.")

            # Validate 'auth' if present
        if 'auth' in val:
            if not isinstance(val['auth'], dict):
                raise ValueError("Invalid 'auth' format.")
            if 'username' in val['auth'] and not 1 <= len(val['auth']['username']) <= 255:
                raise ValueError("Invalid 'username' format.")
            if 'password' in val['auth'] and not isinstance(val['auth']['password'], str):
                raise ValueError("Invalid 'password' format.")
        # Validate expand-domain if present
        if type_key == 'domain' and 'expand-domain' in val:
            if val['expand-domain'] not in ['yes', 'no']:
                raise ValueError("Invalid 'expand-domain' value. Must be 'yes' or 'no'.")

        # Validate recurring
        self._validate_recurring(val['recurring'])

        # Add validations for optional keys if they are present...

    @staticmethod
    def _validate_recurring(recurring: Dict) -> None:
        valid_keys = ['five-minute', 'hourly', 'daily', 'weekly', 'monthly']
        if not set(recurring.keys()).issubset(set(valid_keys)):
            raise ValueError("Invalid keys in 'recurring'.")

        # Check that 'hourly' and 'five-minute' have empty dictionaries as values
        for key in ['hourly', 'five-minute']:
            if key in recurring and recurring[key] != {}:
                raise ValueError(f"'{key}' should be an empty dictionary.")

        # 'daily' validation
        if 'daily' in recurring:
            if not isinstance(recurring['daily'], dict) or 'at' not in recurring['daily']:
                raise ValueError("Invalid format for 'daily' in 'recurring'.")
            if not isinstance(recurring['daily']['at'], str) or not recurring['daily'][
                'at'].isdigit() or not 0 <= int(recurring['daily']['at']) <= 23:
                raise ValueError("'at' in 'daily' should be a string representing an hour in the range 0-23.")

        # 'weekly' validation
        if 'weekly' in recurring:
            if not isinstance(recurring['weekly'], dict) or 'day-of-week' not in recurring['weekly'] or 'at' not in \
                    recurring['weekly']:
                raise ValueError("Invalid format for 'weekly' in 'recurring'.")
            if recurring['weekly']['day-of-week'].lower() not in ['sunday', 'monday', 'tuesday', 'wednesday',
                                                                  'thursday', 'friday', 'saturday']:
                raise ValueError("Invalid 'day-of-week' in 'weekly'.")
            if not isinstance(recurring['weekly']['at'], str) or not recurring['weekly'][
                'at'].isdigit() or not 0 <= int(recurring['weekly']['at']) <= 23:
                raise ValueError("'at' in 'weekly' should be a string representing an hour in the range 0-23.")

        # 'monthly' validation
        if 'monthly' in recurring:
            if (not isinstance(recurring['monthly'], dict) or 'day-of-month' not in recurring['monthly'] or 'at' not in
                    recurring['monthly']):
                raise ValueError("Invalid format for 'monthly' in 'recurring'.")
            if not isinstance(recurring['monthly']['day-of-month'], int) or not 1 <= recurring['monthly'][
                'day-of-month'] <= 31:
                raise ValueError("'day-of-month' in 'monthly' should be an integer in the range 1-31.")
            if not isinstance(recurring['monthly']['at'], str) or not recurring['monthly'][
                'at'].isdigit() or not 0 <= int(recurring['monthly']['at']) <= 23:
                raise ValueError("'at' in 'monthly' should be a string representing an hour in the range 0-23.")

class CustomURLCategories(Object):
    valid_types = ['URL List', 'Category Match']
    CompareAttributeList = ['type_', 'member']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_length=256, has_tags=False, **kwargs)
        self.type_: str = kwargs.get('type', 'URL List')
        if self.type_ not in self.valid_types:
            raise ValueError(f"Invalid type: {self.type_}. Must be one of: {', '.join(self.valid_types)}")
        self.member: Dict[List[str]] = kwargs.get('member', {'member': []})

    @property
    def type_(self):
        return self._type_

    @type_.setter
    def type_(self, value: str):
        if value not in self.valid_types:
            raise ValueError(f"Invalid type: {value}. Must be one of: {', '.join(self.valid_types)}")
        self._type_ = value
        self.entry.update({'type': value})

    @property
    def member(self):
        return self._member

    @member.setter
    def member(self, value: dict):
        if not isinstance(value, dict) or 'member' not in value or not isinstance(value['member'], list):
            raise TypeError("Member must be a dictionary with a 'member' key containing a list of strings.")
        for member in value['member']:
            if not isinstance(member, str):
                raise ValueError("Each member in the list must be a string.")
        self._member = value
        self.entry.update(**value)

    def add_member(self, new_member: str):
        """Add a new member to the member list."""
        if not isinstance(new_member, str):
            raise ValueError("New member must be a string.")

        # Ensure the member is not already in the list to avoid duplicates
        if new_member not in self._member['member']:
            self._member['member'].append(new_member)
            self.entry.update({'member': self._member['member']})
        else:
            print(f"Member {new_member} is already in the list.")

    def remove_member(self, member_to_remove: str):
        """Remove an existing member from the member list."""
        if not isinstance(member_to_remove, str):
            raise ValueError("Member to remove must be a string.")

        # Check if the member exists in the list before attempting to remove
        if member_to_remove in self._member['member']:
            self._member['member'].remove(member_to_remove)
            self.entry.update({'member': self._member['member']})
        else:
            print(f"Member {member_to_remove} not found in the list.")

class SDWANPathQualityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, has_tags=False, **kwargs)
        self.metric: Dict = kwargs.get('metric')

    @property
    def metric(self) -> Dict:
        return self._metric

    @metric.setter
    def metric(self, value: Dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("Metric must be a dictionary.")

        valid_sensitivity = ['low', 'medium', 'high']

        # Validate latency
        if 'latency' not in value or not isinstance(value['latency'], dict):
            raise ValueError("Latency metrics are missing or incorrect format.")
        latency_threshold = value['latency'].get('threshold', 100)
        latency_sensitivity = value['latency'].get('sensitivity', 'medium')
        if not (10 <= latency_threshold <= 3000):
            raise ValueError("Latency threshold must be between 10 and 3000.")
        if latency_sensitivity not in valid_sensitivity:
            raise ValueError("Invalid latency sensitivity value.")

        # Validate pkt-loss
        if 'pkt-loss' not in value or not isinstance(value['pkt-loss'], dict):
            raise ValueError("Packet loss metrics are missing or incorrect format.")
        pkt_loss_threshold = value['pkt-loss'].get('threshold', 1)
        pkt_loss_sensitivity = value['pkt-loss'].get('sensitivity', 'medium')
        if not (1 <= pkt_loss_threshold <= 100):
            raise ValueError("Packet loss threshold must be between 1 and 100.")
        if pkt_loss_sensitivity not in valid_sensitivity:
            raise ValueError("Invalid packet loss sensitivity value.")

        # Validate jitter
        if 'jitter' not in value or not isinstance(value['jitter'], dict):
            raise ValueError("Jitter metrics are missing or incorrect format.")
        jitter_threshold = value['jitter'].get('threshold', 100)
        jitter_sensitivity = value['jitter'].get('sensitivity', 'medium')
        if not (10 <= jitter_threshold <= 2000):
            raise ValueError("Jitter threshold must be between 10 and 2000.")
        if jitter_sensitivity not in valid_sensitivity:
            raise ValueError("Invalid jitter sensitivity value.")

        # If all validations pass, set the metric
        self._metric = {
            'latency': {'threshold': latency_threshold, 'sensitivity': latency_sensitivity},
            'pkt-loss': {'threshold': pkt_loss_threshold, 'sensitivity': pkt_loss_sensitivity},
            'jitter': {'threshold': jitter_threshold, 'sensitivity': jitter_sensitivity},
        }
        self.entry.update({'metric': self._metric})

class GlobalProtectHIPObjects(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class GlobalProtectHIPProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class CustomDataPatterns(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class CustomSpywareSignatures(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, has_tags=False, **kwargs)
        self.name: int = kwargs.get('name')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: int) -> None:
        if 15000 <= value <= 18000 or 6900001 <= value <= 7000000:
            self._name = value
            self.entry.update({'name': value})
        else:
            raise ValueError("Value must be between 15000-18000 or 6900001-7000000")

class CustomVulnerabilitySignatures(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, has_tags=False, **kwargs)
        self.name: int = kwargs.get('name')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: int) -> None:
        if 41000 <= value <= 45000 or 6800001 <= value <= 6900000:
            self._name = value
            self.entry.update({'name': value})
        else:
            raise ValueError("Value must be between 41000-45000 or 6800001-6900000")

class AntivirusSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class AntiSpywareSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class VulnerabilityProtectionSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class URLFilteringSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class FileBlockingSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class WildFireAnalysisSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class DataFilteringSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=65, max_description_lenght=255, has_tags=False, **kwargs)

class DoSProtectionSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class GTPProtectionSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=64, max_description_lenght=128, has_tags=False, **kwargs)

class SCTPProtectionSecurityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=21, max_description_lenght=255, has_tags=False, **kwargs)

class SecurityProfileGroups(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32,  has_tags=False, **kwargs)

class LogForwardingProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=65, max_description_lenght=1024, has_tags=False, **kwargs)

class AuthenticationEnforcements(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32,  has_tags=False, **kwargs)

class DecryptionProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32,  has_tags=False, **kwargs)

class PacketBrokerProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32, max_description_lenght=255, has_tags=False, **kwargs)

class SDWANSaasQualityProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32,  has_tags=False, **kwargs)

class SDWANTrafficDistributionProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32,  has_tags=False, **kwargs)

class SDWANErrorCorrectionProfiles(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32,  has_tags=False, **kwargs)

class Schedules(Object):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_name_length=32,  has_tags=False, **kwargs)