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

class PanoramaTab(Base, PAN):
    def __init__(self, PANDevice, **kwargs):
        Base.__init__(self, PANDevice, **kwargs)
        PAN.__init__(self, PANDevice.base_url, api_key=PANDevice.api_key)
        self.endpoint: str = 'Panorama'

    def _build_params(self) -> Dict[str, str]:
        """
        Builds the parameter dictionary for the API request based on the object's state.

        Returns:
            Dict[str, str]: The parameters for the API request.
        """
        params = {}
        if self.name:
            params['name'] = self.name

        return params

class Templates(PanoramaTab):
    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_description_length=255, max_name_length=63, **kwargs)
        self.PANDevice = PANDevice
        self.settings = kwargs.get('settings', 'vsys1')

    @property
    def settings(self):
        return self._settings

    @settings.setter
    def settings(self, value):
        if not isinstance(value, str):
            raise TypeError(f'The attribute settings must be of type str.')
        if not value.startswith('vsys'):
            raise ValueError(f'The attribute settings must be a vsys.')
        self._settings = value
        self.entry.update({'settings': {'default-vsys': value}})

class TemplateStacks(PanoramaTab):
    variable_types = ['ip-netmask', 'ip-range', 'fqdn', 'group-id', 'device-priority', 'device-id', 'interface',
                      'as-number', 'qos-profiles', 'egress-max', 'link-tag']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_description_length=255, max_name_length=63, **kwargs)
        self.templates: Dict = {'member': []}
        self.devices: Dict = {'entry': []}
        self.variable: Dict = {'entry': []}

    def add_device(self, name: str, variable: dict[list]) -> bool:
        """
        Adds a device and its associated variable to the 'devices' entry.

        This method validates the structure of the given variable, creates a new
        device entry containing the specified name and variable, and appends it
        to the devices list. It ensures that the updated devices entry is
        assigned back to the main 'entry' attribute.

        Args:
            name: The name of the device to be added.
            variable: The data or configuration associated with the device.

        Returns:
            bool
        """
        if self.validate_variable_structure(variable):
            logger.debug(f'Adding device {name} to template stack {self.name}')
            device_entry = {'@name': name, 'variable': variable}
            self.devices['entry'].append(device_entry)
            self.entry['devices'] = self.devices
            return True
        else:
            logger.debug(f'Invalid variable structure for device {name} in template stack {self.name}. Not adding.')
            logger.debug(f'Varibles provide: {variable}')
            return False

    def update_variable(self, name: str, variable_type: str, variable_value: str):
        if variable_type in self.variable_types:
            variable_entry = {'@name': name, 'type': {variable_type: variable_value}}
            self.variable['entry'].append(variable_entry)
            self.entry['variable'] = self.variable

    def update_device_variable(self, device_name: str, variable_name: str, variable_type: str,
                               variable_value: str) -> None:
        if variable_type in self.variable_types:
            # Find the device by name
            for device_entry in self.devices['entry']:
                if device_entry['@name'] == device_name:
                    # Find the variable by name within the device's 'variable' list
                    variable_found = False
                    for var_entry in device_entry['variable']['entry']:
                        if var_entry['@name'] == variable_name:
                            # Update existing variable
                            var_entry['type'] = {variable_type: variable_value}
                            variable_found = True
                            break

                    if not variable_found:
                        # Add new variable if not found
                        device_entry['variable']['entry'].append({
                            '@name': variable_name,
                            'type': {variable_type: variable_value}
                        })
                    break

    def add_template_member(self, member):
        self.templates['member'].append(member)
        self.entry['templates'] = self.templates

    def get_variables_from_device(self) -> list:
        """
        Extracts and processes variables from a given device within the current object's devices list.
        This function retrieves the first device from the devices list and, if that device has variables,
        formats and appends them to a list. If no devices are present initially, it attempts to refresh the
        device list before proceeding.

        Returns:
            list: A list of dictionaries where each dictionary represents a variable with its name and type.

        """
        def extract_variables():
            variables = []
            device = self.devices['entry'][0]  # Fetch the first device
            if 'variable' in device:
                for var in device['variable']['entry']:
                    # Extract the type key and set its value to None
                    key_name = next(iter(var['type']))  # Get the first (only) key in the type dictionary
                    variables.append({
                        '@name': var['@name'],
                        'type': {key_name: None}
                    })
            self.variable['entry'] = variables
            return variables

        if self.devices['entry']:
            return extract_variables()
        else:
            self.refresh()
            if not self.devices['entry']:
                logger.warning(f'No devices found in {self.name} template stack.')
                return []
            else:
                return extract_variables()

    @property
    def templates(self):
        return self._templates

    @templates.setter
    def templates(self, value: Dict):
        if self.validate_templates_structure(value):
            self._templates = value
            self.entry['templates'] = value
        else:
            raise ValueError("Invalid templates structure")

    @staticmethod
    def validate_templates_structure(templates: Dict) -> bool:
        # Validate the structure: {'member': []}
        if not isinstance(templates, dict) or 'member' not in templates:
            return False
        if not isinstance(templates['member'], list):
            return False
        return True

    @property
    def variable(self):
        return self._variable

    @variable.setter
    def variable(self, value: Dict):
        if self.validate_variable_structure(value):
            self._variable = value
            self.entry['variables'] = value
        else:
            raise ValueError("Invalid variable structure")

    def validate_variable_structure(self, variable: Dict) -> bool:
        if not isinstance(variable, dict) or 'entry' not in variable:
            logger.debug(f'Variable is not a Dictionary or entry not in variable.')
            return False
        if not isinstance(variable['entry'], list):
            logger.debug(f'Variable entry is not a list.')
            return False
        for item in variable['entry']:
            if not isinstance(item, dict) or '@name' not in item or 'type' not in item:
                logger.debug(f'Missing keys @name and type. You provided {item}')
                return False
            if not isinstance(item['type'], dict) or len(item['type']) != 1:
                logger.debug(f'Key type must be a dictionary with one key. You provided {item["type"]}.')
                return False
            type_key = next(iter(item['type']))
            if type_key not in self.variable_types or not isinstance(item['type'][type_key], str):
                logger.debug(f'Key type is not valid. You provided {type_key} as type {type(item["type"][type_key])}')
                return False
        return True

    @property
    def devices(self):
        return self._devices

    @devices.setter
    def devices(self, value: Dict):
        if self.validate_devices_structure(value):
            self._devices = value
            self.entry['devices'] = value
        else:
            raise ValueError("Invalid devices structure")

    def validate_devices_structure(self, devices: Dict) -> bool:
        if not isinstance(devices, dict) or 'entry' not in devices:
            return False
        if not isinstance(devices['entry'], list):
            return False
        for item in devices['entry']:
            if not isinstance(item, dict) or '@name' not in item or 'variable' not in item:
                return False
            if not self.validate_variable_structure(item['variable']):
                return False
        return True

    def set_variable(self, device_name, variable_name, variable_value, variable_type, variable_descriotion=None):
        # xpath = f"/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='{self.name}']/devices/entry[@name='{device_name}']/variable"
        # element = f"<entry name={variable_name}><type><{variable_type}><{variable_value}></{variable_type}></type></entry>"
        # return self.PANDevice.set_xml(xpath, element)
        pass

    def get_template_stack(self, template_name: str) -> List[str]:
        """
        Retrieves a list of template stacks containing the specified template name.

        :param template_name: The name of the template to search for in template stacks.
        :return: A list of template stacks that include the specified template.
        """
        template_stacks = TemplateStacks(self.PANDevice)
        return [
            template_stack.get('@name')
            for template_stack in template_stacks.get()
            if template_name in template_stack.get('templates', {}).get('member', [])
        ]

class DeviceGroups(PanoramaTab):

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_description_length=255, max_name_length=63, **kwargs)
        self.authorization_code = None
        self.to_sw_version = 'None'
        self.reference_templates = kwargs.get('reference_templates')
        self.entry.update({'devices': {'entry': []}})

    @property
    def reference_templates(self):
        return self._reference_templates

    @reference_templates.setter
    def reference_templates(self, value):
        if value:
            if not isinstance(value, list):
                raise TypeError(f'Attribute {sys._getframe().f_code.co_name} must be of type list.')
            for member in value:
                if not isinstance(member, str):
                    raise TypeError(f'The items in {sys._getframe().f_code.co_name} list must be of type str.')
                # Check to see if the template exists on the device
                template = Templates(self.PANDevice, name=member)
                if not template.get():
                    # try to see if is a Template stack instead
                    templatestack = TemplateStacks(self.PANDevice, name=member)
                    if not templatestack.get():
                        raise ValueError(f'There is no such template or template stack called {memer} on {self.PANDevice.IP}')
            self._reference_templates = value
            self.entry.update({'reference-templates': {'member': value}})
        else:
            self._reference_templates = None

    @property
    def authorization_code(self):
        return self._authorization_code

    @authorization_code.setter
    def authorization_code(self, val):
        if val:
            self.Valid_Serial(val, 63)
            self._authorization_code = val
            self.entry.update({'authorization-code': val})
        else:
            self._authorization_code = None

    @property
    def to_sw_version(self):
        return self._to_sw_version

    @to_sw_version.setter
    def to_sw_version(self, val):
        if val:
            if not isinstance(val, str):
                raise TypeError(f'Attribute {sys._getframe().f_code.co_name} must be of type str.')
            self._to_sw_version = val
            self.entry.update({'to-sw-version': val})
        else:
            self._to_sw_version = 'None'

    def getParentDG(self) -> Optional[str]:
        """
        Returns the parent device group for a given child device group using the XML API.

        Returns:
            Optional[str]: The name of the parent device group if found, 'shared' if the device group
                           is top-level, or None if an error occurs or the parent cannot be determined.
        """
        URL = f'{self.PANDevice.base_url}/api/'
        xpath = f'/config/readonly/devices/entry[@name="localhost.localdomain"]/device-group/entry[@name="{self.name}"]/parent-dg'
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': xpath,
            'key': self.PANDevice.API_KEY  # Assuming API_KEY is required for authentication
        }

        try:
            response = self.session.get(URL, params=params)
            response.raise_for_status()  # Check for HTTP errors

            result = xmltodict.parse(response.text)
            status = result.get('response', {}).get('@status')

            if status == 'success':
                parent_dg = result.get('response', {}).get('result', {}).get('parent-dg')
                return parent_dg if parent_dg is not None else 'shared'
            else:
                logger.error(f'Could not get parent DG for {self.name}: {result.get("response", {}).get("msg")}')
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f'HTTP error occurred: {e}')
        except Exception as e:
            logger.error(f'Error parsing response: {e}')
        return None

    def add_device(self, serial: str) -> None:
        """
        Adds a device by serial number to the device group.

        Parameters:
        - serial (str): Serial number of the firewall to add to this group.

        Raises:
        - ValueError: If the serial number is invalid or empty.
        - AttributeError: If the devices list or entry dictionary is not properly initialized.
        """
        if not serial:
            raise ValueError("Serial number cannot be empty.")

        try:
            # Ensure 'entry' is a dictionary as expected.
            if 'devices' not in self.entry or 'entry' not in self.entry['devices'] or not isinstance(
                    self.entry['devices']['entry'], list):
                raise AttributeError("'entry' dictionary is not properly initialized.")

            # Add the serial number to the devices list and entry dictionary.
            self.entry['devices']['entry'].append({'@name': serial})
        except AttributeError as e:
            logger.error(f"Failed to add device: {e}")

    def add_reference_template(self, template_name: str) -> None:
        """
        Adds a new reference template to the device group.

        Parameters:
        - template_name (str): The name of the template to add.

        Raises:
        - ValueError: If the template_name is empty.
        - TypeError: If template_name is not a string.
        """
        if not isinstance(template_name, str):
            raise TypeError("template_name must be a string.")
        if not template_name:
            raise ValueError("template_name cannot be empty.")

        # Initialize the 'reference-templates' structure if it doesn't exist
        if 'reference-templates' not in self.entry:
            self.entry['reference-templates'] = {'member': []}

        # Check to ensure the template_name does not already exist to prevent duplicates
        if template_name not in self.entry['reference-templates']['member']:
            self.entry['reference-templates']['member'].append(template_name)
        else:
            # Log or handle the case where the template already exists if needed
            logger.warning(f"Template '{template_name}' already exists in the reference templates.")
