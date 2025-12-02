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
        if isinstance(value, dict):
            if 'default-vsys' in value:
                self._settings = value
                self.entry.update({'settings': value})
                return
        elif isinstance(value, str):
            if not value.startswith('vsys'):
                raise ValueError(f'The attribute settings must be a vsys.')
            self._settings = {'default-vsys': value}
            self.entry.update({'settings': {'default-vsys': value}})
            return
        else:
            raise TypeError(f'The attribute settings must be of type str, not {type(value)}.')


class TemplateStacks(PanoramaTab):
    """Represents a Panorama template stack and its templates, devices, and variables.

    This class models the JSON structure used by the Panorama REST API for
    template stacks, including:

    - Stack-level templates under ``templates.member``.
    - Devices assigned to the stack under ``devices.entry``.
    - Stack-level variable definitions under ``variable.entry``.
    - Per-device variable assignments under
      ``devices.entry[*].variable.entry``.

    Stack-level variables
    ---------------------
    Stack-level variables describe which variables are available to the
    template stack and what *type* they are. Each definition looks like::

        {
            "@name": "$mgmt_ip",
            "type": {"ip-netmask": "0.0.0.0/0"}
        }

    and is stored inside ``self.variable['entry']`` and serialized as the
    ``variable`` block on the template stack.

    Per-device variables
    --------------------
    Devices are stored in ``self.devices['entry']``. Each device can contain
    a per-device ``variable`` block that assigns values to the stack-level
    variables for that device::

        {
            "@name": "0123456789",  # device serial
            "variable": {
                "entry": [
                    {
                        "@name": "$mgmt_ip",
                        "type": {"ip-netmask": "10.0.0.1/32"}
                    }
                ]
            }
        }

    Typical usage
    -------------

    Create or load a template stack::

        ts = TemplateStacks(panorama, name="Branch-Stack")
        ts.refresh()  # optional, to pull live data

    Define variables at the stack level::

        ts.update_variable("$mgmt_ip", "ip-netmask", "0.0.0.0/0")
        ts.update_variable("$hostname", "hostname", "default-host")
        ts.edit()

    Add a device to the stack::

        ts.add_device("0123456789")
        ts.edit()

    Set a device variable value (recommended entry point)::

        ts.set_device_variable_value(
            device_serial="0123456789",
            variable_name="$mgmt_ip",
            value="10.1.2.3/32",
        )
        ts.edit()

    The :meth:`set_device_variable_value` helper only requires the device
    serial, variable name, and value. It automatically infers the variable
    type from the stack-level definition and creates the device entry if it
    does not already exist (unless disabled via
    ``create_device_if_missing=False``).
    """
    variable_types = ['ip-netmask', 'ip-range', 'hostname', 'ipv4-subnet', 'ipv6-subnet', 'pre-shared-key',
                        'fqdn', 'group-id', 'device-priority', 'device-id', 'interface',
                        'as-number', 'qos-profile', 'egress-max', 'link-tag']

    def __init__(self, PANDevice, **kwargs):
        super().__init__(PANDevice, max_description_length=255, max_name_length=63, **kwargs)
        self.templates: Dict = kwargs.get('templates', {'member': []})
        self.devices: Dict = kwargs.get('devices', {'entry': []})
        self.variable: Dict = kwargs.get('variable', {'entry': []})

    def _ensure_devices_container(self) -> None:
        if not isinstance(self.devices, dict) or 'entry' not in self.devices:
            self.devices = {'entry': []}
        if 'devices' not in self.entry:
            self.entry['devices'] = self.devices

    def _ensure_device_variables_container(self, device_entry: Dict[str, Any]) -> None:
        """Ensure a device has a well-formed variable container.

        Normalizes any of the following into ``{'entry': []}``:
        - Missing ``variable`` key.
        - ``variable`` set to ``None`` or a non-dict value.
        - ``variable`` as an empty dict or a dict without ``'entry'``.
        - ``variable['entry']`` present but not a list.
        """

        var_block = device_entry.get('variable')

        # If there is no variable block or it is not a dict, create a new one
        if not isinstance(var_block, dict):
            device_entry['variable'] = {'entry': []}
            return

        # Ensure there is an 'entry' list
        entry = var_block.get('entry')
        if not isinstance(entry, list):
            device_entry['variable']['entry'] = []

    def add_device(self, name: str, variables: Optional[Dict] = None) -> bool:
        self._ensure_devices_container()

        if variables is not None:
            # variables must be a variable dict: {'entry': [ ... ]}
            if not self.validate_variable_structure(variables):
                logger.debug(f"Invalid variable structure for device {name}. Not adding.")
                logger.debug(f"Variables provided: {variables}")
                return False
            device_entry: Dict[str, Any] = {'@name': name, 'variable': variables}
        else:
            device_entry = {'@name': name}

        self.devices['entry'].append(device_entry)
        self.entry['devices'] = self.devices

        return True

    def remove_device(self, name: str) -> bool:
        self._ensure_devices_container()
        for idx, device_entry in enumerate(self.devices['entry']):
            if device_entry.get('@name') == name:
                del self.devices['entry'][idx]
                self.entry['devices'] = self.devices
                return True
        return False

    def set_device_variable_value(
        self,
        device_serial: str,
        variable_name: str,
        value: Any,
        create_device_if_missing: bool = True,
    ) -> None:
        """Set a per-device variable value using only serial, name, and value.

        Parameters
        ----------
        device_serial:
            Serial number of the device in the template stack.
        variable_name:
            Name of the variable (for example ``"$mgmt_ip"``). The variable
            must already be defined at the stack level via
            :meth:`update_variable`.
        value:
            Value to assign to this variable for the specified device.
        create_device_if_missing:
            If ``True`` (default), a new device entry is added to
            ``devices.entry`` if one with ``@name == device_serial`` does not
            already exist. If ``False``, the method will only update existing
            devices.

        Notes
        -----
        The method looks up ``variable_name`` in the stack-level
        ``self.variable['entry']`` block to determine the correct variable
        *type* (for example ``"ip-netmask"`` or ``"hostname"``). It then
        delegates to :meth:`update_device_variable` to create or update the
        per-device variable entry under
        ``devices.entry[*].variable.entry``.
        """

        # Infer the variable type (from stack-level block or existing devices)
        var_type_key = self._infer_variable_type(variable_name)

        if not var_type_key:
            raise ValueError(
                f"Variable definition {variable_name!r} not found for template stack {self.name}; "
                "define it at the stack level or ensure another device has it assigned."
            )

        # Optionally create the device entry if it does not exist yet
        device_exists = any(
            isinstance(d, dict) and d.get('@name') == device_serial
            for d in self.devices.get('entry', [])
        )

        if not device_exists and create_device_if_missing:
            self.add_device(device_serial)

        # For pre-shared-key, allow callers to pass a simple string and wrap
        # it as {'value': <string>} for convenience.
        if var_type_key == 'pre-shared-key' and isinstance(value, str):
            prepared_value: Any = {'value': value}
        else:
            prepared_value = value

        # Delegate to the lower-level helper that knows about types
        self.update_device_variable(device_serial, variable_name, var_type_key, prepared_value)

    def _infer_variable_type(self, variable_name: str) -> Optional[str]:
        """Return the variable type key for a given variable name, if known.

        The lookup order is:

        1. Stack-level ``variable.entry`` definitions.
        2. Existing device-level ``devices.entry[*].variable.entry`` blocks.
        """

        # 1) Look at stack-level variable definitions, if present
        if self.variable and isinstance(self.variable, dict) and 'entry' in self.variable:
            for var_def in self.variable.get('entry', []):
                if var_def.get('@name') == variable_name and isinstance(var_def.get('type'), dict):
                    if var_def['type']:
                        return next(iter(var_def['type']))

        # 2) Fallback: inspect variables from existing devices in the stack
        if self.devices and isinstance(self.devices, dict):
            for dev in self.devices.get('entry', []):
                if not isinstance(dev, dict):
                    continue
                dev_var = dev.get('variable')
                if not isinstance(dev_var, dict):
                    continue
                for var in dev_var.get('entry', []):
                    if var.get('@name') == variable_name and isinstance(var.get('type'), dict):
                        if var['type']:
                            return next(iter(var['type']))

        return None

    def update_variable(self, name: str, variable_type: str, variable_value: str):
        if variable_type in self.variable_types:
            variable_entry = {'@name': name, 'type': {variable_type: variable_value}}
            self.variable['entry'].append(variable_entry)
            self.entry['variable'] = self.variable

    def update_device_variable(self, device_name: str, variable_name: str, variable_type: str,
                               variable_value: Any) -> None:
        if variable_type not in self.variable_types:
            return

        self._ensure_devices_container()

        for device_entry in self.devices['entry']:
            if device_entry.get('@name') != device_name:
                continue

            self._ensure_device_variables_container(device_entry)

            # For pre-shared-key we accept either a dict({'key'/'value'}) or a
            # plain string (convenience, wrapped as {'value': <str>}).
            if variable_type == 'pre-shared-key' and isinstance(variable_value, str):
                normalized_value: Any = {'value': variable_value}
            else:
                normalized_value = variable_value

            variable_found = False
            # Use get() accessors to avoid KeyError if the container wasn't
            # fully normalized for some reason.
            for var_entry in device_entry.get('variable', {}).get('entry', []):
                if var_entry.get('@name') == variable_name:
                    if variable_type == 'pre-shared-key':
                        # Expect a dict with one of 'key' or 'value'
                        if not isinstance(normalized_value, dict):
                            raise ValueError("pre-shared-key variable_value must be a dict with 'key' or 'value'.")
                        var_entry['type'] = {variable_type: normalized_value}
                    else:
                        var_entry['type'] = {variable_type: normalized_value}
                    variable_found = True
                    break

            if not variable_found:
                # Ensure the entry list exists before appending
                if 'variable' not in device_entry or not isinstance(device_entry['variable'], dict):
                    device_entry['variable'] = {'entry': []}
                if 'entry' not in device_entry['variable'] or not isinstance(device_entry['variable']['entry'], list):
                    device_entry['variable']['entry'] = []

                if variable_type == 'pre-shared-key':
                    if not isinstance(normalized_value, dict):
                        raise ValueError("pre-shared-key variable_value must be a dict with 'key' or 'value'.")
                    payload = {variable_type: normalized_value}
                else:
                    payload = {variable_type: normalized_value}

                device_entry['variable']['entry'].append({
                    '@name': variable_name,
                    'type': payload
                })

            self.entry['devices'] = self.devices
            break

    def remove_device_variable(self, device_name: str, variable_name: str) -> bool:
        self._ensure_devices_container()

        for device_entry in self.devices['entry']:
            if device_entry.get('@name') != device_name:
                continue

            if 'variable' not in device_entry or 'entry' not in device_entry['variable']:
                return False

            for idx, var_entry in enumerate(device_entry['variable']['entry']):
                if var_entry.get('@name') == variable_name:
                    del device_entry['variable']['entry'][idx]
                    self.entry['devices'] = self.devices
                    return True
            return False

        return False

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
            var_block = device.get('variable', {}) if isinstance(device, dict) else {}
            entry_list = []
            if isinstance(var_block, dict):
                raw_entry = var_block.get('entry', [])
                if isinstance(raw_entry, list):
                    entry_list = raw_entry

            for var in entry_list:
                if not isinstance(var, dict) or 'type' not in var or '@name' not in var:
                    continue
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
            self.entry['variable'] = value
        else:
            raise ValueError("Invalid variable structure")

    def validate_variable_structure(self, variable: Dict) -> bool:
        if not isinstance(variable, dict):
            logger.debug(f'Variable is not a Dictionary.')
            return False

        # Treat missing or empty 'entry' as a valid empty variable container
        entry_list = variable.get('entry', [])
        if entry_list in (None, ''):
            entry_list = []

        if not isinstance(entry_list, list):
            logger.debug(f'Variable entry is not a list.')
            return False

        if not entry_list:
            # An empty variable block is acceptable (no variables defined yet)
            return True

        for item in entry_list:
            if not isinstance(item, dict) or '@name' not in item or 'type' not in item:
                logger.debug(f'Missing keys @name and type. You provided {item}')
                return False
            if not isinstance(item['type'], dict) or len(item['type']) != 1:
                logger.debug(f'Key type must be a dictionary with one key. You provided {item["type"]}.')
                return False

            type_key = next(iter(item['type']))
            type_val = item['type'][type_key]

            if type_key not in self.variable_types:
                logger.debug(f"Key type {type_key} is not in allowed variable_types for {item['@name']}.")
                return False

            # Special handling for pre-shared-key: value is a dict with 'key' or 'value' (string)
            if type_key == 'pre-shared-key':
                if not isinstance(type_val, dict):
                    logger.debug(f"pre-shared-key value must be a dict; got {type(type_val)} for {item['@name']}.")
                    return False
                if not any(k in type_val for k in ('key', 'value')):
                    logger.debug(f"pre-shared-key dict must contain 'key' or 'value' for {item['@name']}: {type_val}.")
                    return False
                # Ensure any present key/value fields are strings
                for k in ('key', 'value'):
                    if k in type_val and not isinstance(type_val[k], str):
                        logger.debug(f"pre-shared-key field {k!r} must be str for {item['@name']}, got {type(type_val[k])}.")
                        return False
            else:
                # All other types must have a simple string value
                if not isinstance(type_val, str):
                    logger.debug(f"Key type is not valid. For variable {item['@name']}, you provided {type_key} "
                                 f"as type {type(type_val)}. Value is {type_val}.")
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
            if not isinstance(item, dict) or '@name' not in item:
                return False
            if 'variable' in item:
                var_block = item['variable']
                # Allow empty dict or {'entry': []} as "no variables yet"
                if isinstance(var_block, dict):
                    entry_list = var_block.get('entry', [])
                    if entry_list in (None, ''):
                        entry_list = []
                    if entry_list:
                        # Only run full validation when there are actual entries
                        if not self.validate_variable_structure(var_block):
                            return False
                else:
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
