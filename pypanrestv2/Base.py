import getpass
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
from icecream import ic

logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NetworkRequestError(Exception):
    """
    Exception raised for errors in the network request.

    Attributes:
        message -- explanation of the error
        details -- optional details of the error (default None)
    """
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details

class PAN:
    """
    Base class for palo alto devices
    The IP address of the device is the only mandatory parameter.
    Either api_key or username and password are needed. The API_KEY can be obtained from using the username and password
    to connect to the device.
    The ver for software version is required for API calls. If this is not provided, it can be obtained by connecting
    to the devide and issuing the OP command "show system info".
    The "show system info" also returns a number of other usefull information that can be used by the class so might
    as well extract it at the same time.
    Since access to the device can be restricted to prevent execuing OP commands, there needs to be another REST call
    that can be made to verify the API_KEY. This can be prompted for, or provided via config.yaml input. Without the
    "show system info", the version must be provided. If the sytem is not able to get the version, raise an exception.
    """
    yes_no = ['yes', 'no']

    def __init__(self, base_url: str, **kwargs):
        self.base_url: str = base_url
        self.api_key: str = kwargs.get('api_key')
        self.username: str = kwargs.get('username')
        self.password: str = kwargs.get('password')
        self.force_interactive: bool = kwargs.get('force_interactive', True)
        self.session: requests.Session = requests.Session()
        self.session.verify = False
        if self.api_key:
            try:
                self.session.headers = {'X-PAN-KEY': self.api_key}
                self.SystemInfo: dict = self.op('show system info').get('result', {}).get('system')
            except requests.HTTPError as http_err:
                logger.error(f'HTTP error occurred: {http_err}')
        elif self.username and self.password:
            try:
                self.api_key = self.getkey()
                self.session.headers = {'X-PAN-KEY': self.api_key}
                self.SystemInfo: dict = self.op('show system info').get('result', {}).get('system')
            except requests.HTTPError as http_err:
                logger.error(f'HTTP error occurred: {http_err}')
        else:
            raise ValueError("Must provide either an api_key or both username and password for authentication.")

        if self.SystemInfo:
            self.ver = self.ver_from_sw_version(self.SystemInfo['sw-version'])
            if self.password:
                # if we used a password, clear it from memory as it is no longer needed now that we have a working API key
                self.password = None
            self.hostname = self.SystemInfo['hostname']
        else:
            raise ValueError(f"Can not determine the PANOS version for {self.base_url}.")

    @staticmethod
    def valid_name(value: str, max_name_length: int) -> bool:
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

        pattern = r"^[ 0-9a-zA-Z._-]+$"

        allowed = re.compile(pattern, re.IGNORECASE)

        # Check length first for efficiency
        if len(value) > max_name_length:
            raise ValueError(f"The name exceeds the maximum length of {max_name_length} characters.")
        if not allowed.match(value):
            raise ValueError(
                "The name contains invalid characters. Only alphanumeric characters, spaces, and ._- are allowed.")

        return True

    def rest_request(self, method: str, **kwargs) -> dict:
        valid_endpoints = ['Objects', 'Policies', 'Network', 'Device', 'Panorama']
        if self.endpoint not in valid_endpoints:
            raise ValueError(f'endpoint attribute must be one of {valid_endpoints}, not {self.endpoint}.')
        if self.pre_post and self.endpoint == 'Policies':
            url = f"{self.base_url}/restapi/{self.ver}/{self.endpoint}/{self.__class__.__name__.split('Rules')[0]}{self.pre_post}Rules"
        else:
            url = f"{self.base_url}/restapi/{self.ver}/{self.endpoint}/{self.__class__.__name__}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()

    def xml_request(self, **kwargs) -> dict:
        """
        xml requests are always GET
        :param kwargs:
        :return:
        """
        url = f"{self.base_url}/api/"
        response = self.session.get(url, **kwargs)
        response.raise_for_status()
        return xmltodict.parse(response.text)

    @staticmethod
    def is_interactive_mode() -> bool:
        """
        Check if the script is running in an interactive mode.
        """
        return sys.stdin.isatty()

    def prompt_for_credentials(self) -> None:
        """
        Prompt the user for credentials if not already set.
        """
        if not self.username:
            self.username = input('Please enter the admin username: ')
        if not self.password:
            self.password = getpass.getpass('Please enter the admin password: ')

    def getkey(self) -> Optional[str]:
        """
        Get the API key from a Palo Alto Networks firewall or Panorama.
        :return: API key as a string or None if an error occurs
        """
        params: dict[str, str] = {
            'type': 'keygen',
            'user': self.username,
            'password': self.password
        }
        try:
            response = self.xml_request(params=params)
        except requests.exceptions.ConnectionError:
            logger.error('Error connecting to firewall.')
            return None

        # Check for error code in the response
        if response.get('response', {}).get('@code') == '403':
            logger.warning('Access denied. Check your username and password.')
            return None
        else:
            # Extract the API key from the parsed response
            api_key: Optional[str] = response.get('response', {}).get('result', {}).get('key')
            return api_key

    @staticmethod
    def ver_from_sw_version(sw_version: str) -> Optional[str]:
        """
        Extracts and formats the version string to include only the major and minor version numbers,
        prefixed with 'v'. If the input string does not contain a version pattern that can be parsed,
        None is returned.

        :param sw_version: The software version string to parse.
        :return: A formatted version string or None if parsing fails.
        """
        try:
            # Split the string by decimal point and ensure at least two parts exist
            parts = sw_version.split('.')
            if len(parts) >= 2:
                # Use only the first two parts (major and minor versions)
                result = '.'.join(parts[:2])
                return f'v{result}'
            else:
                return None
        except AttributeError:
            # In case the input is not a string or another error occurs
            return None

    @property
    def base_url(self):
        return self._base_url

    @base_url.setter
    def base_url(self, value: str):
        # Normalize the value by stripping the scheme (if present) for validation
        stripped_value = value.split("//")[-1]
        # Split stripped value to isolate the hostname/IP and the rest of the path
        hostname_and_port = stripped_value.split('/')[0]

        # Extract hostname/IP and port (if present)
        if ':' in hostname_and_port:
            hostname, port = hostname_and_port.split(':', 1)
        else:
            hostname, port = hostname_and_port, None

        # Validate port if it exists
        if port:
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                raise ValueError(f"Provided port {port} in base_url {value} is invalid.")

        # Initialize a flag to indicate whether the provided hostname is an IP address
        is_ip_address = False

        # Check if the hostname is an IP address
        try:
            ipaddress.ip_address(hostname)  # Validate as IP address
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        # If not an IP address, attempt DNS resolution
        if not is_ip_address:
            try:
                # Perform DNS resolution
                dns.resolver.resolve(hostname, 'A')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                raise ValueError(f"Provided base_url {value} is neither a valid IP address nor a resolvable hostname.")

        # Prepend https:// if missing
        if not value.startswith('https://'):
            value = 'https://' + value

        # Assign the validated and normalized base_url to the instance attribute
        self._base_url = value

    @property
    def hostname(self):
        return self._hostname

    @hostname.setter
    def hostname(self, value):
        if not isinstance(value, str):
            raise ValueError("Hostname must be a string.")
        if len(value) >= 32:
            raise ValueError("Hostname must be less than 32 characters long.")
        self._hostname = value

    @staticmethod
    def string_to_xml(string, **kwargs) -> str:
        # Basic function to take a string and convert it to xml format for issuing Operational Commands.
        # Sometimes a value is given, this value is a single string that is placed in the middle of the XML string.
        value = kwargs.get('value')
        data = string.split(' ')
        XML_Right = []
        XML_Left = []
        # Build out the start and end of the XML string
        for item in data:
            left = f'<{item}>'
            right = f'</{item}>'
            XML_Left.append(left)
            XML_Right.insert(0, right)
        # Add in the value by putting it at the end of the left most XML tags.
        if value:
            XML_Left.append(value)
        # Close off the XML by adding in the right most XML tags.
        XML_Left.extend(XML_Right)
        return ''.join(XML_Left)

    def set_xml(self, xpath: str, element: str) -> dict:
        """
        Set a config setting using the XML API
        :param xpath: The xpath of the element to be set
        :param element: The element to be set
        :return: Dict with the status of the set command
        """
        params: dict = {
            'type': 'config',
            'action': 'set',
            'xpath': xpath,
            'element': element
        }
        try:
            parsed_response = self.xml_request(params=params, timeout=8)
            status = parsed_response['response']['@status']
            message = parsed_response['response'].get('msg', 'No message provided')

            return {'status': status, 'msg': message}
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error occurred: {e}")
            return {'status': 'error', 'msg': str(e)}
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Connection error occurred: {e}")
            return {'status': 'error', 'msg': 'Connection error'}
        except requests.exceptions.Timeout as e:
            logging.error(f"Request timed out: {e}")
            return {'status': 'error', 'msg': 'Timeout'}
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return {'status': 'error', 'msg': 'Unexpected error'}

    def get_xml(self, xpath: str) -> Dict[str, Any]:
        """
        Fetches configuration from the device using an XML format via a GET request.

        :param xpath: The XPath specifying the configuration to fetch.
        :return: A dictionary parsed from the XML response.
        """
        params: Dict[str, str] = {
            'type': 'config',
            'action': 'get',
            'xpath': xpath,
        }
        try:
            response = self.xml_request(params=params, timeout=8)
            return response
        except requests.exceptions.HTTPError as e:
            logging.error(f'HTTP error occurred: {e}')  # Specific HTTP errors (e.g., 404, 401, ...)
        except requests.exceptions.ConnectionError as e:
            logging.error(f'Error connecting to the server: {e}')  # Problems with the network
        except requests.exceptions.Timeout as e:
            logging.error(f'Timeout error: {e}')  # The request timed out
        except requests.exceptions.RequestException as e:
            logging.error(f'Error during requests to {url}: {e}')  # Any other requests exception
        except Exception as e:
            logging.error(f'An unexpected error occurred while processing the XML: {e}')  # Non-requests related errors

            # Return an empty dict or a specific error structure if preferred
        return {'error': 'An error occurred while fetching the XML configuration.'}

    def edit_xml(self, xpath: str, element: str) -> Dict[str, Any]:
        """
        Edit XML configuration by specifying a path and the element to edit.

        :param xpath: The XPath to the configuration element to edit.
        :param element: The new XML element to insert.
        :return: A dictionary with the status and message of the operation.
        """
        params = {
            'type': 'config',
            'action': 'edit',
            'xpath': xpath,
            'element': element
        }
        try:
            response = self.xml_request(params=params, timeout=8)
            return {
                'status': response['response'].get('@status'),
                'msg': response['response'].get('msg', 'No message provided')
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return {'status': 'error', 'msg': str(e)}
        except Exception as e:  # Generic exception handling
            logger.error(f"Parsing error or other exception: {e}")
            return {'status': 'error', 'msg': 'An unexpected error occurred'}

    def delete_xml(self, xpath: str) -> Dict[str, Any]:
        """
        Delete an XML configuration element specified by the XPath.

        :param xpath: The XPath to the configuration element to delete.
        :return: A dictionary with the status and message of the operation.
        """
        params = {
            'type': 'config',
            'action': 'delete',
            'xpath': xpath,
        }
        try:
            response = self.xml_request(params=params, timeout=8)

            return {
                'status': response['response'].get('@status'),
                'msg': response['response'].get('msg', 'No message provided')
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return {'status': 'error', 'msg': str(e)}
        except Exception as e:  # Catching generic exceptions for logging and error reporting
            logger.error(f"Parsing error or other exception: {e}")
            return {'status': 'error', 'msg': 'An unexpected error occurred'}

    def send_command(self, cmd: str, value: Optional[Any] = None, timeout: int = 60) -> Dict[str, Any]:
        """
        Send a command to the firewall.

        :param cmd: Command to be sent.
        :param value: Additional value for the command, if any.
        :param timeout: Timeout for the request in seconds.
        :return: Parsed XML response as a dictionary.
        """

        params = {'type': 'op', 'cmd': self.command_to_payload(cmd, value)}
        try:
            response = self.xml_request(params=params, timeout=timeout)
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return {'response': {'@status': 'error', 'msg': str(e)}}
        except Exception as e:  # Catching generic exceptions for logging and error reporting
            logger.error(f"Parsing error or other exception: {e}")
            return {'response': {'@status': 'error', 'msg': 'An unexpected error occurred'}}

    def command_to_payload(self, cmd: str, value: Optional[Any]) -> str:
        """
        Convert command to payload. This method needs to be implemented based on specific requirements.

        :param cmd: Command to be sent.
        :param value: Additional value for the command, if any.
        :return: The command converted into a payload string.
        """
        return self.string_to_xml(cmd, value=value)

    def wait_for_job_completion(self, job_id: str) -> None:
        """
        Poll the job status until completion.

        :param job_id: The ID of the job to poll.
        """
        params = {'type': 'op', 'cmd': self.string_to_xml('show jobs id', value=job_id)}

        while True:
            try:
                job = self.xml_request(params=params, timeout=8)
                status = job['response']['result']['job']['status']

                if status == 'FIN':
                    logger.info(f"Job {job_id} is 100% complete.")
                    break

                progress = job['response']['result']['job']['progress']
                logger.info(f"On device {self.hostname}, Job {job_id} is {progress}% complete.")

            except requests.exceptions.RequestException as e:
                logger.error(f"Error polling job status: {e}")
                break

            time.sleep(5)

    def op(self, cmd: str, value: str = None, wait: bool = False) -> Dict[str, Any]:
        """
        Execute a command on the firewall.

        :param wait: Wait for the job to finish or not
        :param value: Value in to go with the command.
        :param cmd: The command to execute.
        :return: The parsed result of the command execution.
        """

        result = self.send_command(cmd, value)

        if result['response']['@status'] == 'success' and wait:
            job_id = result['response']['result'].get('job')
            if job_id:
                self.wait_for_job_completion(job_id)

        return self.parse_result(result)

    @staticmethod
    def parse_result(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and return the command execution result.

        :param result: The raw result from the command execution.
        :return: A dictionary containing the status and result of the command execution.
        """
        if 'result' in result['response']:
            return {'status': result['response']['@status'], 'result': result['response']['result']}
        else:
            return {'status': result['response']['@status'],
                    'result': {k: v for k, v in result['response'].items() if k != '@status'}}

    def clear_sessions(self):
        """
        Clear all sessions on the firewall
        :return:
        """
        self.op('clear session all')

    def restart_management(self):
        """
        Restart the management server on the firewall
        :return:
        """
        self.op('debug software restart process management-server')

    def commit(self, wait: bool = False) -> Dict:
        """
        Commit changes to Panorama or Firewall. If "wait" argument is True, then wait for the commit job to finish.
        """
        if not isinstance(wait, bool):
            raise ValueError('The wait attribute must be True or False')

        params = {
            'key': self.api_key,
            'type': 'commit',
            'cmd': '<commit></commit>'
        }

        parsed_response = self.xml_request(params=params)

        if parsed_response.get('response', {}).get('@status') == 'success':
            job_id = parsed_response.get('response', {}).get('result', {}).get('job')
            if wait and job_id:
                # Waiting for completion
                commmit_status = self.wait_for_commit_to_finish(job_id)
                return {**commmit_status, 'job_id': job_id}
            elif job_id:
                # Job ID present but not waiting for completion
                return {'status': 'pending', 'job_id': job_id}
            else:
                # Success but no job ID found
                return {'status': 'success', 'message': 'Commit successful, no job ID provided.'}
        else:
            return {'status': parsed_response.get('response', {}).get('@status'),
                    'msg': parsed_response.get('response', {}).get('msg', 'Unknown error')}

    def wait_for_commit_to_finish(self, job_id) -> dict:
        """
        Wait for the commit job to finish and return the final status.
        """
        while True:
            result = self.op('show jobs id', value=job_id)
            job_status = result.get('result', {}).get('job', {}).get('status')

            if job_status == 'FIN':
                logger.info(f"Commit job {job_id} finished.")
                return {'status': result.get('result', {}).get('job', {}).get('result')}
            time.sleep(10)  # Adjust sleep time as needed

    def get_license_info(self) -> Tuple[List[str], Dict[str, Union[str, int]]]:
        """
        Get the license info for this device.
        Returns a tuple containing a list of column names and a dictionary with license information.
        """
        columns = [
            'serial', 'device name', 'support', 'Threat Prevention', 'GlobalProtect Gateway',
            'PAN-DB URL Filtering', 'DNS Security', 'WildFire License', 'Logging Service', 'PA-VM',
            'Advanced URL Filtering', 'Device Management License'
        ]

        try:
            response = self.op('request license info')
            if response.get('status') == 'success' and response.get('result', {}).get('licenses', {}).get('entry',
                                                                                                          None) is not None:
                licenses = {
                    'device name': self.hostname,
                    'serial': self.serial
                }
                for lic in response['result']['licenses']['entry']:
                    if lic.get('expires') and lic.get('expires') != 'Never':
                        endDateRAW = datetime.strptime(lic['expires'], '%B %d, %Y')
                        endDateRAW = int(endDateRAW.timestamp()) * 1000
                        feature_name = lic.get('feature')
                        if lic.get('feature') == 'Premium':
                            licenses.update({'support': endDateRAW})
                        else:
                            licenses.update({feature_name: endDateRAW})
                return columns, licenses
            else:
                raise ValueError("Failed to retrieve license information or no licenses found.")
        except Exception as e:
            raise RuntimeError(f"Error retrieving license information: {e}")

    def refresh_license(self):
        """
        Fetch the licenses from palo alto networks custom support portal
        :return:
        """
        return self.op('request license fetch')

    @staticmethod
    def version_key(version):
        # For finding the newest version of the content
        return tuple(map(int, version.split('-')))

    def update_content(self):
        """
        Download the latest version of the Apps & Threats and install it.
        :return: status and result of the operation
        """

        download = self.op('request content upgrade download latest', wait=True)

        if download['status'] == 'success':
            current_info = self.op('request content upgrade info')
            app_version_list = []
            current_verison = ''
            for entry in current_info['result']['content-updates']['entry']:
                app_version_list.append(entry['app-version'])
                if entry['current'] == 'yes':
                    current_verison = entry['app-version']
            hightest_version = max(app_version_list, key=self.version_key)
            if current_verison != hightest_version:
                # There is a newer version, upgrade to it.
                install = self.op('request content upgrade install version', value='latest', wait=True)
                return install
            else:
                logging.info(f'Content is already up to date. Nothing to do.')
                return {'status': 'success',
                        'msg': 'Content is already up to date. Nothing to do.'}

    def update_av(self):
        """
        Downlaod and install the lastest AntiVirus.
        You can only get the Anti-Virus content if the Threat Prevention license is on the firewall
        :return: status and result of the operation
        """
        download = self.op('request anti-virus upgrade download latest', wait=True)
        if download['status'] == 'success':
            current_info = self.op('request anti-virus upgrade info')
            app_version_list = []
            current_verison = ''
            for entry in current_info['result']['content-updates']['entry']:
                app_version_list.append(entry['app-version'])
                if entry['current'] == 'yes':
                    current_verison = entry['app-version']
            hightest_version = max(app_version_list, key=self.version_key)
            if current_verison != hightest_version:
                install = self.op('request anti-virus upgrade install version', value='latest', wait=True)
                return install
            else:
                logging.info(f'Anti-Virus is already up to date. Nothing to do.')
                return {'status': 'success',
                        'msg': 'Anti-Virus is already up to date. Nothing to do.'}

    def update_hostname(self, hostname):
        xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/hostname"
        element = f"<hostname>{hostname}</hostname>"
        return self.edit_xml(xpath, element)


class Firewall(PAN):
    # Firewall object using REST API
    valid_location = ['vsys', 'panorama-pushed', 'predefined', '']

    def __init__(self, base_url: str, **kwargs):
        super().__init__(base_url, **kwargs)
        self.model: str = self.SystemInfo.get('model')
        self.family: str = self.SystemInfo.get('family')
        self.serial: str = self.SystemInfo.get('serial')
        self.vsys_list: List[str] = self.get_vsys_list()

    def get_vsys_list(self) -> List[str]:
        """
        Fetches a list of virtual systems (vsys) configured on the firewall.

        Returns:
            List[str]: A list of vsys identifiers.
        """
        if self.SystemInfo.get('multi-vsys', 'off') == 'off':
            return ['vsys1']

        try:
            cmd_response = self.op('show system setting target-vsys')
            if cmd_response.get('status') == 'success':
                return cmd_response.get('result', [])
            else:
                # Log the error or raise an exception as appropriate
                raise ValueError("Failed to retrieve vsys list.")
        except Exception as e:
            # Log the exception or handle it as needed
            raise RuntimeError(f"Error retrieving vsys list: {e}")

    def connect_to_panorama(self, authkey: str, panorama_ip: str) -> str:
        """
        Connects this firewall to a Panorama management server using an auth key and the Panorama's IP address.

        Args:
            authkey (str): The authentication key for registering with Panorama.
            panorama_ip (str): The IP address of the Panorama server.

        Returns:
            str: success or error
        """
        xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/panorama/local-panorama"
        element = f'<panorama-server>{panorama_ip}</panorama-server>'

        try:
            add_panorama_result = self.set_xml(xpath, element)
            if add_panorama_result.get('status') == 'success':
                op_result = self.op('request authkey set', value=authkey)
                if op_result.get('status') == 'success':
                    return {'status':'success', 'msg': f'Added {self.serial} to Panorama {panorama_ip}.'}
                else:
                    error_msg = f"Failed to set authkey on {self.hostname}. Response: {op_result}"
                    logger.error(error_msg)
                    return {'status':'error', 'msg': error_msg}
            else:
                error_msg = f"Could not add Panorama server {panorama_ip} to firewall {self.hostname}. Response: {add_panorama_result}"
                logger.error(error_msg)
                return {'status':'error', 'msg': error_msg}
        except Exception as e:
            logger.exception(f"Unexpected error connecting {self.hostname} to Panorama {panorama_ip}: {e}")
            return {'status': 'error', 'msg': f'Unexpected error connecting {self.hostname} to Panorama {panorama_ip}, {e}.'}

    def upgrade_to_version(self, new_version: str):
        """
        Perform system upgrade of a firewall device to a specified software version of PAN-OS. The method checks the
        current version, determines if step upgrades are necessary, and handles download, installation, and reboot
        procedures as needed.

        Arguments:
            new_version (str): Target PAN-OS version to which the device should be upgraded.

        Returns:
            dict: A dictionary containing the status of the operation ('success' or 'failure') and a message indicating
            the result or any error encountered.

        """
        def download_and_install(v2: str):
            """
            Represents a firewall class that inherits from the PAN class. Provides functionality
            for upgrading the firewall to a specified version. The upgrade process involves
            downloading, installing the software version, and rebooting the device while checking
            the device's status during the reboot process.

            Attributes:
                None
            """
            logger.debug(f'Firewall {self.hostname} attempting to download version {v2}')
            op_download = self.op('request system software download version', value=v2, wait=True)
            logger.debug(f'Firewall {self.hostname} status of download operation: {op_download}')
            if op_download['status'] == 'success':
                op_install = self.op('request system software install version', value=v2, wait=True)
                logger.debug(f'Firewall {self.hostname} status of install operation: {op_install}')
                if op_install['status'] == 'success':
                    self.op(f'request restart system')
                    loop = 0
                    while True:
                        # Wait for firewall to complete rebooting
                        logger.info(f'Waiting for firewall {self.hostname} to come back after reboot.')
                        if loop == 0:
                            time.sleep(300)
                        else:
                            time.sleep(60)
                        try:
                            new_sysinfo = self.op('show system info')
                            if new_sysinfo.get('result'):
                                if new_sysinfo['status'] == 'success':
                                    # Make sure the current object's version attribute is updated.
                                    self.ver = self.ver_from_sw_version(self.SystemInfo['sw-version'])
                                    return {'status': 'success',
                                            'msg': f'Device {self.hostname} upgraded to {new_version}.'}
                        except requests.exceptions.ConnectionError:
                            # while the firewall is down, we will get this error.
                            loop += 1
                            continue
                        except requests.exceptions.ReadTimeout:
                            # The firewall is up, but autocommit is not yet done.
                            loop += 1
                            continue
                        loop += 1
                        if loop > 20:
                            return {'status': 'failure',
                                    'msg': f'Device {self.hostname} failed to come back after reboot.'}

        # Map the steps needed to upgrade from one major version to the next.
        upgrade_map = {'9.1': '10.0',
                       '10.0': '10.1',
                       '10.1': '10.2',
                       '10.2': '11.0'}

        if self.SystemInfo['sw-version'] == new_version:
            # the current and requested new version are the same, nothing to do.
            return {'status': 'success',
                    'msg': f'The device {self.hostname} is already at version {new_version}. Nothing to do.'}
        # Get current list of available images to download
        op_check = self.op('request system software check')
        if op_check['status'] == 'success':
            logger.debug(f'Firewall {self.hostname} status of check operation: success')
        else:
            logger.error(f'Firewall {self.hostname} status of check operation: {op_check}')
            return {'status': 'failure',
                    'msg': f'Device {self.hostname} failed to retrieve available software versions.'}

        v1_components = self.SystemInfo['sw-version'].split('.')
        v2_components = new_version.split('.')
        v1_major = v1_components[0] + '.' + v1_components[1]
        v2_major = v2_components[0] + '.' + v2_components[1]
        logger.debug(f'Attempting to upgrade {self.hostname} from {self.SystemInfo['sw-version']} to {new_version}.')
        if v1_major != v2_major:
            # as of PANOS 10.2 you no longer need to step upgrade.
            if float(v1_major) >= 10.2:
                logger.debug(f'Firewall {self.hostname} is at a version greater than or equal to 10.2.')
                v2 = f'{v2_major}.0'
                logger.debug(f'Firewall {self.hostname} is attempting to download to {v2}.')
                op_download = self.op('request system software download version', value=v2, wait=True)
                logger.debug(f'Result of download: {op_download}')
                if op_download['status'] == 'success':
                    result = download_and_install(new_version)
                    return result
            # We have to step upgrade to get to version 2
            while v1_major != v2_major:
                if upgrade_map.get(v1_major) == v2_major:
                    # The next version is the next major version, just download the major version, then download and install
                    # the minor version.
                    v2 = f'{upgrade_map[v1_major]}.0'
                    # download the next major version, no need to install it.
                    op_download = self.op('request system software download version', value=v2, wait=True)
                    if op_download['status'] == 'success':
                        # Download and install the new version
                        result = download_and_install(new_version)
                        return result
                    else:
                        error_message = 'Could not install new version of OS. Please upgrade manually.'
                        logger.error(error_message)
                        return {'status': 'failure',
                                'msg': error_message}
                else:
                    # Need to step upgrade to the new version, so keep downloading and installing major versions until
                    # we reach the final major version
                    next_version = f'{upgrade_map[v1_major]}.0'
                    result = download_and_install(next_version)
                    if result['status'] == 'success':
                        logger.info(f'Step upgrade to version {next_version} complete.')
                    else:
                        error_message = 'Could not install new version of OS. Please upgrade manually.'
                        logger.error(error_message)
                        return {'status': 'failure',
                                'msg': error_message}
                v1_major = upgrade_map[v1_major]
        else:
            # The two major version are equal, so just download and install the patch.
            logger.debug(f'Firewall {self.hostname} is already at the same major version as {new_version}. ')
            result = download_and_install(new_version)
            return result

    def sip_disable_alg(self) -> str:
        """
        Disables the SIP Application Layer Gateway (ALG) on the firewall.

        Returns:
            str: The status of the operation ('success' or 'error').
        """
        xpath = "/config/shared/alg-override/application/entry[@name='sip']"
        element = "<alg-disabled>yes</alg-disabled>"
        result = self.set_xml(xpath=xpath, element=element)

        if result.get('status') == 'success':
            return 'success'
        else:
            logging.error(f"Failed to disable SIP ALG. Response: {result}")
            return 'error'


class Panorama(PAN):
    # Panorama object using REST API
    valid_location = ['shared', 'device-group', 'predefined']

    def __init__(self, base_url: str, **kwargs):
        super().__init__(base_url, **kwargs)
        self.licensed_device_capacity: st = self.SystemInfo.get('licensed-device-capacity')
        self.model: str = self.SystemInfo.get('model')
        self.device_groups_list: Dict[str, Dict[str, str]] = self.get_device_groups()
        self.templates: Dict[str, str] = self.get_templates(stack=False)
        self.template_stacks: Dict[str, str] = self.get_templates(stack=True)
        self.serial: str = self.SystemInfo.get('serial')

    def get_device_groups(self) -> Optional[Dict[str, Dict[str, str]]]:
        """
        Retrieves a list of all device groups and their hierarchy from Panorama using the XML API.

        Returns:
            Optional[Dict[str, Dict[str, str]]]: A dictionary with the child DG as key and a dictionary containing
            the parent DG as value, or None if an error occurs.
        """
        cmd = self.op('show dg-hierarchy')
        if cmd.get('status') == 'success':
            dg_groups: Dict[str, Dict[str, str]] = {}
            dg_hierarchy = cmd.get('result', {}).get('dg-hierarchy', {}).get('dg', [])

            def process_dg(dg, parent='shared'):
                if isinstance(dg, list):
                    for child_dg in dg:
                        dg_groups[child_dg.get("@name")] = {'parent': parent}
                        # Recursive call to process nested device groups
                        process_dg(child_dg.get("dg", []), child_dg.get("@name"))
                elif isinstance(dg, dict):
                    dg_groups[dg.get("@name")] = {'parent': parent}
                    # Recursive call to process nested device groups
                    process_dg(dg.get("dg", []), dg.get("@name"))

            process_dg(dg_hierarchy)
            return dg_groups
        else:
            logging.error(f'Could not get device groups for Panorama.')
            return None

    def commit_all(self, **kwargs):

        def build_shared_policy(description, device_group_list, admin, force_template_values, include_template,
                                merge_with_candidate_cfg, validate_only):
            """
                Builds a shared policy XML structure with the given parameters.

                Parameters:
                - description (str): Description of the shared policy.
                - device_group_list (List[str]): List of device groups to be included.
                - admin (List[str]): List of admins to be included.
                - force_template_values (str): Whether to force template values.
                - include_template (str): Whether to include the template.
                - merge_with_candidate_cfg (str): Whether to merge with candidate config.
                - validate_only (str): Whether the operation is validated only.

                Returns:
                - str: A string representation of the XML structure for the shared policy.
                """
            shared_policy_elem = ET.Element('shared-policy')

            # Add description
            if description:
                ET.SubElement(shared_policy_elem, 'description').text = description

            # Dynamically add device groups and their entries
            device_group_elem = ET.SubElement(shared_policy_elem, 'device-group')
            for device_group in device_group_list:
                ET.SubElement(device_group_elem, 'entry', {'name': device_group})

            # Add admin elements
            admin_elem = ET.SubElement(shared_policy_elem, 'admin')
            for admin_name in admin:
                ET.SubElement(admin_elem, 'member').text = admin_name
            # Add other elements
            ET.SubElement(shared_policy_elem, 'force-template-values').text = force_template_values
            ET.SubElement(shared_policy_elem, 'include-template').text = include_template
            ET.SubElement(shared_policy_elem, 'merge-with-candidate-cfg').text = merge_with_candidate_cfg
            ET.SubElement(shared_policy_elem, 'validate-only').text = validate_only

            # Convert to string for inclusion in the final XML
            return ET.tostring(shared_policy_elem, encoding='unicode')

        def build_template_stack(description: str, admin: List[str], force_template_values: str,
                                 merge_with_candidate_cfg: str, validate_only: str, device: List[str],
                                 name_list: List[str]) -> str:
            """
                Constructs an XML structure representing a template stack configuration for Palo Alto Networks devices.

                This function creates a template stack element with specified details, including description,
                administrators, device members, and named entries. The resulting XML structure is intended for use
                in configuring template stacks on Palo Alto Networks firewalls or Panorama.

                Parameters:
                - description (str): A text description of the template stack.
                - admin (List[str]): A list of administrator names to be included as members.
                - force_template_values (str): A string ('yes' or 'no') indicating whether to force template values.
                - merge_with_candidate_cfg (str): A string ('yes' or 'no') indicating whether to merge this configuration
                  with the candidate configuration.
                - validate_only (str): A string ('yes' or 'no') indicating whether the operation should only validate
                  the configuration without applying it.
                - device (List[str]): A list of device names to be included in the template stack.
                - name_list (List[str]): A list of names for entries within the template stack.

                Returns:
                - str: A string representation of the XML structure for the template stack configuration.

                Note:
                - The 'admin' parameter's members are added under the 'admin' element, each as a 'member' sub-element.
                - Devices are added under a 'device' element, each as a 'member' sub-element.
                - Named entries are added directly under the root 'template_stack' element as 'entry' elements with a 'name' attribute.
                """
            template_stack_elem = ET.Element('template_stack')

            # Add description
            if description:
                ET.SubElement(template_stack_elem, 'description').text = description

            # Add admin elements
            admin_elem = ET.SubElement(shared_policy_elem, 'admin')
            for admin_name in admin:
                ET.SubElement(admin_elem, 'member').text = admin_name

            # Add other elements
            ET.SubElement(template_stack_elem, 'force-template-values').text = force_template_values
            ET.SubElement(template_stack_elem, 'merge-with-candidate-cfg').text = merge_with_candidate_cfg
            ET.SubElement(template_stack_elem, 'validate-only').text = validate_only

            # Dynamically add devices
            device_elem = ET.SubElement(template_stack_elem, 'device')
            for device_member in device:
                ET.SubElement(device_elem, 'member').text = device_member

            # Dynamically add names as entry elements
            for name in name_list:
                ET.SubElement(template_stack_elem, 'entry', {'name': name})

            # Convert to string for inclusion in the final XML
            return ET.tostring(template_stack_elem, encoding='unicode')

        def build_log_collector_config(description, log_collector_group):
            # Create the root element for the log collector config
            log_collector_config_elem = ET.Element('log-collector-config')

            # Add description
            if description:
                ET.SubElement(log_collector_config_elem, 'description').text = description

            # Add log collector group if specified
            if log_collector_group:
                ET.SubElement(log_collector_config_elem, 'log-collector-group').text = log_collector_group

            # Convert to string for inclusion in the final XML
            return ET.tostring(log_collector_config_elem, encoding='unicode')

        root = ET.Element('commit-all')

        # Check and build log collector config if applicable
        if kwargs.get('log_collector_config', False):
            log_collector_xml = build_log_collector_config(
                description=kwargs.get('description', ''),
                log_collector_group=kwargs.get('log_collector_group', '')
            )
            root.append(ET.fromstring(log_collector_xml))

        # Check and build shared policy if applicable
        if kwargs.get('shared_policy', False):
            shared_policy_xml = build_shared_policy(
                description=kwargs.get('description', ''),
                device_group_list=kwargs.get('device_group_list', []),
                admin=kwargs.get('admin', []),
                force_template_values=kwargs.get('force_template_values', 'no'),
                include_template=kwargs.get('include_template', 'yes'),
                merge_with_candidate_cfg=kwargs.get('merge_with_candidate_cfg', 'yes'),
                validate_only=kwargs.get('validate_only', 'no')
            )
            root.append(ET.fromstring(shared_policy_xml))

        # Check and build template stack if applicable
        if kwargs.get('template_stack', False):
            template_stack_xml = build_template_stack(
                description=kwargs.get('description', ''),
                admin=kwargs.get('admin', []),
                force_template_values=kwargs.get('force_template_values', 'no'),
                merge_with_candidate_cfg=kwargs.get('merge_with_candidate_cfg', 'yes'),
                validate_only=kwargs.get('validate_only', 'no'),
                device=kwargs.get('device', []),
                name_list=kwargs.get('name', [])
            )
            root.append(ET.fromstring(template_stack_xml))

        params = {
            'key': self.api_key,
            'type': 'commit',
            'action': 'all',
            'cmd': ET.tostring(root, encoding='unicode')
        }
        response = self.xml_request(params=params)
        if response.get('response', {}).get('@status', {}) == 'success':
            return response.get('response', {}).get('result', {}).get('job')

    def get_device_license_info(self) -> Tuple[List[str], List[Dict[str, any]]]:
        """
        Retrieves license information for all devices managed by Panorama.

        Returns:
            Tuple[List[str], List[Dict[str, any]]]: A tuple containing a list of column headers and a list of dictionaries
                                                     with license information for each device.
        """
        report = []
        columns = [
            'serial', 'device name', 'support', 'Threat Prevention', 'GlobalProtect Gateway',
            'PAN-DB URL Filtering', 'DNS Security', 'WildFire License', 'Advanced WildFire License', 'SD WAN',
            'Advanced URL Filtering', 'Premium Partner', 'Device Management License'
        ]
        op_response = self.op('request batch license info')

        if op_response.get('status') == 'success':
            list_of_devices = op_response.get('result', {}).get('devices', {}).get('entry', [])

            for device in list_of_devices:
                licenses = {'serial': device.get('serial-no'), 'device name': device.get('devicename')}
                entry = device.get('licenses', {}).get('entry')
                # Check if 'entry' is a dictionary and convert it to a list if it is
                if isinstance(entry, dict):
                    entry = [entry]
                for pan_license in entry:
                    license_type = pan_license.get('type')
                    expiry_date = pan_license.get('expiry-date')

                    if license_type == 'SUP':
                        licenses['support'] = expiry_date
                    elif license_type == 'SUB' or 'RENSUB':
                        licenses[pan_license.get('@name')] = expiry_date
                report.append(licenses)

        return columns, report

    def get_fw_name_list(self) -> List[str]:
        """
        Retrieves a list of all connected firewall hostnames managed by Panorama.

        Returns:
            List[str]: A list containing the hostnames of all connected firewalls.
        """
        op_response = self.op('show devices connected')
        firewall_name_list = []

        if op_response.get('response', {}).get('@status') == 'success':
            devices = op_response.get('response', {}).get('result', {}).get('devices', {}).get('entry', [])

            for device in devices:
                hostname = device.get('hostname')
                if hostname:
                    firewall_name_list.append(hostname)

        return firewall_name_list

    def get_firewall_connected(self) -> List[Dict[str, str]]:
        """
        Retrieves a list of all connected firewalls with their details from Panorama.

        Returns:
            List[Dict[str, str]]: A list of dictionaries, each containing details of a firewall.
        """
        connected = self.op('show devices connected')
        if connected.get('status') == 'success':
            fw_list = connected.get('result', {}).get('devices', {}).get('entry', [])
            return [
                {'serial': fw.get('serial', ''),
                 'ip_address': fw.get('ip-address', ''),
                 'hostname': fw.get('hostname', ''),
                 'model': fw.get('model', '')}
                for fw in fw_list
            ]
        return []

    def get_panorama_authkey(self, existing_key_name: Optional[str] = None, new_key_name: str = 'key1') -> Optional[str]:
        """
        Retrieves or generates an authorization key for connecting a firewall to Panorama.

        Parameters:
            existing_key_name (Optional[str]): Name of an existing auth key in Panorama. If provided, the function will
                                               try to retrieve this key if it's valid.
            new_key_name (str): Name of the new key to create. This parameter is used if a new key needs to be generated.

        Returns:
            Optional[str]: The auth key if successful, None otherwise.
        """
        authkey = None

        def add_key(name: str) -> None:
            nonlocal authkey
            op = self.op(f'request authkey add name', value=name)
            if op.get('status') == 'success':
                authkey = op.get('result', {}).get('authkey')

        def list_keys() -> list:
            op = self.op('request authkey list', value='*')
            if op.get('status') == 'success':
                authkey = op.get('result', {}).get('authkey', None)
                if authkey is None:
                    return []  # Handle None case by returning an empty list
                entry = authkey.get('entry', [])
                if isinstance(entry, list):
                    return entry
                else:
                    return [entry]
            return []

        if existing_key_name:
            op = self.op(f'request authkey list', value=existing_key_name)
            if op.get('status') == 'success':
                authkey_entry = op.get('result', {}).get('authkey', {}).get('entry', {})
                lifetime = authkey_entry.get('lifetime')
                count = authkey_entry.get('count')
                if int(lifetime) > 600 and int(count) > 1:
                    return authkey_entry.get('key')
                else:
                    self.op(f'request authkey delete', value=existing_key_name)

        add_key(new_key_name if not authkey else new_key_name)

        # After adding a new key or if no existing key was found, validate and return the new key
        for key in list_keys():
            if int(key.get('lifetime', 0)) > 600 and int(key.get('count', 0)) > 1 and key.get('name') == new_key_name:
                op_list_key = self.op(f'request authkey list', value=new_key_name)
                return op_list_key.get('result', {}).get('authkey', {}).get('entry', {}).get('key')

        return authkey

    def add_device(self, serial: str) -> str:
        """
        Adds a device to Panorama using the specified serial number.

        Parameters:
            serial (str): Serial number of the device to add to Panorama.

        Returns:
            str: The status of the operation ('success' or 'error').
        """
        # Ensure the serial number is properly formatted for XML
        serial_formatted = f"'{serial}'"
        xpath = '/config/mgt-config/devices'
        element = f'<entry name={serial_formatted}/>'

        response = self.set_xml(xpath, element)

        # Check the response status and return it
        return response.get('status', 'error')

    def get_templates(self, stack: bool) -> list:
        """
        Returns a list of template names or template stack names based on the 'stack' parameter.
        Template Stacks vs Templates are determined if the key 'template-stack' is 'yes' or 'no'.

        :param stack: A boolean indicating whether to return template stack names (True) or template names (False).
        :return: A list of template names or template stack names.
        """
        result: dict = self.op('show templates')
        template_list: list = []
        if result.get('status') == 'success':
            for entry in result.get('result', {}).get('templates', {}).get('entry', []):
                if stack and entry.get('template-stack', 'no') == 'yes':
                    # Append the template stack name to the template_list
                    template_list.append(entry.get('@name'))
                elif not stack and entry.get('template-stack', 'no') == 'no':
                    # Append the template name to the template_list
                    template_list.append(entry.get('@name'))
        return template_list

class PanProtocol(Protocol):
    # Define common interface that all ObjectTab subclasses must have
    location: str
    name: str
    PANDevice: Panorama | Firewall
    loc: str
    device_group: str
    description: str


# This creates a type variable that can be any subclass of Object or Policy that fits the PanProtocol
T = TypeVar('T', bound='PanProtocol')


class Base:
    def __init__(self, PANDevice: Union[Panorama, Firewall], **kwargs):
        self.PANDevice: Union[Panorama, Firewall] = PANDevice
        self.entry: Dict = {}
        self.max_name_length: int = kwargs.get('max_name_length', 31)
        self.max_description_length: int = kwargs.get('max_description_length', 255)
        self.valid_location = self.PANDevice.valid_location
        self.composite_keys: Set[str] = set()  # Stores composite keys for quick existence checks
        self.location = kwargs.get('location') or self.determine_location(kwargs)
        self.loc = self.determine_location(kwargs)
        self.name: str = kwargs.get('name')
        self.description: str = kwargs.get('description')
        self.tag: Dict[str, List[str]] = kwargs.get('tag')
        self.loc = self.determine_location(kwargs)
        self.device_group: str = kwargs.get('device_group')
        self.template: str = kwargs.get('template')
        self.template_stack: str = kwargs.get('template_stack')
        self.vsys = kwargs.get('vsys')
        self.pre_post: str = None

    def __str__(self):
        return self.name

    def __repr__(self):
        class_name = self.__class__.__name__
        return f"{class_name}(name={self.name!r}, location={self.location!r})"

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        if value:
            if not self.PANDevice.valid_name(value, self.max_name_length):
                raise ValueError(f"Provided name '{value}' is invalid.")
            self._name = value
            self.entry.update({'@name': self._name})
        else:
            self._name = None

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str) -> None:
        if value:
            if not isinstance(value, str):
                raise TypeError("Description must be a string.")

            if len(value) > self.max_description_length:
                raise ValueError(f"Description exceeds the maximum length of {self.max_description_length} characters.")

            self._description = value
            self.entry.update({'description': self._description})

    @property
    def location(self) -> str:
        return self._location

    @location.setter
    def location(self, value: str) -> None:
        if isinstance(self.PANDevice, Firewall):
            self._location = value
        elif value not in self.valid_location:
            raise ValueError(f"Invalid location. Must be one of: {self.valid_location}")
        self._location = value

    @property
    def tag(self) -> Dict[str, List[str]]:
        return self._tag

    @tag.setter
    def tag(self, value: Dict[str, List[str]]) -> None:
        if value:
            self.validate_member_dict(value, 'tag')
            self._tag = value
            self.entry.update({'tag': value})

    @property
    def device_group(self) -> str:
        return self._device_group

    @device_group.setter
    def device_group(self, value: str) -> None:
        if value:
            if not isinstance(self.PANDevice, Panorama):
                raise TypeError("device_group can only be set for Panorama devices.")

            if self.location != 'device-group':
                raise ValueError("device_group can only be set when location is 'device-group'.")

            if value not in self.PANDevice.device_groups_list:
                raise ValueError(f"Invalid device group: {value}. Must be one of: {self.PANDevice.device_group_list}")

            self._device_group = value

    @property
    def vsys(self) -> str:
        return self._vsys

    @vsys.setter
    def vsys(self, value: str) -> None:
        if value:
            # Check if the PANDevice is of type Firewall
            # if not isinstance(self.PANDevice, Firewall):
            #     raise TypeError("vsys can only be set for Firewall devices.")

            # # Check if the location is 'vsys' or 'panorama-pushed'
            # if self.location not in ['vsys', 'panorama-pushed']:
            #     raise ValueError("vsys can only be set when location is 'vsys' or 'panorama-pushed'.")

            # Check if the provided vsys value is in the PANDevice.vsys_list
            # if value not in self.PANDevice.vsys_list:
            #     raise ValueError(f"Invalid vsys: {value}. Must be one of: {self.PANDevice.vsys_list}")

            self._vsys = value
            self.entry.update({'vsys': value})

    @staticmethod
    def validate_member_dict(value: Dict[str, List[str]], attribute_name: str) -> None:
        if not isinstance(value, dict):
            raise TypeError(f"{attribute_name} must be a dictionary.")

        if 'member' not in value:
            raise ValueError(f"Dictionary for {attribute_name} must contain the 'member' key.")

        if not isinstance(value['member'], list):
            raise TypeError(f"'member' key in {attribute_name} should be associated with a list.")

        if not all(isinstance(item, str) for item in value['member']):
            raise ValueError(f"All items in the 'member' list of {attribute_name} must be strings.")

    def determine_location(self, kwargs: Dict[str, Any]) -> str:
        """Determines location based on PANDevice type and kwargs."""
        if isinstance(self.PANDevice, Panorama):
            return kwargs.get('device_group', 'shared')
        elif isinstance(self.PANDevice, Firewall):
            return kwargs.get('vsys', '')
        return 'shared'

    @staticmethod
    def _create_composite_key(location: str, name: str) -> str:
        """Creates a composite key based on location and name."""
        return f"{location}:{name}"

    def add_cache(self, pan_object: T) -> None:
        """Adds an object to the cache if not already present, using a composite key."""
        # Determine the appropriate location for the composite key
        location_for_key = pan_object.location if self.location == 'shared' else pan_object.loc

        # Create the composite key using the determined location
        composite_key = self._create_composite_key(location_for_key, pan_object.name)
        if composite_key not in self.composite_keys:
            self.pan_objects[composite_key] = pan_object
            self.composite_keys.add(composite_key)

    def exists_cache(self, location, name):
        """Checks if a pan_object exists in the cache based on its composite key."""
        composite_key = self._create_composite_key(location, name)
        return composite_key in self.composite_keys

    def get_cache(self, location, name):
        """Returns the pan_object object for the given location and name if it exists."""
        composite_key = self._create_composite_key(location, name)
        return self.pan_objects.get(composite_key)

    def clear_cache(self):
        """Clears the cache."""
        self.pan_objects.clear()
        self.composite_keys.clear()

    def refresh_cache(self):
        """Fetches all address objects and stores them in the cache."""
        data = self.get()
        if data:
            for entry in data:
                # Dynamically create an instance of the subclass from which this method was called
                instance = self.__class__(**entry)
                self.add_cache(instance)

    def _build_params(self) -> Dict[str, str]:
        """
        Builds the parameter dictionary for the API request based on the object's state.

        Returns:
            Dict[str, str]: The parameters for the API request.
        """
        params = {'location': self.location} if self.location else {}
        if self.name:
            params['name'] = self.name
        if self.location in ['template', 'vsys']:
            params.update({self.location: self.loc})
        if self.location == 'device-group':
            params.update({self.location: self.device_group})
        if type(self).__name__ == 'Zones' and hasattr(self, 'vsys'):
            params['vsys'] = self.vsys

        return params

    def get(self) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieve details for the current network tab based on its name and location.

        Returns:
            Optional[List[Dict[str, Any]]]: A list of entries from the API response or None if an error occurs.
        """
        params = self._build_params()
        try:
            response = self.rest_request('GET', params=params)
        except requests.exceptions.RequestException as e:
            logging.error(f'Failed to get {self.__class__.__name__}: {e}')
            raise Exception(f'Network request failed: {e}') from e

        if response.get('@status') != 'success':
            logging.error(f'API returned error: {response.get("message", "Unknown error")}')
            return None

        return response.get('result', {}).get('entry')

    def get_all(self) -> List[Dict[str, Any]]:
        """
        Get a list of all elements in this section.

        Returns:
            List[Dict[str, Any]]: A list of entries from the API response.

        Raises:
            Exception: If the API request fails or returns an error status.
        """
        params = self._build_params()

        try:
            response = self.rest_request('GET', params=params)
        except requests.exceptions.RequestException as e:
            logging.error(f'Network request failed: {e}')
            raise Exception(f'Network request failed: {e}') from e

        if response.get('@status') != 'success':
            error_message = response.get('message', 'Unknown error')
            logging.error(error_message)
            raise Exception(f'API request failed: {error_message}')

        return response.get('result', {}).get('entry', [])

    def create(self) -> bool:
        """
        Attempts to create a new entry in the network configuration.

        Returns:
            bool: True if the entry was successfully created, False otherwise.

        Raises:
            NetworkRequestError: If there's an issue with the network request.
            APIResponseError: If the API returns a non-success status.
        """
        params = self._build_params()
        data = {'entry': self.entry}
        try:
            response = self.rest_request('POST', params=params, json=data)
        except requests.exceptions.RequestException as e:
            logging.error(f'Failed to create {self.__class__.__name__}: {e}')
            raise NetworkRequestError(f'Network request failed for {self.PANDevice.base_url}', {'error': str(e)})

        if response.get('@status') != 'success':
            logging.error(f'API returned error during create: message: {response.get("message", "Unknown error")}, details: {response.get("details", "Unknown error")}')
            raise APIResponseError('API request did not return success during create', response)

        return True

    def edit(self) -> bool:
        """
        Attempts to edit an existing entry in the network configuration.

        Returns:
            bool: True if the entry was successfully edited.

        Raises:
            NetworkRequestError: If there's an issue with the network request.
            APIResponseError: If the API returns a non-success status.
        """
        params = self._build_params()
        data = {'entry': self.entry}

        try:
            response = self.rest_request('PUT', params=params, json=data)
        except requests.exceptions.RequestException as e:
            logging.error(f'Failed to edit {self.__class__.__name__}: {e}')
            raise NetworkRequestError(f'Network request failed for {self.base_url}', {'error': str(e)})

        if response.get('@status') != 'success':
            logging.error(f'API returned error during edit: {response.get("message", "Unknown error")}')
            raise APIResponseError('API request did not return success during edit', response)

        return True

    def delete(self) -> bool:
        """
        Attempts to delete an existing entry in the network configuration.

        Returns:
            bool: True if the entry was successfully deleted.

        Raises:
            NetworkRequestError: If there's an issue with the network request.
            APIResponseError: If the API returns a non-success status.
        """
        params = self._build_params()

        try:
            response = self.rest_request('DELETE', params=params)
        except requests.exceptions.RequestException as e:
            logging.error(f'Failed to delete {self.__class__.__name__}: {e}')
            raise NetworkRequestError(f'Network request failed for {self.base_url}', {'error': str(e)})

        if response.get('@status') != 'success':
            logging.error(f'API returned error during delete: {data.get("message", "Unknown error")}')
            raise APIResponseError('API request did not return success during delete', response)

        return True

    def rename(self, newname: str) -> bool:
        """
        Attempts to rename an existing entry in the network configuration.

        Parameters:
            newname (str): The new name for the item.

        Returns:
            bool: True if the item was successfully renamed.

        Raises:
            ValueError: If the new name does not meet validation criteria.
            NetworkRequestError: If there's an issue with the network request.
            APIResponseError: If the API returns a non-success status.
        """
        # Validate the new name
        if not self.valid_name(newname, self.max_name_length):
            raise ValueError(f'Invalid new name: {newname}')

        params = self._build_params()
        params.update({'newname': newname})

        try:
            response = self.rest_request('POST', params=params)
        except requests.exceptions.RequestException as e:
            logging.error(f'Failed to rename {self.__class__.__name__} {self.name} to {newname}: {e}')
            raise NetworkRequestError(f'Network request failed for {self.base_url}', {'error': str(e)})

        if response.get('@status') != 'success':
            logging.error(f'API returned error during rename: {response.get("message", "Unknown error")}')
            raise APIResponseError('API request did not return success during rename', response)

        return True

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

        entry: List[Dict[str, Any]] = self.get()
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







