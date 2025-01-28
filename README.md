# PyPanRestV2

**PyPanRestV2** is a Python library designed to simplify interactions with Palo Alto Networks firewalls and Panorama via their REST API. It provides a higher level of abstraction, allowing users to manage firewalls and Panorama without needing to construct REST requests manually or work with XML for areas of the firewall configuration that still require it.

---

## Features

- **High-Level Abstraction**: Simplifies interaction with the Palo Alto Networks API.
- **Support for Firewalls and Panorama**: Manage both individual firewalls and Panorama devices.
- **REST API Integration**: Allows seamless communication with devices.
- **Convenient Pythonic Objects**: Intuitive Python objects for interacting with specific sections of Palo Alto firewall configurations.

---

## Installation

To include `PyPanRestV2` in your project, you can clone the repository:

```bash
git clone https://github.com/wellhealthtechnologies/PyPanRestV2.git
```

Once cloned, ensure required dependencies are installed (if applicable).

---

## Basic Usage

### Import the Required Classes
Start by importing the necessary classes from the library:

```python
from pypantrestv2 import Firewall, Panorama
```

### Connect to a Firewall or Panorama Device
Create a `Firewall` or `Panorama` object by providing the required connection details:

For a **Firewall**:
```python
firewall = Firewall(base_url="192.168.1.1", api_key="12345")
```

For **Panorama**:
```python
panorama = Panorama(base_url="192.168.2.1", username="admin", password="my_password")
```

### Interact with Specific Sections of the Device
Once connected, create an object representing the section of the firewall or Panorama device you want to manage. For example, to interact with the **Security Policies**:

```python
from pypanrestv2.Policies import SecurityRules
security_policy = SecurityRules(firewall, name='rule1')
# Add your logic to manage security policies.
# if this is an existing rule you can do stuff like
security_policy.refresh() # to get the rule from the firewall

```

---

## Repository

Visit the project's GitHub repository for source code, documentation, enhancements, and contributions:

[PyPanRestV2 Repository on GitHub](https://github.com/wellhealthtechnologies/PyPanRestV2.git)

---

## Requirements

- **Python 3.12+** (or higher)
- **Palo Alto Devices** or Panorama
- Python modules listed in requirements.txt

---

## THIS IS A WORK IN PROGRESS
Not section of the firewall or panorama has been enumerated, and they change with every new PanOS version.

## Contributing

Contributions are welcome! If you want to report issues, request features, or contribute to the library:

1. Fork the repository.
2. Create a feature branch: `git checkout -b my-feature`.
3. Commit your changes: `git commit -m "Add detailed description of changes"`.
4. Push to the branch: `git push origin my-feature`.
5. Submit a pull request.

Be sure to check the documentation, if provided, before starting contributions.

---

## License

This project is licensed under the MIT. See the [LICENSE](./https://opensource.org/license/mit) file for details.

---

## Author

Mark Rzepa
mark@rzepa.com

---
