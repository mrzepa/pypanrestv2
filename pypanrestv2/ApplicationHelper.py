class Operator:
    def __init__(self, context):
        self.context = context

    @property
    def context(self) -> str:
        return self._context

    @context.setter
    def context(self, value):
        if not isinstance(value, str):
            raise ValueError("Context must be a string.")


class PatternMatchOperator(Operator):
    def __init__(self, context, pattern, qualifier):
        super().__init__(context)
        self.pattern = pattern
        self.qualifier = self.initialize_qualifier(qualifier)

    def initialize_qualifier(self, qualifier):
        if 'entry' in qualifier:
            return [{entry['@name']: entry['value']} for entry in qualifier['entry']]
        return []

    def to_dict(self):
        return {
            'type': 'pattern-match',
            'context': self.context,
            'pattern': self.pattern,
            'qualifier': {'entry': self.qualifier},
        }


class GreaterThanOperator(Operator):
    def __init__(self, context, value, qualifier):
        super().__init__(context)
        self.value = value
        self.validate_value(value)
        self.qualifier = self.initialize_qualifier(qualifier)

    def validate_value(self, value):
        if not isinstance(value, int) or not (0 <= value <= 4294967295):
            raise ValueError("Value must be an integer between 0 and 4294967295.")

    def initialize_qualifier(self, qualifier):
        if 'entry' in qualifier:
            return [{entry['@name']: entry['value']} for entry in qualifier['entry']]
        return []

    def to_dict(self):
        return {
            'type': 'greater-than',
            'context': self.context,
            'value': self.value,
            'qualifier': {'entry': self.qualifier},
        }


class LessThanOperator(Operator):
    def __init__(self, context, value, qualifier):
        super().__init__(context)
        self.value = value
        self.validate_value(value)
        self.qualifier = self.initialize_qualifier(qualifier)

    def validate_value(self, value):
        if not isinstance(value, int) or not (0 <= value <= 4294967295):
            raise ValueError("Value must be an integer between 0 and 4294967295.")

    def initialize_qualifier(self, qualifier):
        if 'entry' in qualifier:
            return [{entry['@name']: entry['value']} for entry in qualifier['entry']]
        return []

    def to_dict(self):
        return {
            'type': 'less-than',
            'context': self.context,
            'value': self.value,
            'qualifier': {'entry': self.qualifier},
        }


class EqualToOperator(Operator):
    def __init__(self, context, position, mask, value):
        super().__init__(context)
        self.position = position
        self.mask = mask
        self.value = value
        self.validate_position(position)
        self.validate_mask(mask)
        self.validate_value(value)

    def validate_position(self, position):
        if not isinstance(position, str) or len(position) > 127:
            raise ValueError("Position must be a string up to 127 characters long.")

    def validate_mask(self, mask):
        if not isinstance(mask, str) or not re.match(r'^0[xX][0-9A-Fa-f]{8}$', mask):
            raise ValueError("Mask must be a 4-byte hex value.")

    def validate_value(self, value):
        if not isinstance(value, str) or len(value) > 10:
            raise ValueError("Value must be a string up to 10 characters long.")

    def to_dict(self):
        return {
            'type': 'equal-to',
            'context': self.context,
            'position': self.position,
            'mask': self.mask,
            'value': self.value,
        }

class OrConditionEntry:
    def __init__(self, name, operator_data):
        self.validate_name(name)
        self.name = name
        self.operator = self.initialize_operator(operator_data)

    def validate_name(self, name):
        if not isinstance(name, str) or len(name) > 31:
            raise ValueError("Invalid name in or-condition entry.")

    def initialize_operator(self, operator_data):
        if not isinstance(operator_data, dict):
            raise ValueError("Operator data must be a dictionary.")

        operator_type = operator_data.get('type')
        if operator_type == 'pattern-match':
            return PatternMatchOperator(context=operator_data.get('context'),
                                        pattern=operator_data.get('pattern'),
                                        qualifier=operator_data.get('qualifier'))
        elif operator_type == 'greater-than':
            return GreaterThanOperator(context=operator_data.get('context'),
                                       value=operator_data.get('value'),
                                       qualifier=operator_data.get('qualifier'))
        elif operator_type == 'less-than':
            return GreaterThanOperator(context=operator_data.get('context'),
                                       value=operator_data.get('value'),
                                       qualifier=operator_data.get('qualifier'))
        elif operator_type == 'equal-to':
            return EqualToOperator(context=operator_data.get('context'),
                                   position=operator_data.get('position'),
                                   mask=operator_data.get('mask'),
                                   value=operator_data.get('value'))
        else:
            raise ValueError(f"Unsupported operator type: {operator_type}")

    def to_dict(self):
        # Convert the OrConditionEntry instance to a dictionary format
        or_condition_dict = {
            'name': self.name,
            # Include operator serialization here once operator.to_dict() is defined
            'operator': self.operator.to_dict() if self.operator else None,
        }
        return or_condition_dict

class AndConditionEntry:
    def __init__(self, name, or_condition=None):
        self.validate_name(name)
        self.name = name
        self.or_condition = self.initialize_or_condition(or_condition)

    def validate_name(self, name):
        if not isinstance(name, str) or len(name) > 31:
            raise ValueError("Invalid name in and-condition entry.")
        # Ensures the name consists only of allowed characters
        if not all(char.isalnum() or char in "._-" for char in name):
            raise ValueError("Name in and-condition entry contains invalid characters.")

    def initialize_or_condition(self, or_condition):
        if or_condition and 'entry' in or_condition:
            return [OrConditionEntry(**entry) for entry in or_condition['entry']]
        return []

    def to_dict(self):
        # Convert the AndConditionEntry instance to a dictionary format
        and_condition_dict = {
            'name': self.name,
            # Serialize or-condition if it's present
            'or-condition': {'entry': [condition.to_dict() for condition in self.or_condition] if self.or_condition else None},
        }
        return and_condition_dict


class SignatureEntry:
    def __init__(self, name, comment="", scope="protocol-data-unit", order_free="no", and_condition=None):
        self.validate_name(name)
        self.name = name
        self.comment = comment
        self.scope = self.validate_scope(scope)
        self.order_free = self.validate_order_free(order_free)
        self.and_condition = self.initialize_and_condition(and_condition)

    def to_dict(self):
        # Convert the SignatureEntry instance to a dictionary format suitable for inclusion in self.entry
        signature_dict = {
            'name': self.name,
            'comment': self.comment,
            'scope': self.scope,
            'order-free': self.order_free,
            'and-condition': {'entry': [condition.to_dict() for condition in self.and_condition] if self.and_condition else None},
        }
        return signature_dict

    def validate_name(self, name):
        if not isinstance(name, str) or len(name) > 31 or not all(char.isalnum() or char in "._-" for char in name):
            raise ValueError("Invalid name for signature entry.")

    def validate_scope(self, scope):
        if scope not in ["protocol-data-unit", "session"]:
            raise ValueError("Invalid scope value.")
        return scope

    def validate_order_free(self, order_free):
        if order_free not in ["yes", "no"]:
            raise ValueError("Invalid order-free value.")
        return order_free