"""JSON schemas for Hermes model tools."""

PREPARE_SCHEMA = {
    "type": "object",
    "properties": {
        "project_id": {
            "type": "string",
            "description": "Operator-registered project identifier.",
        },
        "task": {
            "type": "string",
            "description": "Bounded task text without credentials or private data.",
        },
        "include": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 256,
            "description": "Explicit project-relative files or directories; '.' is forbidden.",
        },
    },
    "required": ["project_id", "task", "include"],
    "additionalProperties": False,
}

STATUS_SCHEMA = {
    "type": "object",
    "properties": {
        "handoff_id": {
            "type": "string",
            "description": "Controller-generated handoff identifier.",
        }
    },
    "required": ["handoff_id"],
    "additionalProperties": False,
}

VERIFY_SCHEMA = {
    "type": "object",
    "properties": {
        "handoff_id": {
            "type": "string",
            "description": "Previously approved handoff identifier.",
        }
    },
    "required": ["handoff_id"],
    "additionalProperties": False,
}
