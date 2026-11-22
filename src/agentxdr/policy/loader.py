"""Declarative YAML policy loader for AgentXDR."""

from __future__ import annotations

from pathlib import Path
from typing import Union

from agentxdr.models.policy import PolicySchema


def load_policy_yaml(source: Union[str, Path]) -> PolicySchema:
    """Load, parse, and validate a PolicySchema from a YAML string or file path.

    Parameters
    ----------
    source: Union[str, Path]
        A YAML string content or a filesystem Path / path string pointing to a policy file.

    Returns
    -------
    PolicySchema
        Validated PolicySchema instance.

    Raises
    ------
    FileNotFoundError
        If a provided file path does not exist.
    ValueError / ValidationError
        If the YAML content is malformed or violates the policy schema.
    """
    if isinstance(source, Path):
        return PolicySchema.from_yaml_file(source)

    if isinstance(source, str):
        if not source.strip():
            raise ValueError("YAML content cannot be empty")
        # If the string does not contain newlines, test if it points to an existing file
        if "\n" not in source:
            p = Path(source)
            if p.is_file():
                return PolicySchema.from_yaml_file(p)
        return PolicySchema.from_yaml_str(source)

    raise TypeError(f"Expected str or Path, got {type(source).__name__}")
