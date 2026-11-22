"""MCP Tool Schema Registry — canonical SHA-256 pinning for MCP tool schemas."""

from __future__ import annotations

import hashlib
import json
from typing import Dict, Optional, Tuple

from agentxdr.models.policy import PolicySchema


class McpSchemaRegistry:
    """Registry for verified MCP tool schema hashes.

    Prevents schema substitution attacks (ASI04) by pinning the canonical
    SHA-256 of each approved tool's name + description + inputSchema.
    """

    def __init__(self) -> None:
        self._registry: Dict[str, str] = {}  # tool_name -> expected_hash

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def compute_tool_hash(tool: dict) -> str:
        """Compute the canonical SHA-256 hash for a tool descriptor.

        The canonical form includes only ``name``, ``description``, and
        ``inputSchema`` so that irrelevant metadata fields do not affect
        the pinned digest.
        """
        canonical = json.dumps(
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "inputSchema": tool.get("inputSchema", {}),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Registry management
    # ------------------------------------------------------------------

    def register(self, tool_name: str, expected_hash: str) -> None:
        """Add or update a pinned hash entry for *tool_name*."""
        self._registry[tool_name] = expected_hash

    @classmethod
    def load_from_policy(cls, policy: PolicySchema) -> "McpSchemaRegistry":
        """Build a registry from the ``tools`` list in *policy*.

        Only tools that carry a non-None ``schema_sha256`` are pinned.
        """
        registry = cls()
        for tool_policy in policy.tools:
            if tool_policy.schema_sha256 is not None:
                registry.register(tool_policy.name, tool_policy.schema_sha256)
        return registry

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_tool(self, tool: dict) -> Tuple[bool, Optional[str]]:
        """Verify that *tool*'s computed hash matches the pinned hash.

        Returns
        -------
        (is_verified, expected_hash)
            ``is_verified`` is ``True`` iff the computed hash equals the
            registered hash.  ``expected_hash`` is ``None`` when the tool
            name is not in the registry (unregistered), in which case
            ``is_verified`` is also ``False``.
        """
        tool_name: str = tool.get("name", "")
        if tool_name not in self._registry:
            return False, None

        expected = self._registry[tool_name]
        computed = self.compute_tool_hash(tool)
        return (computed == expected), expected
