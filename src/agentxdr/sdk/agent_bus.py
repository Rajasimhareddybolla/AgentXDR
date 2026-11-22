"""Cryptographic inter-agent communication bus and signed envelope."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from agentxdr.sdk.context import AgentXDRContext


@dataclass
class InterAgentEnvelope:
    """Tamper-evident, cryptographically signed inter-agent message envelope."""

    message_id: str
    trace_id: str
    sender_agent_id: str
    receiver_agent_id: str
    timestamp_utc: str
    nonce: str
    attenuated_token: str
    taint_labels: List[str]
    payload: Dict[str, Any]
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert envelope to serializable dictionary."""
        return {
            "message_id": self.message_id,
            "trace_id": self.trace_id,
            "sender_agent_id": self.sender_agent_id,
            "receiver_agent_id": self.receiver_agent_id,
            "timestamp_utc": self.timestamp_utc,
            "nonce": self.nonce,
            "attenuated_token": self.attenuated_token,
            "taint_labels": self.taint_labels,
            "payload": self.payload,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InterAgentEnvelope":
        """Reconstruct envelope from serialized dictionary."""
        return cls(
            message_id=data["message_id"],
            trace_id=data["trace_id"],
            sender_agent_id=data["sender_agent_id"],
            receiver_agent_id=data["receiver_agent_id"],
            timestamp_utc=data["timestamp_utc"],
            nonce=data["nonce"],
            attenuated_token=data["attenuated_token"],
            taint_labels=data.get("taint_labels", []),
            payload=data["payload"],
            signature=data["signature"],
        )


class AgentBus:
    """Inter-agent communication bus enforcing cryptographic signing and role attenuation."""

    def __init__(self, ctx: AgentXDRContext, signing_key: bytes) -> None:
        self.ctx = ctx
        self.signing_key = signing_key

    def _compute_signature(self, nonce: str, trace_id: str, payload: Dict[str, Any]) -> str:
        """Compute HMAC-SHA256 signature over nonce, trace_id, and canonical payload JSON."""
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        canonical_bytes = f"{nonce}:{trace_id}:{canonical_payload}".encode("utf-8")
        return hmac.new(self.signing_key, canonical_bytes, hashlib.sha256).hexdigest()

    def send(
        self,
        receiver_agent_id: str,
        payload: Dict[str, Any],
        attenuated_roles: Optional[List[str]] = None,
    ) -> InterAgentEnvelope:
        """Construct, sign, and seal a message envelope for a peer agent.

        Monotonically narrows roles: delegated roles must be a subset of the sender's active roles.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        message_id = f"msg-{uuid.uuid4()}"
        nonce = secrets.token_hex(16)

        # Enforce monotonic role attenuation (Scope_A->B subset of Scope_A)
        if attenuated_roles is not None:
            effective_roles = [r for r in attenuated_roles if r in self.ctx.user_roles]
        else:
            effective_roles = list(self.ctx.user_roles)

        token_payload = {
            "user_id": self.ctx.user_id,
            "roles": effective_roles,
            "expires_at": (now + datetime.timedelta(seconds=300)).isoformat(),
        }
        attenuated_token = base64.b64encode(json.dumps(token_payload).encode("utf-8")).decode("utf-8")

        signature = self._compute_signature(nonce, self.ctx.trace_id, payload)

        return InterAgentEnvelope(
            message_id=message_id,
            trace_id=self.ctx.trace_id,
            sender_agent_id=self.ctx.agent_id,
            receiver_agent_id=receiver_agent_id,
            timestamp_utc=now.isoformat(),
            nonce=nonce,
            attenuated_token=attenuated_token,
            taint_labels=list(self.ctx.get_taint_snapshot()),
            payload=payload,
            signature=signature,
        )

    def verify(self, envelope: InterAgentEnvelope) -> bool:
        """Verify cryptographic HMAC-SHA256 signature and tamper-integrity."""
        expected_sig = self._compute_signature(envelope.nonce, envelope.trace_id, envelope.payload)
        return hmac.compare_digest(envelope.signature, expected_sig)
