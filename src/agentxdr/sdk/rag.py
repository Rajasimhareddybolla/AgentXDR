"""RAG Retrieval Guard — enforces pre-retrieval ACL filtering and injection scanning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from agentxdr.mcp.injection_scanner import McpInjectionScanner
from agentxdr.sdk.context import AgentXDRContext


@dataclass
class RagRetrievalResult:
    """Result of a guarded RAG document retrieval operation."""

    query: str
    chunks: List[Dict[str, Any]]
    acl_filter_applied: bool
    injection_detected: bool
    taint_labels_added: List[str]


class RagGuard:
    """Protects RAG retrieval by enforcing mandatory RBAC ACLs and scanning chunk contents."""

    def __init__(
        self,
        ctx: AgentXDRContext,
        scanner: Optional[McpInjectionScanner] = None,
    ) -> None:
        self.ctx = ctx
        self.scanner = scanner or McpInjectionScanner()

    def retrieve(
        self,
        store: Any,
        query: str,
        enforce_rbac: bool = True,
        top_k: int = 10,
    ) -> RagRetrievalResult:
        """Execute a secure RAG retrieval against any vector/document store.

        Parameters
        ----------
        store:
            Document or vector store exposing a ``query(query, top_k, filter=None)`` method.
        query:
            User search query string.
        enforce_rbac:
            Whether to inject principal ACL filters into the query.
        top_k:
            Maximum number of document chunks to retrieve.
        """
        acl_filter = None
        if enforce_rbac:
            acl_filter = {
                "user_id": self.ctx.user_id,
                "roles": list(self.ctx.user_roles),
            }

        # Query duck-typed vector store
        if acl_filter is not None:
            raw_chunks = store.query(query, top_k=top_k, filter=acl_filter)
        else:
            raw_chunks = store.query(query, top_k=top_k)

        injection_found = False
        taint_labels_added: List[str] = ["RESTRICTED_INTERNAL"]
        self.ctx.add_taint("RESTRICTED_INTERNAL")

        processed_chunks: List[Dict[str, Any]] = []
        for chunk in raw_chunks:
            c = dict(chunk)
            content = c.get("content", "")

            # Scan for indirect prompt injection
            is_inj, _ = self.scanner.scan_tool_response(content)
            if is_inj:
                injection_found = True
                if "SUSPECTED_INJECTION" not in taint_labels_added:
                    taint_labels_added.append("SUSPECTED_INJECTION")
                self.ctx.add_taint("SUSPECTED_INJECTION")

            c["_provenance"] = {
                "acl_enforced": enforce_rbac,
                "source_taint": "RESTRICTED_INTERNAL",
                "injection_flag": is_inj,
            }
            processed_chunks.append(c)

        return RagRetrievalResult(
            query=query,
            chunks=processed_chunks,
            acl_filter_applied=enforce_rbac,
            injection_detected=injection_found,
            taint_labels_added=taint_labels_added,
        )
