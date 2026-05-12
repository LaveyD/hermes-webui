"""
Shared helpers for session compression anchor metadata.
"""


def _content_text(content, *, part_types):
    if isinstance(content, list):
        return "\n".join(
            str(part.get("text") or part.get("content") or "")
            for part in content
            if isinstance(part, dict) and part.get("type") in part_types
        ).strip()
    return str(content or "").strip()


def _content_has_part_type(content, part_types):
    if not isinstance(content, list):
        return False
    return any(
        isinstance(part, dict) and part.get("type") in part_types
        for part in content
    )


def visible_messages_for_anchor(messages, *, auto_compression: bool = False):
    """Return transcript messages that can anchor compression UI metadata.

    Manual compression historically only counted plain ``text`` content parts
    for non-assistant messages, while the streaming auto-compression path also
    accepted provider-style ``input_text`` / ``output_text`` parts and metadata
    markers on any non-tool role. Keep that difference explicit at the call site
    instead of carrying two near-identical helper implementations.
    """
    out = []
    text_part_types = {"text", "input_text", "output_text"} if auto_compression else {"text"}
    for message in messages or []:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if not role or role == "tool":
            continue

        content = message.get("content", "")
        has_attachments = bool(message.get("attachments"))
        text = _content_text(content, part_types=text_part_types)

        if auto_compression:
            has_tool_calls = bool(
                isinstance(message.get("tool_calls"), list) and message.get("tool_calls")
            )
            has_tool_use = _content_has_part_type(content, {"tool_use"})
            has_reasoning = bool(message.get("reasoning"))
            if not text:
                has_reasoning = has_reasoning or _content_has_part_type(
                    content,
                    {"thinking", "reasoning"},
                )
            if text or has_attachments or has_tool_calls or has_tool_use or has_reasoning:
                out.append(message)
            continue

        if role == "assistant":
            has_tool_calls = bool(
                isinstance(message.get("tool_calls"), list) and message.get("tool_calls")
            )
            has_tool_use = _content_has_part_type(content, {"tool_use"})
            has_reasoning = bool(message.get("reasoning")) or _content_has_part_type(
                content,
                {"thinking", "reasoning"},
            )
            if text or has_attachments or has_tool_calls or has_tool_use or has_reasoning:
                out.append(message)
            continue

        if text or has_attachments:
            out.append(message)
    return out
