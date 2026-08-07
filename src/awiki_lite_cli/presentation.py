"""Safe human-terminal rendering for untrusted remote text."""

from __future__ import annotations


def terminal_text(value: str) -> str:
    """Escape terminal controls and line separators into visible ASCII sequences."""
    output: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\n":
            output.append("\\n")
        elif character == "\r":
            output.append("\\r")
        elif character == "\t":
            output.append("\\t")
        elif codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            width = 2 if codepoint <= 0xFF else 4
            output.append(f"\\x{codepoint:0{width}x}")
        elif character in {"\u2028", "\u2029"}:
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)
