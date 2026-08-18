export function terminalText(value: string): string {
  let output = '';
  for (const character of value) {
    const codepoint = character.codePointAt(0) ?? 0;
    if (character === '\n') {
      output += '\\n';
    } else if (character === '\r') {
      output += '\\r';
    } else if (character === '\t') {
      output += '\\t';
    } else if (codepoint < 0x20 || (codepoint >= 0x7f && codepoint <= 0x9f)) {
      const width = codepoint <= 0xff ? 2 : 4;
      output += `\\x${codepoint.toString(16).padStart(width, '0')}`;
    } else if (character === '\u2028' || character === '\u2029') {
      output += `\\u${codepoint.toString(16).padStart(4, '0')}`;
    } else {
      output += character;
    }
  }
  return output;
}
