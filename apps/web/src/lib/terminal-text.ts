import type { Terminal } from "@xterm/xterm"

/** Snapshot the parsed buffer, not raw ANSI bytes. Join soft wraps so selections
 * copy real lines; textContent rendering keeps remote output inert. */
export function terminalText(terminal: Terminal): string {
  const buffer = terminal.buffer.active
  let text = ""
  for (let index = 0; index < buffer.length; index++) {
    const line = buffer.getLine(index)
    if (!line) continue
    if (index > 0 && !line.isWrapped) text += "\n"
    text += line.translateToString(!buffer.getLine(index + 1)?.isWrapped)
  }
  return text.replace(/\n+$/, "")
}
