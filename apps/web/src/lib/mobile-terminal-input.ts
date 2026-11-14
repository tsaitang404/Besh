/** One owner for mobile text input: xterm's key/composition/input paths must not
 * independently forward the same edit. Install on its ancestor (capture phase).
 * Never retain already-sent text for an IME to autocorrect later. */
export function attachMobileTerminalInput(
  host: HTMLElement,
  textarea: HTMLTextAreaElement,
  enabled: () => boolean,
  send: (text: string) => void,
  paste: (text: string) => void,
) {
  let composing = false
  let pending: string | null = null
  let timer: ReturnType<typeof setTimeout> | undefined
  let action = ""
  let confirming = false
  const reset = () => { textarea.value = "" }
  const flush = () => {
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
    if (pending !== null) {
      const text = pending
      pending = null
      reset()
      if (text) send(text)
    }
  }
  const stop = (event: Event, prevent = false) => {
    event.stopImmediatePropagation()
    if (prevent && event.cancelable) event.preventDefault()
  }
  const listeners: Array<[string, EventListener]> = []
  const listen = <K extends keyof HTMLElementEventMap>(name: K, handler: (event: HTMLElementEventMap[K]) => void) => {
    const listener: EventListener = event => {
      if (event.target === textarea && enabled()) handler(event as HTMLElementEventMap[K])
    }
    host.addEventListener(name, listener, true)
    listeners.push([name, listener])
  }
  listen("compositionstart", event => {
    stop(event)
    flush()
    composing = true
    confirming = false
  })
  listen("compositionupdate", event => stop(event))
  listen("compositionend", (event: CompositionEvent) => {
    stop(event)
    // Some keyboards dispatch compositionend twice. Only an open transaction
    // may commit; a later final input updates this transaction, never adds to it.
    if (!composing) return
    composing = false
    pending = event.data
    confirming = true
    timer = setTimeout(() => { flush(); confirming = false }, 0)
  })
  listen("keydown", (event: KeyboardEvent) => {
    if (composing || event.isComposing || event.keyCode === 229) {
      stop(event)
      return
    }
    if (confirming && event.key === "Enter") {
      stop(event, true)
      action = "Enter"
      flush()
      confirming = false
      return
    }
    confirming = false
    flush()
    if (event.ctrlKey || event.metaKey || event.altKey) return
    if (event.key === "Enter" || event.key === "Backspace") {
      stop(event, true)
      action = event.key
      reset()
      send(event.key === "Enter" ? "\r" : "\x7f")
    } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      // Let the browser edit the textarea; input is the only text sender.
      stop(event)
    }
  })
  listen("keypress", (event: KeyboardEvent) => {
    if (!event.ctrlKey && !event.metaKey && !event.altKey) stop(event)
  })
  listen("keyup", () => { action = "" })
  listen("beforeinput", (event: InputEvent) => {
    stop(event)
    if (event.inputType === "insertReplacementText" && !composing && pending === null) {
      stop(event, true)
      reset()
    } else if (event.inputType === "insertLineBreak" || event.inputType === "insertParagraph") {
      stop(event, true)
      if (!composing && !confirming && action !== "Enter") { flush(); send("\r"); reset() }
    } else if (event.inputType === "deleteContentBackward" && !composing) {
      stop(event, true)
      if (action !== "Backspace") { flush(); send("\x7f"); reset() }
    }
  })
  listen("input", (event: InputEvent) => {
    stop(event)
    if (composing || event.isComposing) return
    if (pending !== null) {
      // WebKit final input follows compositionend; Chromium may send it before.
      pending = textarea.value || pending
      return
    }
    if (event.inputType === "insertText" || event.inputType === "insertFromComposition") {
      const text = textarea.value
      reset()
      if (text) send(text)
    } else reset()
  })
  // Keep xterm's bracketed-paste handling, without letting its textarea retain it.
  listen("paste", (event: ClipboardEvent) => {
    const text = event.clipboardData?.getData("text/plain")
    if (text === undefined) return
    stop(event, true)
    flush()
    reset()
    paste(text)
  })
  listen("blur", () => {
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
    composing = false
    pending = null
    confirming = false
    action = ""
    reset()
  })
  return () => {
    if (timer !== undefined) clearTimeout(timer)
    for (const [name, listener] of listeners) host.removeEventListener(name, listener, true)
  }
}
