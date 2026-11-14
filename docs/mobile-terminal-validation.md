# Mobile terminal verification

Base: `3f3de67b5058ef41071340628a35e033c92edee8` (fork main).

`npm run check` and `npm run test:regressions` remain the general checks.
After the web build, run `npm run test:terminal`. Set
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium` when using system Chromium.
The browser suite uses a local static server, synthetic API replies and an
intercepted terminal WebSocket; no SSH host or production credentials are needed.
The standalone event suite also runs as `node tests/mobile-terminal-input.mjs`
on Node 22.18+ (TypeScript type stripping).

## What changed

A capture listener on the terminal host owns text events from xterm's public
textarea on touch-capable devices. Desktop devices without touch retain xterm's
input path. Printable keys are forwarded from input, not independently from
keypress. Composition edits stay local until commit. An open composition may
commit once; final input before/after compositionend and duplicate compositionend
are covered. Composition finalization waits one event-loop turn. Enter used to
confirm a composition in that transaction is consumed; a subsequent Enter emits
one CR. Plain keydown and beforeinput Enter/Backspace do not both send.
Already-sent text is removed from the textarea, and explicit
insertReplacementText is rejected so correction cannot rewrite earlier commands.
Paste goes through xterm's public paste method (including bracketed-paste mode).
The existing browser autocorrect/autocapitalize/spellcheck settings remain.

“Select output” reads xterm's parsed active buffer into an inert, selectable,
scrollable text snapshot. Soft wraps join into real lines, ANSI escapes are not
copied, and HTML-looking output remains text. It does not send Ctrl+C. The
snapshot includes only retained scrollback/current active screen, not an unlimited
session log, and does not update during selection. Reopen it to refresh. The
terminal remains mounted with its original dimensions while selecting.

## Required device checks before promoting a draft

Automated dispatch of events does not run a real keyboard/IME or native selection
handles. Verify on Android Chrome with Gboard English, Chinese Pinyin and Japanese,
and iOS Safari with English, Chinese and Japanese keyboards:

1. Type `printf '%s\\n' hello` with suggestions enabled in system settings. Confirm
   no automatic capitalization/correction rewrites already entered command text.
2. Commit Chinese/Japanese candidates with the candidate bar, space and Enter.
   Each commit must appear once; confirming a candidate must not run the command.
   Press Enter again: exactly one command execution.
3. Type a word, Backspace repeatedly, then type the same word again. No text should
   reappear from stale textarea state. Test keydown-229 English without composition.
4. Paste multiple lines; verify behavior with bracketed paste enabled and disabled.
5. Produce multiple output lines and long wrapped lines. Open Select output,
   long-press, extend handles across lines, scroll, and use native Copy. Paste into
   Notes to check the exact selected substring. No remote interrupt should occur.
6. Switch terminal/files/assistant, switch sessions, reconnect, and rotate the
   device while the keyboard is open. Output and connection must survive.
7. On desktop, verify text, CJK composition, Ctrl+C, arrows, Backspace and paste.

Known scope: this is a bounded event-transaction adapter, not a general rich-text
IME editor. Vendor keyboards that deliver final input in a later event-loop task,
non-composition multi-character replacement/deletion (for example Vietnamese
Telex), dictation, hardware keyboards on touch laptops and IME preview positioning
need device traces before being claimed supported. Do not infer real-device
success from synthetic browser tests.

## Related upstream evidence

- https://github.com/xtermjs/xterm.js/issues/5377 and
  https://github.com/xtermjs/xterm.js/issues/3727 describe touch limitations.
- https://github.com/xtermjs/xterm.js/pull/5961 proposes native iOS touch copying;
  this change does not incorporate that unmerged work.
- https://github.com/NousResearch/hermes-agent/pull/116978 addresses duplicate
  composition forwarding in Hermes using a timing/filter guard.
- https://github.com/NousResearch/hermes-agent/issues/136179 reports a separate
  Gboard keydown-229/insertText swallowing path even with that fix present.

Those reports motivate separate event-order cases; they are not evidence that
Besh, or all mobile keyboards, are fixed.
