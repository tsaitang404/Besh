import assert from 'node:assert/strict'
import { attachMobileTerminalInput } from '../apps/web/src/lib/mobile-terminal-input.ts'
import { terminalText } from '../apps/web/src/lib/terminal-text.ts'

// Exercise the DOM adapter without xterm/browser timing. Browser integration
// separately verifies the ancestor capture listener wins over xterm handlers.
function fixture() {
  const textarea = new EventTarget()
  textarea.value = ''
  const sent = [], pasted = []
  let enabled = true
  const dispose = attachMobileTerminalInput(textarea, textarea, () => enabled, text => sent.push(text), text => pasted.push(text))
  const event = (name, data = {}, value) => {
    if (value !== undefined) textarea.value = value
    const e = new Event(name, { cancelable: true })
    Object.assign(e, data)
    textarea.dispatchEvent(e)
    return e
  }
  return { textarea, sent, pasted, event, dispose, disable: () => { enabled = false } }
}
const tick = () => new Promise(resolve => setTimeout(resolve, 5))
{
  const f = fixture()
  f.event('keydown', {key: 'Unidentified', keyCode: 229})
  for (const char of 'git status') {
    f.event('keydown', {key: char})
    f.event('input', { inputType: 'insertText', data: char }, char)
  }
  f.event('keydown', { key: 'Enter' })
  f.event('beforeinput', { inputType: 'insertLineBreak' })
  f.event('keyup', { key: 'Enter' })
  f.event('keydown', { key: 'Backspace' })
  f.event('beforeinput', { inputType: 'deleteContentBackward' })
  f.event('keyup', { key: 'Backspace' })
  f.event('beforeinput', { inputType: 'deleteContentBackward' })
  assert.equal(f.sent.join(''), 'git status\r\x7f\x7f')
  assert.equal(f.textarea.value, '')
  f.event('beforeinput', { inputType: 'insertReplacementText', data: 'Git' })
  f.event('input', { inputType: 'insertReplacementText', data: 'Git' }, 'Git')
  assert.equal(f.sent.join(''), 'git status\r\x7f\x7f')
  f.dispose()
}
for (const text of ['中文', '日本語', 'hello']) {
  for (const order of ['input-before-end', 'input-after-end', 'end-only']) {
    const f = fixture()
    f.event('compositionstart')
    f.event('input', { inputType: 'insertCompositionText', isComposing: true }, 'draft')
    f.event('keydown', { key: 'Enter', keyCode: 229, isComposing: true })
    if (order === 'input-before-end') f.event('input', { inputType: 'insertCompositionText', isComposing: false }, text)
    f.event('compositionend', { data: text }, text)
    f.event('compositionend', { data: text }) // duplicate end is not a new transaction
    if (order === 'input-after-end') f.event('input', { inputType: 'insertText', data: text }, text)
    f.event('beforeinput', { inputType: 'insertParagraph' })
    await tick()
    assert.deepEqual(f.sent, [text], order)
    f.event('keydown', { key: 'Enter' })
    f.event('beforeinput', { inputType: 'insertLineBreak' })
    f.event('keyup', {key: 'Enter'})
    assert.deepEqual(f.sent, [text, '\r'])
    f.dispose()
  }
}
{
  const f = fixture()
  f.event('compositionstart')
  f.event('compositionend', { data: '候補' }, '候補')
  f.event('keydown', {key: 'Enter'})
  await tick()
  assert.deepEqual(f.sent, ['候補'], 'confirmation after compositionend does not execute command')
  f.event('paste', { clipboardData: { getData: () => 'a\nb' } })
  assert.deepEqual(f.pasted, ['a\nb'])
  f.disable()
  f.event('input', { inputType: 'insertText' }, 'desktop')
  assert.deepEqual(f.sent, ['候補'])
  f.dispose()
}
{
  const f = fixture()
  f.event('compositionstart')
  f.event('compositionend', { data: 'stale' }, 'stale')
  f.dispose()
  await tick()
  assert.deepEqual(f.sent, [], 'disposing cancels delayed send')
}
const lines = [
  { isWrapped: false, translateToString: trim => trim ? 'ab' : 'ab  ' },
  { isWrapped: true, translateToString: () => '<script>remote</script>' },
  { isWrapped: false, translateToString: () => 'next' },
  { isWrapped: false, translateToString: () => '' },
]
assert.equal(terminalText({buffer: {active: {length: lines.length, getLine: i => lines[i]}}}), 'ab  <script>remote</script>\nnext')
console.log('PASS mobile input: English, CJK event orders, duplicate compositionend, candidate Enter, single CR, Backspace, replacement rejection, paste, desktop bypass, cleanup; buffer soft wraps')
