import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'
const server = createServer((req, res) => {
  try {
    const path = new URL(req.url, 'http://test').pathname
    const file = path === '/' ? '/index.html' : path
    res.setHeader('Content-Type', file.endsWith('.html') ? 'text/html' : file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'application/octet-stream')
    res.end(readFileSync(new URL('../apps/web/dist' + file, import.meta.url)))
  } catch { res.statusCode = 404; res.end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
let browser
try {
  browser = await chromium.launch({headless:true, executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH})
  for (const mobile of [true, false]) {
    const context = await browser.newContext({ viewport: {width:mobile ? 390 : 1280,height:844}, hasTouch:mobile })
    const page = await context.newPage()
    await page.addInitScript(() => localStorage.setItem('besh:lang','en-US'))
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname
      const fixture = {
        '/api/auth/bootstrap':{required:false},'/api/auth/session':{authenticated:true},
        '/api/servers':{servers:[{id:'test',name:'Test host',host:'example.com',port:22,username:'test',authMethod:'password',groupId:null,os:null}]},
        '/api/server-groups':{groups:[]},'/api/sessions':{sessionId:'test',ticket:'synthetic-ticket'},
        '/api/settings':{aiPermission:'confirm',aiConfigured:false,aiProvider:{configured:false,params:{inputs:{image:false}}},ui:{language:'en-US',theme:'light',terminalFont:14},turnstile:{enabled:false}},
      }[path]
      await route.fulfill({status:fixture?200:404,json:fixture??{}})
    })
    const inputs = []
    let sentReady = false
    let socket
    await page.routeWebSocket('**/api/sessions/**/terminal?*', ws => {
      socket = ws
      ws.onMessage(raw => {
        const message = JSON.parse(String(raw))
        if (message.type === 'resize' && !sentReady) {sentReady = true; ws.send(JSON.stringify({type:'ready'}))}
        if (message.type === 'input') inputs.push(Buffer.from(message.data,'base64').toString('utf8'))
      })
    })
    await page.goto('http://127.0.0.1:'+server.address().port)
    await page.locator('.besh-server-list button').filter({hasText:'Test host'}).click()
    const textarea = page.locator('.xterm-helper-textarea')
    await textarea.waitFor({state:'attached'})
    await textarea.focus()
    await page.keyboard.type('git status')
    await page.keyboard.press('Enter')
    await page.keyboard.press('Backspace')
    await page.waitForTimeout(50)
    assert.equal(inputs.join(''),'git status\r\x7f', mobile ? 'touch English' : 'desktop English')
    inputs.length = 0
    if (!mobile) {
      await page.keyboard.press('Control+c')
      await page.keyboard.press('ArrowUp')
      await page.waitForTimeout(50)
      assert.equal(inputs.join(''), '\x03\x1b[A')
      inputs.length = 0
    }
    if (mobile) {
      await textarea.evaluate(el => {
        const fire = (type, init) => el.dispatchEvent(type.startsWith('composition') ? new CompositionEvent(type,{bubbles:true,...init}) : new InputEvent(type,{bubbles:true,cancelable:true,...init}))
        fire('compositionstart',{})
        el.value = '日本語'
        fire('input',{inputType:'insertCompositionText',isComposing:true,data:'日本語'})
        fire('compositionend',{data:'日本語'})
        fire('compositionend',{data:'日本語'})
        fire('input',{inputType:'insertText',data:'日本語'})
        fire('beforeinput',{inputType:'insertParagraph'})
      })
      await page.waitForTimeout(50)
      assert.deepEqual(inputs,['日本語'])
      await page.keyboard.press('Enter')
      await page.waitForTimeout(50)
      assert.deepEqual(inputs,['日本語','\r'])
      inputs.length = 0
      socket.send(JSON.stringify({type:'data',data:Buffer.from('\x1b[?2004h').toString('base64')}))
      await page.waitForTimeout(50)
      await textarea.evaluate(el => {
        const paste = new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:new DataTransfer()})
        paste.clipboardData.setData('text/plain','paste\nline')
        el.dispatchEvent(paste)
      })
      await page.waitForTimeout(50)
      assert.equal(inputs.join(''),'\x1b[200~paste\rline\x1b[201~','xterm bracketed paste normalizes newlines')
    }
    socket.send(JSON.stringify({type:'data',data:Buffer.from('\r\n\x1b[31mselect this\x1b[0m\r\n<script>inert</script>\r\nlast line').toString('base64')}))
    await page.waitForTimeout(50)
    const before = [...inputs]
    await page.getByRole('button',{name:'Select output',exact:true}).click()
    const output = page.locator('.besh-selectable-output pre')
    await output.waitFor()
    const text = await output.textContent()
    assert.ok(text.includes('select this\n<script>inert</script>\nlast line'))
    assert.equal(await output.locator('script').count(),0)
    assert.equal(await output.evaluate(el => getComputedStyle(el).userSelect),'text')
    assert.equal(await output.evaluate(el => {
      const range = document.createRange();range.selectNodeContents(el)
      const selection = window.getSelection();selection.removeAllRanges();selection.addRange(range)
      return selection.toString()
    }),text)
    assert.deepEqual(inputs,before,'selecting output sends no terminal input')
    await page.getByRole('button',{name:'Back to terminal',exact:true}).click()
    assert.equal(await textarea.count(),1,'same terminal survives snapshot')
    console.log('PASS '+(mobile?'touch':'desktop')+' browser: terminal input bytes and selectable inert output')
    await context.close()
  }
} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)) }
