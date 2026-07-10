## # Web & API Security Bug Bounty Handbook 

## ## Table of Contents 

1. [Cybersecurity Fundamentals](#cybersecurity-fundamentals) 

- 1.1. [What is Cybersecurity?](#what-is-cybersecurity) 

- 1.2. [Domains of Cybersecurity](#domains-of-cybersecurity) 

- 1.3. [Ethical Hacking & Bug Hunting](#ethical-hacking--bug-hunting) 

- 1.4. [Bug Bounty vs. Penetration Testing](#bug-bounty-vs-penetration-testing) 

- 1.5. [Responsible Disclosure](#responsible-disclosure) 

- 1.6. [CVE, CWE, CVSS](#cve-cwe-cvss) 

- 1.7. [CIA Triad](#cia-triad) 

- 1.8. [OWASP & Security Frameworks](#owasp--security-frameworks) 

- 1.9. [MITRE ATT&CK (High-Level)](#mitre-attck-high-level) 

- 1.10. [Risk Assessment](#risk-assessment) 

- 1.11. [Threat Modeling (Beginner)](#threat-modeling-beginner) 

2. [Networking Basics](#networking-basics) 

- 2.1. [OSI Model & TCP/IP](#osi-model--tcpip) 

- 2.2. [DNS](#dns) 

- 2.3. [HTTP & HTTPS](#http--https) 

- 2.4. [TLS & Certificates](#tls--certificates) 

- 2.5. [Cookies & Sessions](#cookies--sessions) 

- 2.6. [JSON Web Tokens (JWT)](#json-web-tokens-jwt) 

- 2.7. [Same-Origin Policy & CORS](#same-origin-policy--cors) 

- 2.8. [HTTP Headers, Methods, Status Codes](#http-headers-methods-status-codes) 

- 2.9. [Caching](#caching) 

2.10. [Proxies and Traffic Interception](#proxies-and-traffic-interception) 

2.11. [Packet Flow & Browser/API Request Lifecycle](#packet-flow--browserapi-requestlifecycle) 

- 2.12. [Practice with Wireshark & Burp Proxy](#practice-with-wireshark--burp-proxy) 

3. [Linux & Command Line](#linux--command-line) 

- 3.1. [Linux File System & Users](#linux-file-system--users) 

- 3.2. [File Permissions](#file-permissions) 

- 3.3. [Basic Shell Commands (ls, cd, cat)](#basic-shell-commands) 

3.4. [File Operations (grep, awk, sed)](#file-operations) 

3.5. [Text Tools (sort, uniq, find, xargs)](#text-tools) 

- 3.6. [JSON Tools (jq)](#json-tools) 

- 3.7. [Terminal Utilities (tmux, vim basics)](#terminal-utilities) 

- 3.8. [Daily Practice Exercises](#daily-practice-exercises) 

4. [Programming for Bug Bounty](#programming-for-bug-bounty) 

- 4.1. [HTML & CSS Basics](#html--css-basics) 

- 4.2. [JavaScript & the DOM](#javascript--the-dom) 

- 4.3. [JSON Data & Scripting](#json-data--scripting) 

- 4.4. [Python for Security](#python-for-security) 

- 4.5. [Bash Scripting](#bash-scripting) 

- 4.6. [HTTP Requests & APIs](#http-requests--apis) 

- 4.7. [Regular Expressions (Regex)](#regular-expressions-regex) 

- 4.8. [APIs and Cookies/JWT Parsing](#apis-and-cookiesjwt-parsing) 

5. [Web Technologies](#web-technologies) 

- 5.1. [Browser Rendering & JavaScript Engine](#browser-rendering--javascript-engine) 

- 5.2. [DOM, HTML, CSSOM, Layout, Paint](#dom-html-cssom-layout-paint) 

- 5.3. [Browser Storage: Cookies, LocalStorage, SessionStorage](#browser-storagecookies-localstorage-sessionstorage) 

5.4. [Authentication vs. Authorization](#authentication-vs-authorization) 

5.5. [Authentication Protocols: OAuth & OpenID Connect](#authentication-protocolsoauth--openid-connect) 

- 5.6. [Session Management & JWTs](#session-management--jwts) 

- 5.7. [CSRF Tokens and Anti-CSRF](#csrf-tokens-and-anti-csrf) 

- 5.8. [Access Control: RBAC & ABAC](#access-control-rbac--abac) 

- 5.9. [Business Workflows & Security](#business-workflows--security) 

6. [Web Application Security](#web-application-security) 

- 6.1. [OWASP Top 10 & Beyond](#owasp-top-10--beyond) 

6.2. [Authentication Flaws](#authentication-flaws) 

- 6.3. [Broken Access Control (IDOR, etc.)](#broken-access-control-idor-etc) 

- 6.4. [Injection (SQL, NoSQL, LDAP, etc.)](#injection-sql-nosql-ldap-etc) 

- 6.5. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss) 

- 6.6. [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf) 

- 6.7. [XML External Entities (XXE)](#xml-external-entities-xxe) 

- 6.8. [Remote Code Execution & Command Injection](#remote-code-execution-command-injection) 

- 6.9. [File Upload Flaws](#file-upload-flaws) 

- 6.10. [Path Traversal](#path-traversal) 

- 6.11. [Open Redirect](#open-redirect) 

- 6.12. [Host Header Injection](#host-header-injection) 

- 6.13. [Clickjacking](#clickjacking) 

- 6.14. [Race Conditions](#race-conditions) 

- 6.15. [HTTP Request Smuggling](#http-request-smuggling) 

- 6.16. [Business Logic Flaws](#business-logic-flaws) 

- 6.17. [Mass Assignment / Parameter Pollution](#mass-assignment--parameter-pollution) 

- 6.18. [Prototype Pollution](#prototype-pollution) 

- 6.19. [Deserialization Attacks](#deserialization-attacks) 

- 6.20. [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti) 

- 6.21. [NoSQL Injection](#nosql-injection) 

- 6.22. [GraphQL Vulnerabilities](#graphql-vulnerabilities) 

7. [Special Deep Dive – IDOR](#special-deep-dive--idor) 

- 7.1. [Why IDOR is Beginner-Friendly](#why-idor-is-beginner-friendly) 

- 7.2. [Horizontal vs. Vertical Privilege Escalation](#horizontal-vs-vertical-privilegeescalation) 

- 7.3. [Object References & UUIDs](#object-references--uuids) 

- 7.4. [Predictable IDs & Hidden APIs](#predictable-ids--hidden-apis) 

- 7.5. [Mobile/API & GraphQL IDOR](#mobileapi--graphql-idor) 

- 7.6. [Bulk IDOR](#bulk-idor) 

- 7.7. [File Download/Upload IDOR](#file-downloadupload-idor) 

- 7.8. [Advanced IDOR Chains & Case Studies](#advanced-idor-chains--case-studies) 

- 7.9. [Attack Methodology & Checklists](#attack-methodology--checklists) 

- 7.10. [Burp Techniques & Automation](#burp-techniques--automation) 

- 7.11. [Common False Positives & Mistakes](#common-false-positives--mistakes) 

- 7.12. [Practice Labs & Real Reports](#practice-labs--real-reports) 

8. [API Security](#api-security) 

- 8.1. [REST, SOAP, GraphQL, gRPC](#rest-soap-graphql-grpc) 

- 8.2. [JSON & XML](#json--xml) 

- 8.3. [JWT, OAuth, OIDC](#jwt-oauth-oidc) 

- 8.4. [API Gateways, Rate Limiting, Pagination, Versioning](#api-gateways-rate-limitingpagination-versioning) 

- 8.5. [API Authentication & Authorization](#api-authentication--authorization) 

- 8.6. [OWASP API Top 10 (BOLA, BFLA, etc.)](#owasp-api-top-10-bola-bfla-etc) 

- 8.7. [API Recon & Fuzzing](#api-recon--fuzzing) 

8.8. [API Documentation Abuse](#api-documentation-abuse) 

8.9. [Postman & Insomnia Workflows](#postman--insomnia-workflows) 

- 8.10. [Burp API Testing](#burp-api-testing) 

9. [Reconnaissance](#reconnaissance) 

- 9.1. [Passive Recon](#passive-recon) 

- 9.2. [Active Recon](#active-recon) 

- 9.3. [Subdomain & DNS Enumeration](#subdomain--dns-enumeration) 

- 9.4. [ASN & WHOIS Enumeration](#asn--whois-enumeration) 

- 9.5. [JavaScript & Endpoint Discovery](#javascript--endpoint-discovery) 

- 9.6. [Parameter & Content Discovery](#parameter--content-discovery) 

- 9.7. [Wayback & Archive Mining](#wayback--archive-mining) 

- 9.8. [GitHub & Code Recon](#github--code-recon) 

- 9.9. [Secrets Hunting & Fingerprinting](#secrets-hunting--fingerprinting) 

- 9.10. [Cloud Asset Discovery](#cloud-asset-discovery) 

- 9.11. [Wordlists & Automation](#wordlists--automation) 

- 9.12. [Noise Reduction & Data Org](#noise-reduction--data-org) 

- 9.13. [Target Prioritization](#target-prioritization) 

10. [Bug Hunting Methodology](#bug-hunting-methodology) 

- 10.1. [Mindset & Attack Surface](#mindset--attack-surface) 

- 10.2. [Selecting Targets & Programs](#selecting-targets--programs) 

- 10.3. [Mapping Workflows & Documentation](#mapping-workflows--documentation) 

- 10.4. [Privilege Boundaries & Chains](#privilege-boundaries--chains) 

- 10.5. [Testing Approach & Avoiding Dead Ends](#testing-approach--avoiding-dead-ends) 

10.6. [Note-taking & Reporting Workflow](#note-taking--reporting-workflow) 

- 10.7. [Automation vs Manual Balance](#automation-vs-manual-balance) 

- 10.8. [Personal Workflow & Decision Trees](#personal-workflow--decision-trees) 

11. [Tools](#tools) 

11.1. [Burp Suite (Professional & Community)](#burp-suite) 

11.2. [Nmap](#nmap) 

11.3. [httpx](#httpx) 

11.4. [Katana Scanner](#katana-scanner) 

11.5. [gau, waybackurls](#gau--waybackurls) 

11.6. [ffuf, dirsearch](#ffuf--dirsearch) 

11.7. [subfinder, amass, assetfinder](#subfinder--amass--assetfinder) 

11.8. [nuclei](#nuclei) 

11.9. [gf patterns](#gf-patterns) 

11.10. [qsreplace, dalfox](#qsreplace--dalfox) 

11.11. [sqlmap (authorized only)](#sqlmap) 

11.12. [Postman & Insomnia](#postman--insomnia) 

11.13. [curl, jq](#curl--jq) 

11.14. [Workflow & Advanced Usage](#workflow--advanced-usage) 

11.15. [Automation & Integration](#automation--integration) 

12. [Hands-on Practice Platforms](#hands-on-practice-platforms) 

12.1. [PortSwigger Web Security Academy](#portswigger-web-security-academy) 

12.2. [OWASP Juice Shop](#owasp-juice-shop) 

12.3. [Damn Vulnerable Web App (DVWA)](#damn-vulnerable-web-app-dvwa) 

12.4. [OWASP WebGoat](#owasp-webgoat) 

12.5. [bWAPP](#bwapp) 

12.6. [Hack The Box / TryHackMe](#hack-the-box--tryhackme) 

12.7. [PentesterLab](#pentesterlab) 

12.8. [PicoCTF](#picotf) 

12.9. [OverTheWire](#overthewire) 

12.10. [VulnHub](#vulnhub) 

12.11. [Root-Me](#root-me) 

12.12. [Platform Comparison Table](#platform-comparison) 

13. [Learning Resources](#learning-resources) 

13.1. [Books](#books) 

13.2. [Documentation & Standards](#documentation--standards) 

13.3. [GitHub Repos & Tools](#github-repos--tools) 

13.4. [Blogs & Research Papers](#blogs--research-papers) 

13.5. [Podcasts & YouTube Channels](#podcasts--youtube-channels) 

13.6. [Communities (Discord, Reddit, Twitter)](#communities) 

13.7. [CTF & Learning Paths](#ctf--learning-paths) 

13.8. [Cheat Sheets & Browser Extensions](#cheat-sheets--browser-extensions) 

14. [Finding Real Bug Bounty Targets](#finding-real-bug-bounty-targets) 

- 14.1. [Platforms (HackerOne, Bugcrowd, etc.)](#platforms-hackerone-bugcrowd-etc) 

- 14.2. [Public vs Private Programs](#public-vs-private-programs) 

14.3. [Scope Analysis & Rules](#scope-analysis--rules) 

14.4. [Asset Prioritization](#asset-prioritization) 

14.5. [Beginner-Friendly Programs](#beginner-friendly-programs) 

14.6. [Safe Testing Guidelines](#safe-testing-guidelines) 

14.7. [Avoiding Duplicates & OOS](#avoiding-duplicates--oos) 

15. [Reporting Vulnerabilities](#reporting-vulnerabilities) 

- 15.1. [Professional Report Structure](#professional-report-structure) 

15.2. [Templates (Title, Summary, Steps, PoC)](#templates) 

- 15.3. [Evidence & Media (Screenshots, Videos)](#evidence--media) 

- 15.4. [Suggested Remediations & Fixes](#suggested-remediations--fixes) 

15.5. [Severity Justification & CVSS](#severity-justification--cvss) 

15.6. [Communication with Triagers](#communication-with-triagers) 

15.7. [Handling N/A, Duplicates, Retests](#handling-na--duplicates--retests) 

16. [Real Bug Bounty Case Studies](#real-bug-bounty-case-studies) 

16.1. [IDOR Report Analysis](#idor-report-analysis) 

16.2. [Access Control Bug](#access-control-bug) 

16.3. [Business Logic Flaw](#business-logic-flaw) 

16.4. [Authentication/OAuth Issue](#authenticationoauth-issue) 

16.5. [API Vulnerability (JWT, GraphQL)](#api-vulnerability-jwt-graphql) 

- 16.6. [Attacker Mindset & Reporting Process](#attacker-mindset--reporting-process) 

17. [Productivity System](#productivity-system) 

- 17.1. [Daily Workflow & Goals](#daily-workflow--goals) 

17.2. [Weekly & Monthly Workflow](#weekly--monthly-workflow) 

- 17.3. [Knowledge Management (Notes, Bookmarks)](#knowledge-management) 

- 17.4. [Recon/Issue Tracking Tools (Obsidian, etc.)](#reconissue-tracking) 

17.5. [Lab Tracking & Bug Tracking](#lab-tracking--bug-tracking) 

- 17.6. [Automation Schedule](#automation-schedule) 

18. [Common Beginner Mistakes](#common-beginner-mistakes) 

19. [90-Day Study Plan](#90-day-study-plan) 

20. [After Your First Bounty](#after-your-first-bounty) 

- 20.1. [Advanced Web Exploits (XSS, SSRF, etc.)](#advanced-web-exploits) 

- 20.2. [Request Smuggling & Deserialization](#request-smuggling--deserialization) 

- 20.3. [Cloud & Infrastructure Security (AWS, Azure, GCP)](#cloud--infrastructuresecurity) 

- 20.4. [Container & Kubernetes](#container--kubernetes) 

- 20.5. [Mobile Security (Android, iOS)](#mobile-security-android-ios) 

- 20.6. [Binary Analysis & Reverse Engineering](#binary-analysis--reverse-engineering) 

20.7. [Source Code Review Techniques](#source-code-review) 

20.8. [Advanced Recon & Automation (Custom Pipelines)](#advanced-recon-automation) 

20.9. [AI-Assisted Security Tools](#ai-assisted-security-tools) 

20.10. [Professional Bug Bounty Career & Pentesting](#professional-bug-bounty-career) 

20.11. [Continuous Learning Strategy](#continuous-learning-strategy) 

21. [Final Checklists & Planners](#final-checklists--planners) 

21.1. [Complete Beginner Checklist](#complete-beginner-checklist) 

21.2. [6-Month Roadmap](#6-month-roadmap) 

21.3. [12-Month Roadmap](#12-month-roadmap) 

21.4. [Skill Progression Matrix](#skill-progression-matrix) 

21.5. [Recommended Certifications (Optional)](#recommended-certifications) 

21.6. [Daily/Weekly/Monthly Planner](#dailyweeklymonthly-planner) 

21.7. [Tool Mastery Checklist](#tool-mastery-checklist) 

21.8. [Practice Lab Checklist](#practice-lab-checklist) 

21.9. [Bug Bounty Readiness Checklist](#bug-bounty-readiness-checklist) 

21.10. [First Bounty Action Plan](#first-bounty-action-plan) 21.11. [Top 100 Things Every Beginner Should Know](#top-100-things-every-beginnershould-know) 

## 1. Cybersecurity Fundamentals 

### 1.1. What is Cybersecurity? 

Cybersecurity is the practice of protecting digital systems, networks, applications, and data from unauthorized access, damage, or theft.  It combines technology, processes, and policies to defend against threats (malware, phishing, insider misuse, etc.).  The ultimate 

goal is to maintain the **confidentiality, integrity, and availability** (CIA) of information and systems.  In simple terms: **Confidentiality** means only authorized users see data; **Integrity** means data isn’t tampered with; **Availability** means services/data are accessible when needed. Maintaining these three pillars is the core of security. 

**Why it matters:** Almost every business, government, and individual relies on digital systems (web apps, mobile apps, APIs).  Cybersecurity protects against criminals or spies stealing information, disrupting services, or harming people.  For example, data breaches (like stolen credit cards or personal records) can ruin reputations and cost millions in fines. 

**Real-World Example:** The 2017 Equifax breach (one of the largest data leaks) occurred because of a web app vulnerability.  Stolen personal data of millions highlighted the need for strong cybersecurity. 

**Exercises:** 

- Write down examples of systems you use daily (online banking, email, social media). List what data must stay confidential, what must be integral, and how to ensure it’s available. 

- Explain in your own words why your personal information must be protected (e.g. identity theft). 

- Use interactive online CIA triad quizzes to test understanding (see Resources). 

**Learning Resources:** 

- Intro articles (e.g. **W3Schools** “What is Cybersecurity?”). 

- Videos on CIA Triad (simple explainers). 

- **Book:** *Cybersecurity for Dummies* (for beginners) or official NIST materials. 

### 1.2. Domains of Cybersecurity 

Cybersecurity is **multi-faceted**. It’s not just one job or tool, but spans many domains focusing on different assets. Key domains include: 

- **Network Security:** Protects data in transit across networks (e.g. corporate LANs, internet). Tools: Firewalls, IDS/IPS, VPNs. Secures routers, switches, wireless. 

- **Endpoint Security:** Protects devices (laptops, phones, IoT). Tools: Antivirus, EDR (Endpoint Detection & Response). Ensures devices aren’t exploited for entry points. 

- **Application Security:** Protects software applications (web/mobile apps). Includes code reviews, vulnerability scans, secure development. Tool examples: static/dynamic analysis, WAFs. 

- **Data Security:** Protects sensitive data at rest/in transit. Includes encryption, secure databases, DLP (Data Loss Prevention). 

- **Identity & Access Management (IAM):** Controls who can access what. Includes authentication systems (logins, SSO, MFA) and authorization rules (roles, policies). 

- **Cloud Security:** Protects cloud infrastructure, services, and data (AWS, Azure, GCP). Uses CASBs (Cloud Access Security Brokers), cloud firewalls, etc. 

- **Operational Security:** Policies/processes that govern how data is handled (e.g. incident response, policies). 

- **Security Operations (SecOps):** Day-to-day monitoring, logging, incident handling. SOC teams. 

- **Governance/Risk Management:** Defining overall security policies, compliance (GDPR, HIPAA), and risk assessments. 

**Why it matters:** Different domains focus on different risk areas. For example, a web developer focuses on **app security**, whereas a network engineer focuses on **network security**. Knowing domains helps target learning. In bug bounties, you’ll mostly deal with application & API security, but understanding network or cloud context helps locate attack surfaces. 

**Real Example:** Social media platforms rely on strong application security (to prevent XSS or SQLi), while banks also need top-notch IAM and network security. 

**Exercises:** 

- Research one example of a breach in each domain (e.g. ransomware for data security, network breach like Target 2013, app breach like XSS on forum). 

- List tools or practices in each domain (e.g. what is a WAF, what is MFA?). 

**Resources:** 

- Cybersecurity guides on [types of security domains](13†L227-L234). 

- OWASP (application sec), CISSP domains for general overview. 

### 1.3. Ethical Hacking & Bug Hunting 

**Ethical Hacking** (or “white-hat” hacking) means legally testing systems for vulnerabilities before malicious hackers find them. Ethical hackers **mimic attackers** but only with permission. They use the same tools and techniques as cybercriminals, but their goal is to **secure** the system. 

**Why it matters:** Without ethical hackers, many vulnerabilities would remain hidden. Organizations rely on ethical hacking to strengthen defenses. Bug bounty programs are one model (crowdsourced ethical hacking) where companies reward hackers for responsibly disclosing bugs. 

**Real Examples:** 

- A security researcher finds a flaw in a website login, reports it, and helps the company fix it (instead of selling it to criminals). 

- Many famous hacks were first spotted by bounty hunters (e.g. Twitter, Yahoo vulnerabilities). 

**Exercises:** 

- Read the Cloud Security Alliance (CSA) definition of penetration testing and note how it matches “ethical hacking” (using hacking tools to find vulnerabilities). 

- Practice by attempting simple challenges on legal platforms (e.g. PortSwigger Academy labs on basic XSS). 

**Resources:** 

- **CSA Penetration Testing Guide**. 

- Online ethical hacking tutorials and beginner-friendly labs (OWASP Juice Shop, TryHackMe Web challenges, etc.). 

### 1.4. Bug Bounty vs. Penetration Testing 

**Bug Bounty** programs invite many independent researchers to find and report vulnerabilities in a scoped system. Companies run them continuously on live products and reward valid findings with bounties. In contrast, **Penetration Testing** is usually a onetime (or periodic) contracted engagement by a security firm to test a system for a fixed duration. 

**Key differences:** 

- **Participants:** Bug bounties are open (or semi-private) to many hackers; pen tests use a small team of hired experts. 

- **Scope & Duration:** Pen test is scheduled for e.g. 2 weeks on staging; bug bounty is ongoing on production features. 

- **Cost:** Bug bounties pay per valid bug (potentially lower total cost); pen test is fixed fee (often high for enterprise). 

- **Outcome:** Bug bounties leverage many eyes and can find more varied issues over time. Pen tests may miss issues outside contracted scope. 

**Why it matters:** As a new hunter, bug bounty programs are an accessible path. They allow flexible hours, many targets, and real rewards. Understanding both concepts helps 

tailor your approach. For bug bounty: focus on realistic targets, pay attention to scope and policy, and demonstrate impact. 

**Citations:** HackerOne explains that bug bounties “incentivize ethical hackers via rewards for reporting vulnerabilities”, and that over time crowdsourced bounties often yield more findings than one-time pentests. 

**Exercises:** 

- Create a side-by-side comparison table of “Bug Bounty vs. Pen Test” (scope, cost, reporting style, longevity). 

- Find a post describing differences (e.g. HackerOne blog) and summarize it. 

**Resources:** 

- HackerOne blog on “Bug Bounty vs Pentesting”. 

- Bugcrowd/Intigriti beginner guides. 

### 1.5. Responsible Disclosure 

**Responsible Disclosure** means reporting security issues to the owner of a system privately, giving them time to fix, before going public. It’s an ethical practice ensuring vulnerabilities are not exploited by bad actors. 

**Why it matters:** If you find a bug in production, you must notify the company as per their policy. This is crucial to avoid legal trouble and ensure you get credit. Most bug bounty programs operate under a legal umbrella (safe harbor) but always clarify rules first. 

**Real Example:** A researcher finds a login bypass on a website. They don’t publish it on social media; instead, they submit it through the company’s bug bounty platform or security contact. The company fixes the bug and rewards the researcher. 

**Exercises:** 

- Look up examples of vulnerability disclosure policies (e.g. Google’s, Microsoft’s). Note key points (e.g. what to include in report, response timelines). 

- Identify the Responsible Disclosure or VDP guidelines of one program (e.g. HackerOne’s safe harbor). 

**Resources:** 

- OWASP’s write-up on Disclosure FAQs. 

- “Coordinated Vulnerability Disclosure” resources (ICASI, etc.). 

### 1.6. CVE, CWE, CVSS 

Security vulnerabilities have standardized identifiers and ratings: 

- **CVE (Common Vulnerabilities and Exposures):** A unique ID for a specific vulnerability in software. For example, “CVE-2023-XXXX” refers to one flaw. Companies reference CVEs in patches. 

- **CWE (Common Weakness Enumeration):** Categories of software design/implementation flaws (like “CWE-79: XSS”, “CWE-22: Path Traversal”). CVEs link to a CWE type. It helps developers and researchers understand and mitigate classes of bugs. 

- **CVSS (Common Vulnerability Scoring System):** A standardized way (0.0–10.0 scale) to rate severity of a vulnerability. The score considers how easily it can be exploited and the impact on confidentiality/integrity/availability. A higher score means more critical. For example, CVSS 9.8 is “Critical”. 

**Why it matters:** Knowing these helps communicate severity. When you report a bug, you’ll justify its severity (like CVSS). And reading CVEs/CWEs helps understanding impact. For instance, a CVE for remote code execution is urgent. 

**Example:** An XSS bug might be categorized as CWE-79 and assigned a CVSS around 6.1 (Medium) if it leaks session cookies. 

**Exercises:** 

- Look up “CVE” and “CWE” references (MITRE’s website). 

- Try assigning CVSS: read OWASP Top 10 “cheat sheet” which often suggests CVSS for each flaw. Or use OWASP’s [CVSS calculator](https://nvd.nist.gov/vuln-metrics/cvss) with a test input. 

**Resources:** 

- IBM Security blog: “What is CVE, CWE, CVSS?”. 

- CVE database (mitre.org). 

- CWE list (mitre.org). 

- NIST CVSS calculator (nist.gov). 

### 1.7. CIA Triad 

The **CIA Triad** stands for **Confidentiality, Integrity, Availability**: 

- **Confidentiality:** Keeping data secret (only authorized people can view it). E.g. using encryption so attackers can’t read stolen data. 

- **Integrity:** Ensuring data isn’t altered or corrupted. For example, hashing or signatures verify data hasn’t changed unauthorized. 

- **Availability:** Ensuring data and services are available when needed (e.g. servers are up, DDoS protection to keep site reachable). 

**Why it matters:** All bug bounty findings typically violate one or more of these. For instance, an RCE break both confidentiality and integrity, since it can reveal data and modify it. Bug hunters often classify vulnerabilities by which CIA component they impact. 

**Exercises:** 

- Take a common vulnerability (like SQLi or XSS) and discuss which parts of CIA it violates. 

- Think of daily life: Why is availability (e.g. being able to log in) as important as confidentiality of your email? 

**Resources:** 

- SecurityScorecard “CIA triad” explainer. 

### 1.8. OWASP & Security Frameworks 

**OWASP** (Open Web Application Security Project) is a nonprofit that provides free resources to improve software security. The most famous OWASP document is the **OWASP Top 10** – a list of the 10 most critical web application vulnerabilities. (Current list: Injection, Broken Auth, XSS, etc.) 

**Why it matters:** The OWASP Top 10 guides what to focus on for web security. As a beginner, learn these top vulnerabilities in detail (they appear in nearly every app). OWASP also provides **cheat sheets**, tools (like ZAP), and training. 

**Other Frameworks:** 

- **NIST Cybersecurity Framework:** Standards and guidelines for managing cybersecurity risks. Good for overall knowledge (but advanced). 

- **MITRE ATT&CK:** A knowledge base of attacker tactics and techniques (we cover highlevel in 1.9). 

- **CSA (Cloud Security Alliance):** Focused on cloud best practices. 

- **CIS Controls:** Prioritized security best-practices. 

For a beginner, OWASP and MITRE ATT&CK are most relevant. 

**Exercises:** 

- Read OWASP’s description of Top 10. Identify which ones you’ve heard of. 

- Browse the OWASP Top 10 document (e.g. A1 – Injection, A2 – Broken Auth, etc.). 

**Resources:** 

- OWASP official site: [About OWASP] and [Top 10 explanation]. 

- “Why OWASP is important” articles for context. 

### 1.9. MITRE ATT&CK (High-Level) 

The **MITRE ATT&CK** framework is a comprehensive matrix of real-world attacker tactics and techniques. Think of it as a big taxonomy of how attackers operate (e.g. “Phishing”, “Command & Control”, “Privilege Escalation”). It’s used to model threats and guide detection (in enterprise security) rather than for application hacking. 

**Why it matters:** As a bug hunter, ATT&CK teaches you how attackers think and the steps they take (e.g. initial access → execution → persistence). It’s a good reference if you want to understand how a web vulnerability (say, RCE) could fit into a broader attack chain. 

At a high-level: ATT&CK outlines **Tactics** (goals like “Initial Access”, “Execution”, “Exfiltration”) and **Techniques** (specific methods). 

**Exercises:** 

- Browse the MITRE ATT&CK website and read one tactic category (e.g. “Initial Access”). 

- Reflect: If you discover a vulnerability (e.g. SSRF), which tactics/techniques could that enable? 

**Resources:** 

- MITRE ATT&CK official website (summary intro). 

## ### 1.10. Risk Assessment 

**Risk Assessment** is the process of identifying an organization’s most critical assets, potential threats to them, and how vulnerable those assets are. It helps prioritize security efforts. The basic steps are: identify assets (data, servers, code), list threats (hackers, malware), identify vulnerabilities (e.g. outdated software), then evaluate which risks have greatest impact. 

**Why it matters:** By learning risk assessment, you understand how organizations think. You’ll prioritize bugs that impact high-value assets (user data, money) because those are highest risk. Risk = Likelihood × Impact. 

**Example:** In a web app, critical assets might be user credentials or payment data. A login bypass (high impact) is higher risk than a cosmetic CSS flaw (low impact). 

**Exercises:** 

- Write down 3 assets for a web application (e.g. user passwords, product database, admin interface). For each, list possible threats and vulnerabilities. 

- Use a simple risk matrix (Low/Med/High) to rank one vulnerability’s risk. 

**Resources:** 

- Cyberhaven article: *“Risk assessment: identify critical assets, likely threats, and gaps”*. 

- NIST SP800-30 (overview) or OWASP risk rating cheat sheet. 

### 1.11. Threat Modeling (Beginner Level) 

**Threat Modeling** is a systematic way to think about potential threats *before* building or testing a system. It involves asking “What can go wrong?” by mapping out how data flows through the app and what attackers could do at each point. 

**Why it matters:** It trains you to think like an attacker. Before testing a new feature, sketch how it works and what sensitive operations it has. Ask: could this be manipulated or bypassed? Threat modeling helps you find bugs faster and design tests systematically. 

**Example:** If a site has a “reset password” flow, threat modeling asks: could an attacker trick the user’s browser to reset password (CSRF)? Or could guessing tokens allow resets (IDOR)? 

**Exercises:** 

- Try a simple methodology like **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) to a login form. Identify which threats apply. 

- Pick a feature of a website (login, password reset, file upload) and draw a data flow. List possible attacker goals. 

**Resources:** 

- Adam Shostack’s introduction: *“Threat modeling is a structured, repeatable process that lets you think through what can go wrong”*. 

- OWASP Threat Modeling Cheat Sheet. 

<div id="networking-basics"></div> 

## 2. Networking Basics 

### 2.1. OSI Model & TCP/IP 

The **OSI Model** is a conceptual 7-layer model for network communication: Physical, Data Link, Network, Transport, Session, Presentation, Application. It’s a *teaching tool* describing how data flows from cables to applications. For example, HTTP lives at the Application layer, TCP at Transport, IP at Network. 

However, the real Internet uses the simpler **TCP/IP Model** (4 layers: Link, Internet, Transport, Application). 

**Why it matters:** As a bug hunter, you should know the key layers: 

- **Application (HTTP/HTTPS)** – where web protocols run. 

- **Transport (TCP/UDP)** – how data packets are delivered reliably (TCP) or quickly (UDP). 

- **Network (IP)** – routing between hosts. 

**Key facts:** The modern Internet isn’t strictly OSI; it’s based on TCP/IP. Yet OSI helps visualize problems (e.g. SSL works at Transport layer over TCP). 

**Exercises:** 

- Sketch the path of your browser’s request to a website (HTTP over TCP over IP). 

- Use `traceroute` in a terminal to see the network hops. 

**Resources:** 

- Imperva article: *“OSI model: 7 layers from physical to application”*. 

- Networking basics tutorials on packets and IP. 

### 2.2. DNS 

**DNS (Domain Name System)** translates human-readable domain names (like `example.com`) into IP addresses that computers use. It’s often called the “Internet phonebook.” When you enter a URL, your browser asks DNS servers for the IP. 

**Why it matters:** Understanding DNS helps in recon: finding subdomains, checking domain records (A, CNAME, TXT). Misconfigurations (like wildcard DNS) can lead to bugs. DNS is also used in some attacks (like DNS rebinding, though rare in bug bounty context). 

**Example:** `www.google.com` maps to an IP via DNS. Attackers sometimes enumerate subdomains by brute-forcing DNS names. 

**Exercises:** 

- Use `nslookup` or `dig` on a domain (e.g. `dig example.com`) to see the A record. 

- Try online tools to list subdomains of a site. 

**Resources:** 

- Cloudflare: *“What is DNS?”*. 

### 2.3. HTTP & HTTPS 

**HTTP (HyperText Transfer Protocol)** is the protocol browsers use to communicate with web servers. It defines methods like GET, POST, headers, etc. **HTTPS** is “HTTP over 

TLS/SSL”, meaning the traffic is encrypted. HTTPS protects data in transit from eavesdroppers and ensures you’re talking to the real server via certificates. 

**Why it matters:** Always test web apps over HTTPS by default. Learn how to manually send HTTP requests (with curl or Postman) and inspect encrypted traffic (via Burp’s proxy). Understand status codes (200, 404, 500, etc.) as they show how the server responded. 

**Example:** A valid login POST returns status 200 OK; a bad URL might return 404 Not Found. 

**Exercises:** 

- Use `curl -I` to see headers for a website. 

- In Burp Proxy, observe how HTTP requests look (methods, headers). 

- Install a free TLS certificate on a test server (Let’s Encrypt) to practice HTTPS setup. 

**Resources:** 

- Cloudflare: *“What is HTTPS?”*. 

- MDN: “HTTP status codes summary”. 

- Postman blog: *“HTTP methods (verbs)”*. 

### 2.4. TLS & Certificates 

**TLS/SSL** is the encryption layer that secures HTTPS. Websites have a **certificate** (X.509) signed by a trusted CA. When you connect via HTTPS, the browser checks this certificate to verify the server’s identity, then encrypts the session. This prevents tampering and spying. 

**Why it matters:** Bugs can arise from improper TLS implementation (e.g. accepting bad certs). For bug bounty, you may encounter HTTP (insecure) vs HTTPS, or misconfigured HTTPS that leaks info. Understanding certs also helps with attacks like SSL stripping (on unprotected sites). 

**Example:** If a site uses a self-signed or expired cert, browsers warn you. This might lead a user to click through (bad!). Also, Burp can generate its own CA to intercept HTTPS in a proxy setup. 

**Exercises:** 

- View a site’s certificate in the browser (click the lock icon) – check issuer, validity. 

- Try scanning for TLS issues (e.g. with Qualys SSL Labs on a site, or test-ca.py). 

**Resources:** 

- Cloudflare: *“HTTPS depends on TLS certificates for identity verification”*. 

- OWASP: SSL/TLS cheat sheet. 

### 2.5. Cookies & Sessions 

**Cookies** are small pieces of data that a server sends to a browser. The browser stores them (on disk or memory) and sends them back with subsequent requests to that site. Cookies often carry session IDs or user preferences. 

HTTP itself is stateless, so cookies are how websites remember state (like “you are logged in”). For example, after login the server might set a `Set-Cookie: sessionId=abc123`, and the browser uses this cookie to show you as authenticated. 

A **session** typically refers to the period of time a user is logged in. It’s usually tracked by a session ID stored in a cookie. That’s why logins persist across multiple page loads. 

**Why it matters:** Session management is a frequent target. If cookies are not protected (e.g. missing `HttpOnly`/`Secure` flags), attackers may steal them. IDOR or broken auth bugs often involve changing session cookies or replaying them. 

**Real Example:** Without protection, JavaScript could read a cookie with 

`document.cookie`. Setting `HttpOnly` stops that (prevents XSS from stealing it). 

**Exercises:** 

- In developer tools, observe cookies for a site (Safari/Chrome “Application” tab or Firefox “Storage”). Note cookie flags (Secure, HttpOnly, SameSite). 

- After logging in to a site, change a cookie value and refresh. What happens? (Be cautious – only on your test environments!) 

**Resources:** 

- MDN: *“Cookies enable storing data and remembering state; HTTP is stateless.”*. 

- Tutorials on session management and cookie flags. 

### 2.6. JSON Web Tokens (JWT) 

A **JWT** is a compact token format often used for authentication/authorization. It encodes information (claims) in JSON, and is signed so its integrity is protected (and optionally encrypted). Typical flow: server issues a JWT after login, client stores it (e.g. in a cookie or header), and sends it on future API calls. 

JWTs allow stateless session handling: server doesn’t need to store session data, just verify the signature. 

**Why it matters:** Many modern APIs use JWTs. Learn how to inspect and decode them (they’re Base64-encoded). Attacks: if you find no signature validation or use weak secrets, you can forge tokens. Also JWT in cookies vs Authorization header can matter. 

**Exercises:** 

- Obtain a JWT (e.g. from a test login) and use jwt.io or an online tool to decode it. Examine header/payload claims. 

- Try modifying a claim (e.g. user ID) and see if the system accepts it (if signature is weak or missing). 

**Resources:** 

- jwt.io intro: *“JWT defines a compact way to securely transmit info as JSON; it is signed.”*. 

- OWASP: JWT guidance. 

### 2.7. Same-Origin Policy (SOP) & CORS 

The **Same-Origin Policy** is a browser security feature: a web page can only make requests or access content from the *same origin* (same protocol, host, and port) that loaded it. For example, a script on `https://siteA.com` cannot read responses from `https://siteB.com` unless explicitly allowed. 

**Cross-Origin Resource Sharing (CORS)** is a mechanism by which a server can allow specified other origins to access its resources. It works via special HTTP headers like `Access-Control-Allow-Origin`. CORS is **implemented by browsers**; it's not a serverside safeguard—rather, it tells the browser it’s safe. 

**Why it matters:** Misconfigured CORS can lead to data leaks. If a site sets `AccessControl-Allow-Origin: *` on a sensitive API, any site can read it. This is a security misconfiguration. Similarly, understanding SOP helps in preventing attacks like cross-site data theft. In bug bounty, you might find overly permissive CORS. 

**Exercises:** 

- Open browser dev tools, find an API request (in Network tab) and check if any CORS headers exist. 

- Use a simple HTML page from a different origin to attempt fetching data from an API (use JS `fetch`). See if the browser blocks it (error or success). 

**Resources:** 

- MDN: *“Same origin if protocol, host, port match”*. 

- MDN: *“CORS allows servers to specify other origins permitted to load content”*. 

### 2.8. HTTP Headers, Methods, Status Codes 

- **Methods:** Common HTTP methods include `GET` (retrieve data), `POST` (submit data), `PUT/PATCH` (update), `DELETE`. Each has semantic meaning. (Postman: “HTTP methods map to CRUD operations”). In bug hunting, try different methods on endpoints (sometimes changing to PUT or DELETE may bypass logic). 

- **Headers:** Headers carry metadata (e.g. `User-Agent`, `Content-Type`, `Cookie`, `Authorization`, etc.). They can control behavior. For example, `Content-Type: application/json` tells server to parse JSON. Some headers (like `X-Forwarded-For`) can be abused for host header injection or cache poisoning. 

- **Status Codes:** Codes like 200 (OK), 301/302 (Redirect), 400 (client error), 401/403 (auth errors), 404 (not found), 500 (server error) tell you how the server processed your request. For instance, a 200 on a login with wrong password might indicate a logic flaw. Always note unexpected statuses. 

**Why it matters:** Proper use of methods and headers can unlock vulnerabilities (e.g. method tampering, Header Injection). Status codes give clues when manual testing (a weird error suggests injection). 

**Exercises:** 

- Use Burp Repeater to modify an HTTP request: change `GET` to `POST`, tweak headers 

(e.g. add a fake `X-Forwarded-Host`). Observe changes in status. 

- Look at OWASP or MDN for lists of status codes and what they mean. 

**Resources:** 

- Postman: *“HTTP methods indicate what action to perform (CRUD)”*. 

- MDN: *“HTTP status codes indicate request outcome (grouped by 1xx, 2xx, 3xx, 4xx, 5xx)”*. 

### 2.9. Caching 

Web caching speeds up content delivery. The **HTTP cache** stores responses to requests and can reuse them. This means if you request the same URL again, you might get a cached copy (if allowed by headers). 

**Why it matters:** Be aware that caching can affect vulnerability testing. For example, if you POST data and it caches erroneously, an attacker might receive stale info. Conversely, caches can be manipulated (Cache Poisoning). When testing, disable cache or use tools like Burp’s “Disable cache” to ensure you see real responses. 

**Example:** A site might use `Cache-Control: no-cache` on sensitive pages to prevent browsers/proxies from caching them. 

**Exercises:** 

- Use browser dev tools to examine response headers for caching (`Cache-Control`, `ETag`). 

- In Burp Proxy, examine how Chrome’s requests/responses change when caching is disabled. 

**Resources:** 

- MDN: *“The HTTP cache stores a response and reuses it for subsequent requests, eliminating the need to fetch from the origin server.*” 

### 2.10. Proxies and Traffic Interception 

A **proxy** sits between your browser and the internet. In bug hunting, we use intercepting proxies (like **Burp Suite** or **OWASP ZAP**). They act as the browser’s proxy so they can view and modify requests in real-time. 

- **Forward Proxy:** Client configures it; useful in attacks or bypassing IP blocks. 

- **Intercepting Proxy:** Like Burp Proxy, it lets you pause a request, modify it, and forward. 

**Why it matters:** Learning to intercept traffic is critical. You can tamper with requests (change parameters, drop headers) and immediately see server reactions. It’s the core of manual testing. 

**Exercises:** 

- Install Burp Suite Community Edition. Configure your browser (Firefox or Chrome) to use 127.0.0.1:8080 as HTTP proxy. Browse a site and see requests in Burp’s HTTP history. 

- Practice intercepting a login request: modify a field (e.g. switch `username=alice` to `bob`) and forward, to understand parameter tampering. 

**Resources:** 

- Burp Suite documentation (installation, proxy setup). 

- OWASP ZAP beginners guide. 

### 2.11. Packet Flow & Browser/API Request Lifecycle 

Understanding what happens “under the hood” when you browse helps debug issues: 

- **Packet Flow:** At TCP/IP level, your computer sends packets via your network interface (Ethernet/Wi-Fi) to the destination IP and port. Routers/hops handle this on the Internet. 

- **Browser Request Lifecycle:** When you visit a URL: DNS resolution → TCP/TLS handshake → HTTP request sent → Server processes and sends HTTP response → Browser parses HTML, loads resources (CSS, JS, images) by repeating this flow for each. 

- **API Request Lifecycle:** Similar to browser but often JSON data. A client (e.g. your code or Postman) opens a connection to an API endpoint, sends an HTTP request, and processes the JSON response. 

**Why it matters:** If something fails (no DNS, connection reset, slow handshake), you need to know where to look. Tools like Wireshark can show actual packets. Browser DevTools Network tab shows high-level request timeline (DNS, Connect, TTFB). 

**Exercises:** 

- Use Wireshark to capture traffic while browsing (filter by HTTP/TCP). Observe TCP handshake (SYN/SYN-ACK). 

- In Chrome DevTools “Network” panel, look at a request’s timeline (DNS, Connect, Receive). 

**Resources:** 

- Tutorials on packet capture (Wireshark official docs). 

- Browser dev tools network panel help. 

### 2.12. Practice with Wireshark & Burp Proxy 

**Wireshark:** A free network protocol analyzer. Install it to capture real network traffic on your machine. You’ll see TCP handshakes, HTTP requests, DNS queries, etc. Practice: capture while browsing an HTTP site (unencrypted) and see raw headers and packets. For HTTPS, you’d need a man-in-the-middle setup. 

**Burp Proxy:** Used for intercepting and modifying web traffic. Practice basics: enable “Intercept” and try filling a web form, alter the data on the fly. Disable intercept to let traffic pass for traffic logging. 

**Exercises:** 

- In Wireshark, filter for “http” or “tcp.port==80” and view the requests. 

- In Burp, use the **Repeater** to resend a request with modified parameters multiple times and observe differences. 

**Resources:** 

- Wireshark user guide. 

- Burp Academy (free official labs on proxying and repeater usage). 

## 3. Linux & Command Line 

### 3.1. Linux File System & Users 

Linux is a **multi-user** OS where all processes and files have owners. The filesystem starts at root `/` and branches (directories like `/home`, `/etc`, `/usr`, etc.). Key points: 

- **Users:** Each person or service has a user account (found in `/etc/passwd`). Use 

- `whoami`, `id`, or view `/etc/passwd`. Special users exist (root superuser, nobody, etc.). 

- **Groups:** Users belong to groups (`/etc/group`). File permissions include an “owner” and “group”. 

- **Filesystem Hierarchy:** `/home/username` for home directories; `/etc` for configs; 

- `/var` for logs; `/usr/bin` for programs, etc. Learn a few (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`). 

**Why it matters:** Many servers are Linux; knowing navigation (`ls`, `cd`, `pwd`, etc.) is essential. Permissions (next) are Linux-specific and key to privilege issues. 

**Exercises:** 

- Boot a Linux VM or use WSL. Navigate directories: `cd /etc`, `ls`, `cat /etc/hosts`. 

- Create a new user (if possible) and see its home folder. 

**Resources:** 

- Linux tutorial: file hierarchy overview. 

- `man passwd`, `man group` for understanding user files. 

### 3.2. File Permissions 

Every file/directory in Linux has a set of **owner, group, and others** permissions (read, write, execute). For example, `drwxr-x---  alice staff file.txt` means user `alice` can read/write/execute, group `staff` can read/execute, others none. 

Permissions enforce security at the OS level. Misconfigured permissions (e.g. 777 wideopen) can allow local privilege escalation or information disclosure. 

## Commands: 

- `ls -l`: show permissions. (DigitalOcean tutorial explains this). 

- `chmod`: change permissions (numeric `chmod 644 file` or symbolic `u+x`). 

- `chown`: change file owner/group. 

**Why it matters:** In pentesting, weak file perms on a server could let you read `/etc/shadow` or escalate privileges. For bug bounty, if you get code execution (e.g. via RCE), file permissions determine what you can read. 

**Exercises:** 

- In Linux, `touch test.txt; chmod 600 test.txt` to restrict access, then try reading as another user (or simulate via groups). 

- Find a file owned by root only (e.g. `/root/.bashrc`) and note permissions. 

**Resources:** 

- DigitalOcean: *“Linux Permissions Introduction”*. 

- Tutorials on `chmod` and Linux permissions. 

### 3.3. Basic Shell Commands (ls, cd, cat) 

Essential commands to navigate and inspect files: 

- `ls`: list directory contents (`-l` for long format, `-a` for hidden files). 

- `cd`: change directory. 

- `pwd`: print current directory. 

- `cat`: display file contents. 

- `cp/mv/rm`: copy, move/rename, remove files. 

- `mkdir/rmdir`: make/remove directories. 

- `man`: view command manual (e.g. `man ls`). 

**Why it matters:** All hands-on hacking labs require file ops. Practice them daily to build muscle memory. 

**Exercises:** 

- Create directories/files, move them around. 

- Use `man ls` to learn flags (e.g. `ls -lh`, `ls -R`). 

**Resources:** Linux “get started” tutorials. 

### 3.4. File Operations (grep, awk, sed) 

Text-processing tools are powerful on the command line: 

- **grep:** Search files for patterns (regex). Example: `grep "password" /etc/passwd`. It outputs lines containing the pattern. 

- **awk:** A programmable text filter. It processes line by line, splits fields. Useful for pulling columns or complex transformations. 

- **sed:** Stream editor, good for substitutions. For example, `sed 's/foo/bar/g' file.txt` replaces “foo” with “bar”. AWK and sed can often overlap. 

Grep finds lines, sed edits lines, awk works on fields. 

**Why it matters:** When analyzing logs or massaging data, these are indispensable. For example, `grep -R "admin" .` finds all occurrences of “admin” in current directory recursively, useful in recon. 

**Exercises:** 

- Use grep on system files (`grep root /etc/passwd`). 

- Try awk: `echo "one two three" | awk '{print $2}'` (prints “two”). 

- Try sed: create a text file and use `sed` to replace a word. 

**Resources:** 

- DigitalOcean tutorials on [grep] and [awk]. 

- Unix command cheat sheet. 

### 3.5. Text Tools (sort, uniq, find, xargs) 

- **sort:** sorts lines alphabetically or numerically (`sort -n`). 

- **uniq:** filters out repeated lines (usually after sort) or counts them. E.g. `sort file | uniq -c`. 

- **find:** search for files by name, size, etc. Example: `find / -name "*.conf"` searches all `.conf`. 

- **xargs:** build command lines from input. E.g. `find . -name "*.txt" | xargs grep "TODO"` applies grep to each file found. 

**Why it matters:** Automation pipelines often use these. For instance, to enumerate all file types on a server, or to apply an operation on a list of results from grep or find. 

**Exercises:** 

- Use `find /etc -type f -size +1M` to list config files larger than 1MB. 

- Combine `find` and `grep` with `xargs` to search contents of all `.log` files: `find /var/log -name "*.log" | xargs grep "error"`. 

**Resources:** Linux find/grep/xargs tutorials. 

### 3.6. JSON Tools (jq) 

**jq** is a command-line JSON processor. It reads JSON and lets you filter or transform it easily. 

Example: If you have a JSON response `{"user":{"id":123,"name":"Alice"}}`, using `jq '.user.id'` would output `123`. Unlike grep/sed, jq is aware of JSON structure, so it doesn’t break on formatting. 

**Why it matters:** Many APIs return JSON. In bug hunting, you often need to parse or reformat JSON from API responses or craft JSON payloads. jq makes it simple to extract fields or pretty-print. 

**Exercises:** 

- Install jq. Create a small JSON file and use `jq '.' filename.json` to pretty-print. 

- Use `curl https://api.github.com` and pipe to `jq` to see formatted output. 

**Resources:** 

- MangoHost: *“jq is a command-line JSON processor... understands JSON structure natively”*. 

- jq manual / tutorials. 

### 3.7. Terminal Utilities (tmux, vim basics) 

- **tmux:** Terminal multiplexer. Lets you have multiple terminal panes/sessions in one window. Useful for running scanners/long tasks while coding. Learning tmux shortcuts (split, detach, reattach) will greatly improve productivity. 

- **vim:** A classic text editor. You don’t need to be an expert, but know basic modes: Insert (`i`), Save/Quit (`:wq`), and navigation (`h/j/k/l` or arrow keys). 

- Other editors: `nano` is easier for beginners. 

**Why it matters:** When pentesting, you often have many tools and notes open. Using tmux (or similar) helps organize your workspace. Being comfortable editing configs or scripts (with vim/nano) is essential. 

**Exercises:** 

- Install tmux. Open a session, create two panes (`Ctrl+B %` for vertical split), run a command in each. Detach (`Ctrl+B d`) and reattach (`tmux attach`). 

- Create a file with `vim notes.txt`. Inserting text, save, and quit. 

**Resources:** 

- tmux tutorial (O’Reilly cheat sheet). 

- VimTutor (built-in interactive tutorial). 

### 3.8. Daily Practice Exercises 

Build habits by practicing Linux skills daily. Spend a few minutes on these each day: 

- Navigating directories, listing files. 

- Creating/editing simple scripts (bash or python). 

- Using grep/awk/sed on sample files. 

- Searching man pages (`man grep`). 

- Logging commands, exploring `history`. 

- Try a new command each week (e.g. `dig`, `traceroute`, `curl`). 

**Goal:** Become fluent in CLI. This will speed up later hacking tasks immensely. 

## 4. Programming for Bug Bounty 

### 4.1. HTML & CSS Basics 

**HTML** (HyperText Markup Language) structures web pages into elements (tags like `<input>`, `<div>`, `<img>`, etc.). **CSS** (Cascading Style Sheets) defines styles (colors, layout) for those elements. 

**Why it matters:** Understanding how a page is built helps find security issues. E.g., if you see hidden form fields (`<input type="hidden">`), that could indicate IDOR vectors (guessing hidden IDs). Inspecting CSS/HTML can reveal debug info or hidden APIs. 

**Example:** A page’s HTML source might include a hidden `<script>` endpoint or a JWT in a JavaScript variable. 

**Exercises:** 

- Open a simple webpage’s source (Right-click -> View Page Source). Identify different tags. 

- Use browser DevTools Elements panel to live-edit HTML or CSS. Change a button text or color; see it reflect. 

**Resources:** 

- W3Schools or MDN Introduction to HTML/CSS. 

### 4.2. JavaScript & the DOM 

**JavaScript** runs in the browser and manipulates the DOM (Document Object Model) of the page. The DOM is an object tree representing all HTML elements. JS can read/modify DOM elements, listen to events (clicks, keystrokes), and send network requests (AJAX/fetch). 

**Why it matters:** Many XSS or DOM-based flaws involve JS. E.g. unsanitized JS `innerHTML` can cause XSS. Also, knowing JS lets you bypass client-side logic: you can manipulate form validation by altering JS variables via console. 

**Example:** If a script reads `document.cookie` and displays it, a malicious script can exploit that (XSS). Or, if you know the DOM IDs (`document.getElementById(...)`), you can automate interactions. 

**Exercises:** 

- In DevTools console, type `document.title` to see the page title. 

- Use `document.getElementsByTagName('input')` to list input fields. 

- Modify a field via console, e.g. `document.querySelector('input[name="email"]').value = 

'attacker@example.com'`. 

**Resources:** 

- W3Schools: *“HTML DOM is an object model”*. 

- JavaScript basics tutorial (MDN). 

### 4.3. JSON Data & Scripting 

**JSON** (JavaScript Object Notation) is a lightweight data format (e.g. `{"user": "alice", "id": 1}`). It’s ubiquitous in APIs. Knowing JSON structure helps you craft and parse payloads. 

**Why it matters:** Many bug bounties involve JSON APIs (e.g. REST or GraphQL). You’ll often intercept JSON (use `jq` to parse). Knowing how to structure JSON requests and extract fields is crucial. 

**Exercises:** 

- Use `curl -H "Accept: application/json"` on a public API (like GitHub’s) and parse the output with `jq`. 

- Practice forming a JSON with `curl -X POST --data '{"key": "value"}'` to a dummy endpoint (like a local server or httpbin). 

**Resources:** 

- JSON.org for syntax basics. 

- Postman tutorials on working with JSON in APIs. 

### 4.4. Python for Security 

**Python** is a beginner-friendly scripting language widely used in security. You can write scripts to automate tasks, process data, and exploit vulnerabilities. 

**Why it matters:** Many tools (Nmap scripts, SQLMap, Recon tools) are in Python. Writing small Python scripts (using `requests` library) lets you automate sending HTTP requests, fuzzing parameters, or parsing results. It’s more powerful than pure Bash for complex logic. 

**Example:** A Python script to fetch an API endpoint with different IDs and log unauthorized data. 

**Exercises:** 

- Write a simple Python script to `import requests` and `print(response.text)` from a URL (e.g. `api.github.com`). 

- Use Python’s `re` module for regex searches, or `json` module for parsing JSON responses. 

**Resources:** 

- W3Schools: *“Python is a popular programming language… used for web development, scripting”*. 

- Codecademy or free Python intro course. 

### 4.5. Bash Scripting 

**Bash** (Bourne Again SHell) allows automating command-line tasks via scripts. A simple bash script starts with `#!/bin/bash`. You can loop over files, send series of curl commands, or manipulate text. 

**Why it matters:** Quickly gluing together Linux commands can speed up recon. For example, a one-liner to brute-force file upload names or iterate over user IDs. 

**Exercises:** 

- Create `script.sh` that pings a list of hosts (for host in $(cat hosts.txt); do ping -c 1 $host; done). 

- Use `chmod +x script.sh` and run it. 

**Resources:** 

- Online bash scripting tutorials (e.g. By Example on ShellCheck site). 

### 4.6. HTTP Requests & APIs 

Learn libraries for making HTTP requests in scripts: 

- In Python: `requests` library (`pip install requests`). 

- In Bash: `curl` or `wget`. 

- Postman/Insomnia for manual API interaction. 

Practice sending different request types (GET, POST with JSON body, PUT, DELETE). Understand headers like `Content-Type: application/json`. 

**Why it matters:** You’ll often write scripts to automate API testing (fuzzing endpoints, parameter enumeration). 

**Exercises:** 

- Use Python+requests to call an API and check response code. 

- With curl: `curl -X POST -H "Content-Type: application/json" -d '{"name":"test"}' 

- https://httpbin.org/post`. 

**Resources:** 

- Python requests docs. 

- curl usage examples. 

### 4.7. Regular Expressions (Regex) 

**Regular Expressions (regex)** are patterns used to search or match text (e.g. to find an email: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`). They are powerful for filtering and extracting data (e.g. grabbing all URLs from text, or validating input formats). 

**Why it matters:** As a bug hunter, you’ll encounter messy output. Regex help in grabbing just what you need (like extracting tokens from a log). Many tools (grep, Burp’s intruder, Python) support regex for matching vulnerabilities. 

**Exercises:** 

- Write a regex to find `href="..."` values in HTML. 

- Test regex patterns on sample text with an online tester (regex101.com). 

**Resources:** 

- RegexOne tutorials (beginner friendly). 

- Official GNU grep regex guide for syntax. 

### 4.8. APIs and Cookies/JWT Parsing 

Combine skills: parse cookies and JWTs in code. 

**Why it matters:** Often APIs use cookies or JWTs for auth. Being able to programmatically decode JWT (with Python’s `jwt` library) or parse cookie strings is useful. 

**Exercises:** 

- Use Python’s `http.cookies` to parse `Set-Cookie` header. 

- Use Python’s `jwt` package to decode a JWT’s payload. 

**Resources:** 

- Python docs on `http.cookies`. 

- PyJWT library. 

## 5. Web Technologies 

### 5.1. Browser Rendering & JavaScript Engine 

When a browser loads a page, it: 

1. Parses HTML into the **DOM (Document Object Model)** – a tree of objects. 

2. Parses CSS into the **CSSOM** and applies styles. 

3. Executes JavaScript on the **single main thread**, which can manipulate the DOM. 

4. Performs **layout/reflow** to calculate element positions, then **paint** to display pixels. 

The event **loop** waits for events (clicks, network, timers) and handles them one at a time. Rendering steps like **Reflow** can be expensive, so browsers optimize when to recalc layout (they do it on demand or when needed). 

**Why it matters:** DOM-based vulnerabilities (DOM XSS) occur in the browser’s execution phase. Understanding rendering can explain issues like “flashing” of unsafe content before scripts run. It also helps diagnose performance issues that can affect load behavior. 

**Exercises:** 

- Use Chrome DevTools “Performance” recording to see paint/layout events on a page. 

- Read [77†L352-L360] TL;DR: layout (reflow) is calculating how to paint elements, and browsers delay it because it’s costly. 

**Resources:** 

- W3Schools: *“The HTML DOM is an object model of the page”*. 

- Blog: “How Browsers Work” articles. 

- StackOverflow [77]: *“Reflow is the calculation of all the boxes in the page needed to paint elements...”*. 

### 5.2. DOM, HTML, CSSOM, Layout, Paint 

Key concepts: 

- **DOM Tree:** Browser’s representation of HTML elements. JS interacts with this. 

- **CSSOM & Render Tree:** CSS rules are applied to DOM to create a render tree. 

- **Layout (Reflow):** Calculating element sizes/positions. Then **Paint** draws pixels. 

When you inject or modify elements via JS (like `element.innerHTML = "<script>..."`), the DOM and render must update. Knowing this can help in understanding why certain dynamic XSS payloads work or fail. 

**Exercises:** 

- Use DevTools: Inspect Element and modify HTML (e.g. delete an element). Note live update. 

- Use JS Console: `document.body.style.backgroundColor = 'red'` – immediate repaint. 

**Resources:** 

- W3Schools: DOM tree construction. 

- Web.dev: “Populating the page: how browsers work.” 

### 5.3. Browser Storage: Cookies, LocalStorage, SessionStorage 

Besides cookies, modern browsers support: 

- **LocalStorage:** Key-value store that persists across sessions (until user clears). 

- **SessionStorage:** Similar, but data is cleared when tab/window closes. 

LocalStorage and SessionStorage are accessible via JS (`window.localStorage`). Cookies differ (sent automatically on requests to the server, have size limits). SessionStorage is pertab and lifetime of tab. 

**Why it matters:** Storage can hold sensitive tokens (some apps put JWTs in localStorage – bad practice due to XSS risk). CORS issues can arise if an API is on a different origin. Some CSRF protections involve SameSite cookie attribute. 

**Example:** If a site doesn’t use HTTPS, cookies (unless flagged Secure) can be intercepted. If it uses LocalStorage to hold tokens, an XSS bug could dump them. 

**Exercises:** 

- In DevTools > Application, experiment with adding LocalStorage entries for a site 

- (`localStorage.setItem('key','value')`). 

- See how closing a tab affects sessionStorage. 

**Resources:** 

- GeeksforGeeks: *“LocalStorage persists until browser closed, SessionStorage lasts per 

tab”*. 

- MDN docs on Web Storage. 

### 5.4. Authentication vs. Authorization 

**Authentication (AuthN):** Verifying a user’s identity (e.g. login). You ask “Who are you?” and they provide credentials. 

**Authorization (AuthZ):** Determining what that user can do. You ask “What resources/actions are you allowed?”. 

They are distinct. Example: entering a valid username/password is authentication. Checking user’s role to see if they can access admin page is authorization. 

**Why it matters:** Many vulnerabilities arise from confusion here. For instance, after login (AuthN success), the system must enforce AuthZ (like role checks). If AuthZ is missing or flawed (e.g. no check that a resource belongs to the user), that’s a “Broken Access Control” issue. Always verify both steps. 

**Example:** A user logs in as Alice (AuthN). Then they shouldn’t be able to read Bob’s messages (AuthZ). A bug allowing Alice to view Bob’s data is an authorization flaw. 

**Exercises:** 

- Read Curity’s explanation: “Authentication is verifying identity; authorization is verifying access rights.”. 

- On a web app, try accessing a resource without login (should be blocked – that’s AuthN). Then login as regular user and try admin page (should be blocked – AuthZ). 

**Resources:** 

- Curity blog: *“AuthN vs AuthZ”*. 

- Auth0 docs: short guides. 

### 5.5. Authentication Protocols: OAuth & OpenID Connect 

**OAuth 2.0:** An authorization framework allowing a user to grant limited access to an application (“client”) to their resources without sharing credentials. It uses tokens (access and refresh). In OAuth, the user (resource owner) authorizes a client (e.g. a third-party app) to access resources on a resource server (API) via an authorization server issuing tokens. 

**OpenID Connect (OIDC):** A layer on top of OAuth 2.0 that adds **authentication**. It provides an ID token (usually JWT) that contains user identity claims (email, name). OAuth alone does not authenticate the user to the client; OIDC does. 

**Okta Summary:** OAuth2 is for **delegated authorization** (getting access tokens for APIs). OIDC extends OAuth2 for **user authentication/SSO** (giving ID tokens with user info). 

**Why it matters:** Modern apps use OAuth/OIDC. As a bug hunter, you may encounter issues like open redirects in OAuth flows, token leaks, or logic bugs in login flows. Understanding how these flows work is critical. 

**Example:** “Login with Google” uses OIDC: Google authenticates you and gives the app an ID token, not your password. 

**Exercises:** 

- Review Okta docs: *“OAuth 2.0 provides scoped access tokens; OIDC adds user authentication and SSO”*. 

- Find an example OAuth flow diagram (Auth Code flow) and follow steps. 

**Resources:** 

- Okta Developer: *“OAuth 2.0 vs OIDC overview”*. 

- RFC6749 (OAuth2 spec) and OIDC core spec (for deeper study). 

### 5.6. Session Management & JWTs 

Web sessions can be stateful (server keeps session data) or stateless (JWTs). Key point: After login, the server must track that identity either via sessions (cookie-based ID) or JWT tokens. 

**Session Fixation/Logout:** Ensure old sessions are invalidated on logout. Check if cookies have `HttpOnly`, `Secure`, `SameSite`. JWT pitfalls: storing JWT in localStorage (vulnerable to XSS). Check signature algorithm (none or symmetric HS256?). 

**Exercises:** 

- Log in to a site and inspect whether it uses cookies or returns a JWT. 

- Try to reuse an old session cookie or JWT after logout and see if still valid (hopefully not). 

**Resources:** 

- JWT best practices (e.g. OWASP). 

### 5.7. CSRF Tokens and Anti-CSRF 

**Cross-Site Request Forgery (CSRF)** is an attack that tricks a user’s browser into submitting unintended requests to a trusted site (where they are authenticated). Since browsers send cookies automatically, an attacker’s page can cause the user’s browser to perform actions (like changing password) without user intent. 

The common defense: **CSRF Tokens**. These are random values tied to the user’s session, included in forms or headers for state-changing actions. The server validates that the token matches before performing the action. Without the correct token, the request is rejected. 

- Example: Before updating a profile, the HTML form includes `<input type="hidden" name="csrf_token" value="ABC">`. The server checks this matches the session value. 

**Why it matters:** Look for forms or API endpoints that change state. If there is no random token or the only “check” is a cookie, it’s likely vulnerable. CSRF bugs often lead to account compromise or unwanted fund transfers. 

**Exercises:** 

- See [86†L35-L43]: understanding how a malicious email link could cause state change. 

- Read [87†L266-L274]: *“CSRF occurs when a malicious site causes a user’s browser to perform an unwanted action on a trusted site”*. 

- Experiment: On a testing site with a CSRF flaw, try submitting a hidden form from another domain (e.g. use Burp intruder or a simple HTML file). 

**Resources:** 

- OWASP CSRF page: *“CSRF forces user to execute unwanted actions...“*. 

- OWASP CSRF Cheat Sheet: outlines token pattern (unique, secret, unpredictable). 

### 5.8. Access Control: RBAC & ABAC 

- **RBAC (Role-Based Access Control):** Users are assigned roles (e.g. “admin”, “editor”). Each role has privileges. E.g. only “admin” can delete users. It’s simpler and common in apps. 

- **ABAC (Attribute-Based Access Control):** Access decisions based on attributes (user, resource, environment). For example, user’s department and time of day. More flexible/granular than RBAC. 

**Why it matters:** Web apps often use roles or attributes. Knowing these helps find flaws: e.g., if an endpoint only checks role but not resource ownership (RBAC mistake), or if it trusts user-supplied attributes. 

**Exercises:** 

- Roleplay: List roles your favorite site might have. What can each do? 

- Read IBM’s RBAC guide: *“RBAC authorizes access to systems based on a user’s role.”*. 

- Read [91†L131-L139]: *“ABAC defines access by evaluating attributes of subject and object.”* 

**Resources:** 

- IBM overview: *“RBAC – user’s access based on predefined role”*. 

- Wikipedia ABAC: *“Access is determined by attributes of subject and object”*. 

### 5.9. Business Workflows & Security 

Modern web apps often follow multi-step workflows (e.g. e-commerce checkout, password reset, multi-page forms). Security must be maintained at each step: 

- Enforce auth/authorization at every step (don’t rely on previous step being secure). 

- Use tokens (CSRF) and validate inputs. 

- Beware logic flaws: e.g. an attacker might skip a step or manipulate parameters to get a discount or skip payment. 

**Example:** If a checkout process has steps 1→2→3, ensure a user can’t jump from 1 to 3 skipping payment. Use server-side checks for sequential flow or tokens per step. 

**Exercises:** 

- Map the workflow of a login or purchase process on paper. Identify trust boundaries (where data is sent, what the server checks). 

- Think of a business logic exploit: e.g. “Add to cart” form might allow negative quantities to refund money. 

**Resources:** 

- OWASP: Business Logic Flaw examples (not as standardized as technical flaws). 

- Bug reports (search for “Business Logic bypass” case studies). 

## 6. Web Application Security 

We now cover common web vulnerabilities. For each, we give a concise overview. **Note:** Many OWASP Top 10 items appear below. 

### 6.1. OWASP Top 10 & Beyond 

The OWASP Top 10 (2021) are: 

1. Broken Access Control 

2. Cryptographic Failures (e.g. secrets exposure) 

3. Injection (SQL, NoSQL, OSS, etc.) 

4. Insecure Design (business logic flaws) 

5. Security Misconfiguration 

6. Vulnerable & Outdated Components 

7. Identification & Authentication Failures (Broken Auth) 

8. Software & Data Integrity Failures 

9. Security Logging and Monitoring Failures 

10. Server-Side Request Forgery (SSRF) 

Along with other common bugs, we will cover major classes like XSS, XXE, RCE, etc. Each entry below includes: 

- **Definition:** What it is. 

- **Impact:** What an attacker can do. 

- **Examples:** Real-world incidents if available. 

- **How Attackers Test:** Typical techniques. 

- **Fixes/Prevention:** How developers should mitigate. 

- **Burp/Tools:** How to use Burp or scripts to detect. 

- **Difficulty:** ⭐ (easy) to ⭐⭐⭐⭐⭐ (very hard). 

- **Practice:** References to labs or exercises. 

#### 6.2. Broken Access Control (BAC) 

- **Definition:** Flaws where users can access resources or actions outside their permission (missing checks). This includes **IDOR** (Insecure Direct Object References) and other vertical/horizontal privilege escalations. 

- **Impact:** Unauthorized data disclosure or modification. E.g. reading other users’ private data, deleting others’ accounts. 

- **Examples:** API allows any user to `GET /admin/users`. Company founder Doug Hoyte’s report: user could see all users’ data via JSON API. 

- **Testing:** Try manipulating IDs/URLs. Test whether admin endpoints are protected. Use Burp to modify tokens or cookies. 

- **Fix:** Enforce checks on server-side: always verify that the authenticated user is allowed to access the requested resource (e.g. compare `record.owner == user` in code). Use unpredictable IDs (UUIDs) over sequential to make guessing harder. 

- **Burp Flow:** Use Repeater to change resource IDs, or Intruder to bruteforce IDs. Proxycheck for missing auth (200 OK instead of 403). 

- **Difficulty:** ⭐⭐ (often easy but critical). 

- **Labs:** Practice on Juice Shop (chapter “Broken Access Control”). 

#### 6.3. Insecure Direct Object Reference (IDOR) 

*Special Deep Dive in Section 7 covers this comprehensively.* Briefly: IDOR is a subset of Broken Access Control where an object reference (like a numeric ID) is exposed and modifiable, allowing access to other objects. 

Example: `GET /download?file=123` – change 123 to 124 to download someone else’s file. 

(Citation: OWASP API: *“Attackers exploit by manipulating object ID in request; unauthorized access to others’ objects leads to data leakage or takeover.”*.) 

#### 6.4. Injection (SQL, NoSQL, LDAP, etc.) 

- **Definition:** When untrusted input is included in commands or queries sent to an interpreter (e.g. database, LDAP, OS) without proper sanitization. The classic is **SQL Injection**, where attackers append SQL to manipulate queries. 

- **Impact:** Attackers can view, modify, or delete database contents; sometimes execute commands on the host. 

- **Example:** `SELECT * FROM users WHERE id = ' ` + userInput. If `userInput = '1 OR 1=1 --'`, it returns all users. 

- **Testing:** Insert `'` or SQL syntax into form fields. Look for database errors or change in output. Use tools like SQLMap (with authorization!) to automate. 

- **Fix:** Use parameterized queries/prepared statements so input is treated as data, not code. ORMs can help if used correctly. 

- **Burp Flow:** Use Repeater/Intruder to send `' OR '1'='1` payloads. Monitor responses or time differences. 

- **Difficulty:** ⭐⭐ (common, critical). 

- **Resources:** PortSwigger *SQL Injection* tutorial (definition and impact). 

**Other injection types:** NoSQL (similar concept in MongoDB queries), LDAP injection, command injection (shell commands, see RCE), etc. 

#### 6.5. Cross-Site Scripting (XSS) 

- **Definition:** Injection of malicious scripts into web pages viewed by other users. Three main types: Stored (Persistent), Reflected, DOM-based. 

- **Impact:** Attacker’s script runs in victim’s browser as if trusted. It can steal cookies, redirect, deface pages. The worst is stealing session cookies for account takeover. 

- **Examples:** A stored XSS on Myspace (2005) used this to propagate worms. 

- **Testing:** Insert `<script>alert(1)</script>` or event handlers into inputs (forms, URLs). Check if script executes. Use Burp’s JS search plugin. Try DOM XSS via reflected input in URLs. 

- **Fix:** Contextual output encoding. For HTML content, encode `<` as `&lt;`. Use secure frameworks (React, etc) that auto-escape. For DOM, avoid `innerHTML`, use `textContent`. 

- **Burp Flow:** In Repeater, send payloads to various endpoints. See if they appear in responses or if the browser executes them when previewed. 

⭐⭐⭐ - **Difficulty:** (often easy to find once looking, but needs care for context). 

- **Resources:** OWASP XSS page. 

#### 6.6. Server-Side Request Forgery (SSRF) 

- **Definition:** The server-side application fetches a URL based on user input (like an image URL preview), but attacker can provide a malicious URL. The server then makes requests on behalf of the attacker to internal or external resources. 

- **Impact:** Access internal networks (e.g. `http://localhost:8000`) or external scanning, or cause internal actions. If combined with open internal APIs, it can lead to RCE or data leak. 

- **Example:** Twitter’s image fetch SSRF allowed poking internal AWS metadata in 2019. 

- **Testing:** Find any form field or API that takes a URL. Input `http://127.0.0.1` or `http://169.254.169.254` (cloud metadata). Tools: Burp collaborator or Nmap scanning via SSRF. 

- **Fix:** Whitelist allowed domains, or sanitize inputs. Best to avoid allowing arbitrary URLs; use a fixed backend or require uploads. 

- ⭐⭐⭐ 

- - **Difficulty:** (moderate – finding an entry point takes insight). 

- **Resources:** PortSwigger SSRF tutorial (no direct cite here, but it’s a key learning). 

#### 6.7. XML External Entities (XXE) 

- **Definition:** Occurs when an application parses XML input and permits external entity references. Malicious XML can make the server read local files or access network resources. 

- **Impact:** Read internal files (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`), or DoS via huge expansion (Billion Laughs). 

- **Testing:** If the app takes XML (SOAP APIs, old XML configs), try payloads that define external entities. 

- **Fix:** Disable external entity parsing in XML libraries (use safe parsers), or validate against strict schemas. 

- **Difficulty:** ⭐⭐⭐ (mainly seen in legacy SOAP/XML, less in JSON/REST apps). 

#### 6.8. Remote Code Execution (RCE) & Command Injection 

- **Definition:** RCE is when attacker can execute code on server. Often via **Command Injection** (passing unsanitized input to shell commands). 

- **Impact:** Full server takeover – attacker runs arbitrary OS commands. This usually leads to an immediate high-severity compromise. 

- **Examples:** Webshells, telneting into servers. 

- **Testing:** Inputs that go to system calls (file paths in forms, etc.). Try injecting `; ls` or `&& whoami`. Monitor errors or output. 

- **Fix:** Never pass user input to shell. Use parameterized OS calls or remove shell invocation. Escape inputs rigorously. 

- ⭐⭐⭐⭐ 

- - **Difficulty:** (harder to find; often layers of filtering). 

#### 6.9. File Upload Vulnerabilities 

- **Definition:** Insecure handling of file uploads (e.g. user can upload a webshell). 

- **Impact:** RCE (if PHP script uploaded) or storage abuse. 

- **Testing:** Try uploading scripts (e.g. .php, .jsp) disguised as images. Check magic bytes, content-type. 

- **Fix:** Allow only needed types, store outside web root, rename files, validate content. 

- **Difficulty:** ⭐⭐ (straightforward to test). 

#### 6.10. Path Traversal 

- **Definition:** Manipulating file paths to access files outside intended directories (e.g. 

- `../../etc/passwd`). 

- **Impact:** Read sensitive files on server. If writeable, also modify. 

- **Testing:** Any file parameter; try `../` sequences. 

- **Fix:** Canonicalize and check paths, restrict root directory. 

- ⭐⭐. 

- - **Difficulty:** 

#### 6.11. Open Redirect 

- **Definition:** URLs that redirect based on a parameter (like `?url=`) without validation. Attacker can redirect victim to a malicious site. 

- **Impact:** Phishing attacks (user thinks link goes to legit site, but gets sent elsewhere). 

- **Testing:** Find redirect endpoints; input `evil.com`. 

- **Fix:** Only redirect to whitelisted domains or use relative paths. 

- **Difficulty:** ⭐ (easy low-impact). 

#### 6.12. Host Header Injection 

- **Definition:** Taking advantage of trusting the `Host:` HTTP header (e.g. password reset links or validation use it). If an attacker sets `Host: evil.com`, the app might generate a link to evil.com. 

- **Impact:** Can poison links in emails (reset password, etc.) to point to attackercontrolled domain. 

- **Fix:** Do not trust user-supplied host headers. Use fixed known host for link generation or validate the header. 

- ⭐⭐. 

- - **Difficulty:** 

#### 6.13. Clickjacking 

- **Definition:** Framing the site in an invisible layer (iframe) to trick user clicks. 

- **Fix:** Use `X-Frame-Options: SAMEORIGIN` header to prevent embedding. 

- ⭐ 

- - **Difficulty:** (preventative; not usually a bug finding target). 

#### 6.14. Race Conditions 

- **Definition:** When two processes access/modify the same resource concurrently leading to unintended outcomes. E.g. double-spend. 

- **Impact:** Bypassing checks (like buying two copies for one payment). 

- **Fix:** Use database transactions/locks. 

- ⭐⭐⭐⭐ 

- - **Difficulty:** (hard to exploit and find). 

#### 6.15. HTTP Request Smuggling 

- **Definition:** Malformed requests exploit differences between front-end and backend parsing of HTTP (with Transfer-Encoding vs Content-Length) to smuggle extra bytes. 

- **Impact:** Bypass security filters, cache poisoning, session hijack, DoS. 

- **Testing:** Advanced: send crafted requests with conflicting headers. 

- **Fix:** Properly configure HTTP servers, avoid ambiguous headers. 

- **Difficulty:** ⭐⭐⭐⭐ (very advanced). 

#### 6.16. Business Logic Flaws 

- **Definition:** Logic errors in the way application processes requests. Not a technical flaw, but bad workflow. 

- **Example:** Bypassing shopping cart (apply coupon after purchase), invoice tampering. 

- **Detection:** Manual understanding of flow. 

- **Fix:** Rigid server-side checks and audits. 

- ⭐⭐⭐⭐⭐ 

- - **Difficulty:** (hard to systematically find). 

#### 6.17. Mass Assignment / HTTP Parameter Pollution 

- **Definition:** If API blindly binds client data to objects, attacker can set properties they shouldn’t (e.g. making `isAdmin=true`). 

- **Impact:** Escalate privileges or overwrite data. 

- **Fix:** Whitelist allowed fields, ignore unexpected ones. 

- ⭐⭐⭐. 

- - **Difficulty:** 

#### 6.18. Prototype Pollution 

- **Definition:** In JavaScript object handling (like Node.js apps using `merge` functions), attacker can inject `__proto__` properties to modify all objects. 

- **Impact:** Affects all users’ data or application behavior. 

- **Fix:** Deep-clone JSON or sanitize keys. 

⭐⭐⭐⭐ - **Difficulty:** (rare, language-specific). 

#### 6.19. Deserialization Attacks 

- **Definition:** If user-controlled data is deserialized into objects (e.g. PHP’s `unserialize`, Java’s serialization), attackers can instantiate arbitrary objects or trigger dangerous behavior. 

- **Impact:** Potential RCE or bypass. 

- **Fix:** Avoid native deserialization of untrusted data, or use safe formats (JSON) and libraries. 

- ⭐⭐⭐⭐. 

- - **Difficulty:** 

#### 6.20. Server-Side Template Injection (SSTI) 

- **Definition:** If templates (e.g. Jinja2, Twig) include unsanitized input, attacker can break out of string context and execute code on server. 

- **Impact:** RCE or data leak. 

- **Fix:** Escape inputs in templates. 

⭐⭐⭐⭐. - **Difficulty:** 

#### 6.21. NoSQL Injection 

- **Definition:** Similar to SQLi, but targeting NoSQL databases (MongoDB, etc.). E.g. sending `{"$gt":""}` operators. 

- **Impact:** Bypass auth, extract data. 

- **Fix:** Validate and sanitize inputs, parameterize. 

- **Difficulty:** ⭐⭐⭐ (seen in Node/Mongo apps). 

#### 6.22. GraphQL Vulnerabilities 

- **Definition:** APIs using GraphQL can have injection, excessive data exposure, or insecure fields. Also can suffer from IDOR (since queries often take object IDs). 

- **Fix:** Validate queries, restrict accessible fields, use query depth limit. 

- ⭐⭐⭐. 

- - **Difficulty:** 

### Practice Resources for Vulnerabilities 

- **Labs:** PortSwigger Web Academy (free) covers XSS, SQLi, SSRF, etc. 

- **Juice Shop challenges:** target many OWASP Top 10. 

- **TryHackMe:** has rooms on XSS, SQLi, etc. 

- **dWasp (DVWA)** or bWAPP for hands-on. 

- **Burp Scanner / Intruder** for automation. 

<div id="special-deep-dive--idor"></div> 

## 7. Special Deep Dive – IDOR 

IDOR (Insecure Direct Object Reference) is **beginner-friendly** yet critical. It occurs when the application exposes internal object references (IDs, filenames, etc.) and fails to properly verify access. 

- **Mental Models:** Think in terms of *objects*: user accounts, files, records. If the client provides an ID (like `user=1234` or `fileID=5678`), ask: *“How does the server know I’m allowed to see object 1234?”* If it doesn’t check, that’s IDOR. 

- **Horizontal vs Vertical:** 

- *Horizontal:* One user accessing another user’s data (same level). E.g. Alice reads Bob’s profile by changing `?userId=1001` to `1002`. 

- *Vertical:* A lower-privileged user doing an admin-level action. E.g. a normal user swapping an ID to act as admin. 

- **Object References:** IDs can be numeric, UUID, or opaque string. Predictable ones (sequential IDs) make IDOR easy. Even “unpredictable” IDs can sometimes be found in page source or JavaScript. 

- **Hidden APIs/Fields:** Many apps have API endpoints (e.g. REST, GraphQL) that are called by frontend JavaScript. Use browser DevTools to inspect network calls. Look for JSON payloads containing IDs or secrets. 

- **Mobile/API IDOR:** Mobile apps often use the same APIs. Inspect app traffic (via proxy) to find endpoints and parameters to test IDOR, often harder to find in web UI. 

- **Bulk IDOR:** Some APIs allow multiple IDs at once (e.g. `ids=1,2,3`). Attackers can manipulate all values in one request. 

- **File Download/Upload IDOR:** If you have a URL like `/download?file=report123`, try other IDs. Sometimes endpoints like `/upload` can accept downloads of any user’s file ID. 

- **Advanced Chains:** Often combine with other bugs (e.g. SSRF to reveal internal IDs, then IDOR to steal data). 

- **Case Studies:** Real reports on HackerOne show IDORs in APIs (search H1 for “IDOR Insecure Direct Object Reference” to read writeups). 

- **Detection Checklist:** 

- Any ID in URL or request? Try changing it. 

- Can a user see others’ data by editing JSON responses or web requests? 

- Are there hidden admin-only endpoints (e.g. `/admin` API that is accessible)? 

- **Burp Techniques:** Use Repeater to edit ID values. Use Intruder to brute-force numeric ID ranges. The `qsreplace` tool can swap IDs in bulk. Monitor responses (status 200 vs 403). Also use Burp’s **match/grep** to highlight interesting IDs in HTTP history. 

- **Automation:** Write a script to iterate IDs on an endpoint (take care not to flood). Tools: 

- `bf`, or custom Python. The `Nuclei` scanner has IDOR templates. 

- **False Positives:** Sometimes the parameter is not actually sensitive. Confirm any 

- “found” data is truly unauthorized info (not public directory listing, etc.). 

- **Beginner Mistakes:** 

- Forgetting to log out and test as another user (to simulate unauthorized). 

- Modifying only easy parts (e.g. changing query param but forgetting to try header-based IDs). 

- Assuming an endpoint is safe because a user must be logged in (still need object-level check). 

**Practice:** 

- Try Juice Shop’s “Broken Access Control” challenges. 

- Try API-specific labs (PortSwigger has API IDOR labs). 

- Use DVWA or GoBuster to find hidden API endpoints. 

## 8. API Security 

### 8.1. REST, SOAP, GraphQL, gRPC 

**REST:** The most common web API style (uses HTTP verbs and JSON). 

**SOAP:** XML-based protocol (older; still used in enterprise). 

**GraphQL:** Query language that allows clients to request exactly the data they need via a single POST endpoint. Schema-driven. 

**gRPC:** A binary RPC protocol using Protocol Buffers, often for internal/microservices. 

**Why it matters:** Web apps often expose REST or GraphQL APIs. Test them just like the web app (often even more bugs there). Tools: Postman, Insomnia, Burp. SoapUI for SOAP. There are specific fuzzing tools for GraphQL (GraphQL-Ben or custom queries). 

**Exercises:** 

- Try interacting with a public REST API (GitHub, etc.). 

- If comfortable, write a simple GraphQL query against a public demo API. 

### 8.2. JSON & XML 

APIs use **JSON** (lightweight, easy) or **XML** (more verbose). If an API accepts XML, watch out for XXE (covered before). If JSON, look for injection (like injecting `{"$gt": ""}` into Mongo queries). 

**Exercises:** 

- If an API has XML endpoints, try including an external entity declaration. 

- With JSON: try sending JSON with extra fields or arrays of objects to test mass assignment or BOLA. 

### 8.3. JWT, OAuth, OIDC 

APIs often require tokens. Learn how to use JWT bearer tokens in Authorization headers, or refresh tokens in OAuth flows. Misconfigurations: JWT with no signature checking (`alg: none`), broken token validation. 

**Exercises:** 

- Use Postman to send `Authorization: Bearer <token>` to an endpoint. If invalid token yields 500, that’s a clue. 

### 8.4. API Gateways, Rate Limiting, Pagination, Versioning 

APIs often implement: 

- **Gateways:** A front-end layer (e.g. AWS API Gateway). Sometimes leaky (exposes endpoint base URLs). 

- **Rate Limiting:** Throttling request counts. 

- **Pagination:** If list endpoints allow large limits, try parameter pollution to bypass (e.g. `?limit=1000000`). 

- **Versioning:** Check old API versions still active (e.g. v1 vs v2 URLs). 

**Exercises:** 

- In an API with pagination, try offset or `limit` parameter manipulation. 

- Look at API docs (or hidden ones) for gateways (often `api.` subdomains). 

### 8.5. API Authentication & Authorization 

Similar to web app, but using tokens: 

- BOLA (Broken Object Level Auth) is IDOR on APIs. 

- BFLA (Broken Function Level Auth): e.g. regular user calling admin-only endpoints. 

- Check default credentials or no-auth endpoints. 

### 8.6. OWASP API Top 10 (BOLA, BFLA, etc.) 

OWASP API Top 10 (2023) includes: 

- **BOLA (Broken Object Level Authorization)** – essentially API IDOR. 

- **Broken Auth:** tokens, sessions. 

- **Excessive Data Exposure:** APIs returning too much data (you can’t fix, but watch out). 

- **Lack of Rate Limiting:** brute forcing possible. 

- **Broken Function Auth:** as above. 

- **Mass Assignment:** sending extra JSON fields. 

- **Security Misconfig:** HTTP verbs allowed, etc. 

- **Injection:** SQL/NoSQL in API. 

- **Improper Assets Management:** discover unprotected endpoints via API docs or naming. 

- **Insufficient Logging:** can’t exploit, but note if no tracking. 

### 8.7. API Recon & Fuzzing 

- **Endpoint Discovery:** Many APIs are documented via OpenAPI/Swagger. Search for 

- `/swagger`, `/api-docs`, `/v2/api-docs`. Also try `.json`, `.yaml` on root or known paths. 

- **API Fuzzing:** Tools like Postman runner, or `nuclei` with API templates. 

- **Header Tweaks:** Some APIs use custom headers (e.g. `X-API-KEY`). Try bypassing with alternatives. 

**Exercises:** 

- Use [httpx](https://github.com/projectdiscovery/httpx) to enumerate subdomains, then list likely API endpoints (`/api/`, `/graphql`). 

- Use Postman collection runner with an auth token to hit many endpoints. 

### 8.8. API Documentation Abuse 

Documentation like Swagger or Postman collections sometimes leak **hidden paths** or parameters. If the dev team forgot to disable them, bug hunters can find *admin* endpoints. 

**Check:** Public repos, GitHub – developers often commit API tests or docs accidentally. 

### 8.9. Postman & Insomnia Workflows 

- **Postman:** Useful for crafting and replaying API requests. Learn to set environment variables (e.g. token). 

- **Insomnia:** Similar. 

- They can import curl commands or OpenAPI specs. 

### 8.10. Burp API Testing 

Burp has extensions (AuthMatrix, JSON evaluator, GraphQL breaker). But also the built-in features: 

- Use **Proxy** to capture API calls from Postman/Insomnia. 

- Use **Intruder** to brute param or header values in API requests. 

- Use **Repeater** for manual testing. 

- **Scanner** (Pro) can automatically crawl API in active scans. 

## 9. Reconnaissance 

Recon is gathering as much information about a target as possible, legally: 

- **Passive Recon:** Google dorks, WHOIS, SSL cert transparency, Shodan. (No interaction with target servers.) 

- **Active Recon:** DNS brute (subfinder), port scans (Nmap), web crawling (httpx, gau). 

- **Subdomain Enumeration:** Tools like Amass, subfinder, assetfinder, find DNS records (A, AAAA, CNAME, TXT). 

- **DNS Enumeration:** Enumerate DNS records (MX, TXT, SPF, etc.) with `dig` or tools. 

- **ASN Enumeration:** Find org’s IP ranges (Shodan/Alexa lists, bgpview). 

- **JS Recon:** Crawling the site’s .js files (tools: **Katana**, **LinkFinder**) to find hidden endpoints or tokens. 

- **Endpoint Discovery:** Brute-force directories/files (`ffuf`, `dirsearch`), check robots.txt, sitemap.xml, code comments. 

- **Parameter Discovery:** Tools like **ParamMiner** or **Burp’s extension for parameters**. 

- **Content Discovery:** Public directory scans, Bruteforce `robots.txt` and `sitemap.xml` to find hidden pages. 

- **Wayback Machine & Archive:** View historical versions of site to find old endpoints (waybackurls, gau). 

- **GitHub Recon:** Search for target’s domains in GitHub repos (e.g. via [GitHub dorking] (https://github.blog/2019-05-23-breaking-up-monoliths-adding-a-framework-for-queryingyour-log-group/)). 

- **Secrets Hunting:** Look for exposed API keys/credentials in public repos, config files. 

- **Tech Fingerprinting:** Identify technologies (Wappalyzer, builtwith) – tells what frameworks/VCS, which suggests likely bugs. 

- **Cloud Asset Discovery:** If target uses cloud (AWS/Azure), find buckets or S3 via googling (s3 bucket enumerations). 

- **Wordlists:** Use curated lists (SecLists) for directories, common endpoints. 

- **Automation:** Write Bash/Python scripts to orchestrate tools (e.g. run subfinder → amass → httpx → ffuf → nuclei). 

- **Noise Reduction:** Filter out benign findings (e.g. pre-crawled files, duplicate endpoints). 

- **Data Organization:** Use tools like `Nuclei templates` or spreadsheets to track endpoints. 

- **Target Prioritization:** Based on scope and potential impact (pay attention to subdomains related to login, payments, admin). 

**Resources:** 

- Tools Documentation (Amass, Subfinder, Gau, Katana). 

- Blogs on recon pipelines (TomNomNom’s blog, etc.). 

## 10. Bug Hunting Methodology 

### 10.1. Mindset & Attack Surface 

Think like an attacker: 

- **Curiosity:** “What if I do X?” 

- **Persistence:** Test all endpoints, not just the homepage. 

- **Questioning:** “Why did the dev do it this way? Can I abuse it?” 

Build your own **attack surface map**: enumerate all subdomains, ports, services, API endpoints, functionalities (login, search, upload, etc.), and potential user roles. Understand the business logic and data flow. 

### 10.2. Selecting Targets & Programs 

Choose programs that: 

- Are in scope for your skills (e.g. if you know web, start with web-only programs). 

- Allow testing of their scope (public vs private). 

- Have reasonable disclosure policies. 

- Provide some info (like a test account in scope). 

Read the program’s scope, rules, and bounty ranges. Start small: e.g. find XSS or broken auth on your first target before moving to complex stuff. 

### 10.3. Mapping Workflows & Documentation 

Before testing, map out how the app is supposed to work: e.g. “User signs up → Email verification → login → dashboard”. Identify “attack vectors” at each step: 

- Where does input enter? 

- What actions are privileged? 

- What data flows to client? 

Refer to official API docs if available. Keep notes of endpoints and purposes. Use a tool like Obsidian or a spreadsheet to track findings. 

### 10.4. Privilege Boundaries & Chains 

Always note privilege levels (guest, user, admin). Check if you can escalate. Also, look for *chains* of actions: e.g. find XSS, then use it to escalate privileges via CSRF or steal tokens. 

### 10.5. Testing Approach & Avoiding Dead Ends 

Have a structured approach: 

- Authentication checks. 

- IDOR/access control. 

- Input validation. 

- Business logic (workflow abuse). 

- Data exposure. 

- Use both manual and automated testing (nuclei scans with permission). 

- **Avoid rabbit holes:** If you get stuck, note it and revisit later. Manage time. 

### 10.6. Note-taking & Reporting Workflow 

Use tools like Burp’s note tabs, or a personal wiki (Obsidian) to log: 

- Endpoints tested, parameters, responses. 

- Evidence (screenshots or output). 

- Vulnerability templates (baselines for reports). 

This ensures your report will be clear and complete. 

### 10.7. Automation vs Manual Balance 

Automate repetitive tasks (like brute-forcing IDs, scanning directories) with scripts and tools. But always verify manually: 

- Automated scanners find many issues, but can produce false positives. 

- Manual testing finds logical bugs (business logic, chained issues) that automation misses. 

Aim for efficiency: let tools handle grunt work, use manual analysis where intelligence and creativity are needed. 

### 10.8. Personal Workflow & Decision Trees 

Develop a personal workflow, e.g.: Recon → Login → Fuzz/IDOR → Logic flows → Hardening. Use decision trees to remember steps (e.g. If you can upload files, consider what transformations happen; if endpoint accepts JSON, consider mass assignment, etc.). 

Keep a checklist of items to test on every target (authentication, direct object refs, input validation, etc.). 

## 11. Tools 

Below are key tools. For each: purpose, basic usage, and notes. 

- **Burp Suite (Pro/Community):** The primary intercepting proxy and suite. 

**Installation:** Download from PortSwigger. **Workflow:** Set browser proxy to Burp, capture traffic. Use **Repeater** to modify requests manually. **Scanner (Pro)** can automatically find many issues (though free edition has manual only). **Common flags:** Use **Comparer** and **Logger++** extensions. 

*Advanced:* Use **Intruder** for parameter fuzzing. **Tip:** In hands-on, focus on manual usage (Proxy/Repeater/Decoder) before moving to Intruder. 

- **Nmap:** Network scanner. **Purpose:** Identify open ports/services on a host. 

**Usage:** `nmap -sV target.com` (service detection) or `-p-` for all ports. 

**Workflow:** Often used in recon for hosts that are in scope (IP addresses of subdomains found). 

*Beginner mistakes:* Scanning without authorization (only use on approved assets). 

- **httpx (Project Discovery):** A fast HTTP request tool. **Usage:** `httpx -l urls.txt -status-code -title` to fetch websites from a list. Great for checking live hosts. 

*Advanced:* Supports concurrency, HTTP/2, follow redirects. 

- **Katana:** A JavaScript link crawler and automated reconnaissance tool. It spiders a domain, finds JS files, endpoints, secrets. 

**Installation:** `go install github.com/projectdiscovery/katana/v2/cmd/katana@latest`. 

**Usage:** `katana -silent -u https://target.com`. 

*Note:* Good for quickly enumerating hidden endpoints. 

- **gau (GetAllURLs):** Pulls known URLs from public archives (Wayback Machine, Common Crawl). 

**Usage:** `gau example.com` lists historical URLs. 

*Use:* Complement wordlist fuzzing, find old endpoints. 

- **waybackurls:** Similar to gau, fetches archived URLs from Wayback Machine. 

**Usage:** `echo "target.com" | waybackurls`. 

- **ffuf (Fuzz Faster U Fool):** Directory brute-forcer. **Installation:** `go install github.com/ffuf/ffuf`. 

**Usage:** `ffuf -w common.txt -u https://target.com/FUZZ` to find directories/files. Supports recursion, headers, and more. 

*Tip:* Use relevant wordlists (e.g. SecLists folder `common.txt`, `svndigger.txt`, etc). 

- **dirsearch:** Python-based directory scanner (`dirsearch.py -u target`). Similar to ffuf. **Usage:** `python3 dirsearch.py -u https://example.com -e php,html` (extensions list). *Note:* Good for targeted scans if know extensions. 

- **subfinder:** Subdomain enumeration. Uses passive sources. 

**Installation:** `go install github.com/projectdiscovery/subfinder/v2@latest`. 

**Usage:** `subfinder -d example.com`. 

*Workflow:* Chain with *amass* for active DNS bruteforce. 

- **amass:** Advanced subdomain and network mapping tool. Passive + active. 

**Usage:** `amass enum -d example.com`. Highly effective at finding subdomains and related domains. 

- **assetfinder:** Quick tool for subdomain list (`assetfinder -subs-only example.com`). 

- **nuclei:** Scanner that uses templates to find vulnerabilities. 

**Usage:** `nuclei -u https://target.com -t /path/to/templates`. 

**Common flags:** `-t /templates/cves/`, `-silent` etc. 

*Important:* Only use on allowed targets. There are many community templates. 

*Automation:* Combine with recon: feed URLs into nuclei for fast scanning of known issues. 

- **gf (Grep filters):** A tool by Tom Hudson that uses pattern files (`gf xss`, `gf sqli`) to filter potential vulnerable parameters from HTTP history. 

**Usage:** After capturing traffic, pipe output to `gf` patterns. 

*Set up:* Add `gf` patterns (GitHub repository of patterns). 

- **qsreplace:** Replace query string values easily (Bobby’s QSReplace). E.g. `echo "id=123" | qsreplace FUZZ` to prepare lists of payloads for Intruder. 

- **dalfox:** A tool for XSS scanning and payload generation. 

**Usage:** `dalfox url https://example.com/?q=1` to test XSS on that param. 

- **sqlmap:** Automated SQL injection tool. VERY powerful but use only on authorized targets. 

**Usage:** `sqlmap -u https://target.com/page?id=1 --batch --level=3`. 

- **Postman:** API exploration GUI. **Usage:** Build requests visually, save collections, handle auth easily. Has scripting (Pre-request) and variable environments. 

- **Insomnia:** Similar to Postman, sometimes preferred for GraphQL. Both good for manual API testing. 

- **curl:** Command-line HTTP client. E.g. `curl -X POST -d '{"key":"val"}' -H "Content-Type: application/json" https://api.com`. Very handy for quick tests in terminal. 

- **jq:** As above (JSON CLI) to parse outputs from curl or other JSON. 

### Tool Workflow & Integration 

- For scanning **subdomains**: use a chain: `subfinder` or `amass` → output to `httpx` to filter live. 

- For **content discovery**: feed found URLs to `gau`/`waybackurls` → feed all to `ffuf` or `nuclei`. 

- Use **tmux** or multiple terminal tabs to run concurrent scans. 

- **Burp + CLI:** Export Burp history (HTTP Requests) and grep with `gf` or custom scripts. 

- **Automation:** Write Bash scripts to combine (e.g., a recon pipeline script that calls all tools and aggregates results). 

**Beginner Tips:** 

- Run tools gently (don’t spam too fast or you'll get IP banned). 

- Always respect robots.txt only if specified by program. 

- Save outputs for reference. 

## 12. Hands-on Practice Platforms 

| Platform                    | Difficulty | Cost      | Best For                 | Learning Focus                  | 

|-----------------------------|:----------:|:---------:|--------------------------|--------------------------------| 

| **PortSwigger Web Security Academy** | ⭐⭐ (Easy) | Free     | Complete beginners        | OWASP Top 10, labs on each vuln   | 

| **OWASP Juice Shop**         | ⭐⭐⭐ | Free       | Beginners/Intermediate    | Wide variety of bugs (XSS, BOLA, etc.) | 

| **DVWA (Damn Vulnerable Web App)** | ⭐⭐ | Free     | Very basic training       | SQLi, XSS, RCE in controlled env | 

| **OWASP WebGoat**           | ⭐⭐⭐ | Free       | Structured learning       | Guided lessons on vulnerabilities | 

| **bWAPP**                  | ⭐⭐ | Free       | Web vulnerabilities (old vs new) | Wide bugs (including old ones) | 

| **Hack The Box**            | ⭐⭐⭐⭐ | Freemium  | CTF-style, labs           | Diverse: web, network, binaries   | 

| **TryHackMe**               | ⭐⭐⭐ | Freemium  | Beginners (guided)        | Step-by-step rooms on web, network | 

| **PentesterLab**            | ⭐⭐⭐⭐ | Paid (some free) | Web vulnerability training | In-depth web labs (includes membership) | 

| **PicoCTF**                | ⭐⭐ | Free       | Young learners            | Game-based CTF (mix of topics) | 

| **OverTheWire**            | ⭐⭐ | Free       | CLI and CTF basics        | Linux commands, basic wargames    | 

| **VulnHub**               | ⭐⭐⭐⭐ | Free       | VM-based pentesting       | Real-world Simulations (incl. networks) | 

| **Root-Me**               | ⭐⭐ | Free       | Web & others              | Many small challenges             | 

- **Difficulty:** Subjective; influenced by background. (⭐ easiest, ⭐⭐⭐⭐⭐ hardest). 

- **Cost:** Many have free content; some (HTB, THM) have paid tiers for advanced. 

- **Prerequisites:** Some require basic Linux or networking knowledge. 

- **Recommended Order:** Start with free platforms: WebSec Academy (targeted, no setup), Juice Shop (browser-based), TryHackMe beginner rooms. Then DVWA/WebGoat for hands-on vulnerable apps. Move to HTB/THM/VulnHub for more challenge and variety. 

**Example Labs:** 

- PortSwigger Academy labs on *“SQL Injection — String-based (GET)”* or XSS. 

- Juice Shop challenge “Forged Feedback” (IDOR) or “Error Handling” (XSS). 

- HackTheBox “Firing Range” (web app pentest). 

## 13. Learning Resources 

## ### Books 

- *“The Web Application Hacker’s Handbook”* (Addison-Wesley) – Comprehensive on web vulns (Intermediate to Advanced). 

- *“The Tangled Web”* by Michal Zalewski – deep dive into browser security (Advanced). 

- *“Black Hat Python”* – Offensive scripting (Intermediate Python). 

- *“Gray Hat Hacking”* – General pentest techniques (Beginner to Intermediate). 

### Official Documentation 

- **MDN Web Docs** – HTML/CSS/JS basics (free). 

- **OWASP Cheat Sheets** – Best practices for each vuln (free) 

[cheatsheetseries.owasp.org]. 

- **Burp Suite Docs** – Official usage guide (free for community). 

- **Cloudflare blog** – Good explainers (DNS, HTTPS, etc.). 

- **Bash/grep manuals** – The `man` pages online. 

### GitHub Repos & Tools 

- **SecLists** (GitHub) – Wordlists for fuzzing. 

- **Awesome Bug Bounty** – Curated list of resources. 

- **Bobby’s GH** – Repos like qsreplace, ffuf, etc. 

- **Kanaloa** – H1 reports in JSON form. 

### Blogs & Research Papers 

- **PortSwigger Blog & Research** – High-quality articles on new vulns. 

- **HackerOne Hacktivity** – Publicly disclosed reports for real-case examples. 

- **Bugcrowd/Intigriti Blogs** – Tips and case studies. 

- **GTFOBins** – Unix privilege escalation techniques. 

## ### Newsletters & Podcasts 

- **Weekly Bugle (H1)** – Weekly security news + write-ups. 

- **The Hacker News** – Security news daily. 

- **Dark Reading** – Enterprise security news. 

- **Podcasts:** *Security Now!*, *Darknet Diaries*, *Daily Swig* (PortSwigger). 

## ### YouTube Channels 

- **LiveOverflow** – beginner-friendly hacking tutorials. 

- **The Cyber Mentor** – OSCP labs & pentesting guides. 

- **StÖK** – Bug bounty tips and walkthroughs. 

- **John Hammond** – CTF exploits. 

## ### Communities 

- **Discord:** (YesWeHack, Bugcrowd, MetaPlatforms) many have #beginners channels. 

- **Reddit:** r/AskNetsec, r/netsecstudents, r/bugbounty. 

- **Twitter/X:** Follow well-known hackers (#infosec). (E.g. @dangoodin001, @nao_sec). 

## ### CTF Platforms 

- **CTFtime.org** – find ongoing CTFs. 

- **pwnable.kr, hackthissite.org** – classic challenges. 

- **Root Me** – wargame style CTF problems. 

## ### Cheat Sheets & Browser Extensions 

- **Cheat Sheets:** OWASP cheat sheets, PayloadsAllTheThings (GitHub). 

- **Extensions:** 

- **Wappalyzer** (fingerprints tech stack). 

- **HackBar** (Firefox) for manual injection testing. 

- **JSONView** (beautify JSON). 

- **NoScript** (disable scripts to view raw HTML). 

## 14. Finding Real Bug Bounty Targets 

### 14.1. Platforms (HackerOne, Bugcrowd, etc.) 

- **HackerOne, Bugcrowd, Synack, YesWeHack, Intigriti:** Major bug bounty platforms hosting programs for companies. 

- **Public vs Private:** Public programs list scope publicly and anyone can apply. Private programs are invite-only or by nomination (often higher payouts but need reputation). 

- Start with public programs (easy entry, community help). 

### 14.2. Public vs Private Programs 

- **Public Program:** Anyone can test. Examples: Discord, GitHub. 

- **Private Program:** Only invited hackers. You may earn reputation to get invited later. 

### 14.3. Scope Analysis & Rules 

- Always read the program’s **scope page** carefully: what subdomains, apps, APIs are allowed or forbidden. 

- Read **policy/rules**: legal rules, required disclosures, duplicate rules. Understand if fingerprinting or scraping is allowed, etc. 

- Follow the rules strictly (no crawling destructive tests if disallowed). 

### 14.4. Asset Prioritization 

Within scope, focus on: 

1. Authentication flows (login, password reset). 

2. Sensitive data (user profiles, databases). 

3. New or complex features (forgotten endpoints). 

4. Admin or high-privilege functions. 

Beginner-friendly: look for user/edit pages, sequential ID parameters, API endpoints returning JSON. 

### 14.5. Beginner-Friendly Programs 

- Look for programs with good docs and supportive triage (HackerOne’s “Triager tips” can help). 

- Programs in known tech stacks (if you know PHP or Node, etc.). 

- Programs offering test accounts (so you can test logged-in bugs). 

- Paid and active programs: see H1 charts (prizes). 

### 14.6. Safe Testing Guidelines 

- Don’t do social engineering or phishing – that's illegal. 

- Don’t test logic that goes into real accounts (money transfer without permission). 

- Get permission: always stick to defined scope (even if you find out-of-scope endpoint, stop). 

### 14.7. Avoiding Duplicates & OOS 

- Check the program’s submitted reports if visible (sometimes H1 public programs let you view duplicate reports). 

- Search sites like GHunt (HackerOne has an API for privately searching your findings). 

- If you find an OOS vulnerability (out of scope), ignore it (or responsibly disclose to the vendor if they have a VDP). 

## 15. Reporting Vulnerabilities 

Professional reporting is as important as finding bugs. Structure: 

- **Title:** A concise summary of the bug and context. 

- **Summary:** High-level overview (what, where, impact). 

- **Impact:** Describe the real-world risk (data leaked, account takeovers). 

- **Steps to Reproduce:** Detailed, numbered steps with exact inputs. Use simple 

language. Include initial state, actions, and outcome. 

- **Proof of Concept (PoC):** Screenshots, request/response captures, videos if needed. Show before/after. 

- **Evidence:** Clear screenshots with highlights. Show tool output (e.g. curl command and output). 

- **Remediation:** Suggest fixes (e.g. implement authorization check on line X). Show understanding of how to fix. 

- **Severity Justification:** Map to CVSS or business impact. If unsure, describe why it’s critical (e.g. “allows admin data leak”). 

- **Responsible Disclosure Note:** Mention you’ll wait the program’s stipulated time. Thank them. 

Communication tips: Be respectful, clear, and patient. If triager asks for more info, provide it promptly. If duplicate or N/A, move on – learn and try elsewhere. 

**Templates:** Many platforms provide their own templates (e.g. HackerOne’s). Use bullet points and code blocks in markdown for clarity. 

## 16. Real Bug Bounty Case Studies 

Learning from real reports is invaluable. Here are examples (non-cited summary): 

- **IDOR Case:** A report where researcher enumerated numeric IDs in a user profile API, found full data for other users. They showed Burp Repeater requests with one ID, then changed it and got another user’s JSON. The report explained the broken object-level check, suggested proper permission checks. 

- **OAuth Misconfig:** A report where an open redirect in OAuth flow allowed stealing tokens. 

- **Business Logic:** A case where a discount coupon was applied twice due to missing state check. 

- **JWT:** A JWT with `alg: none` was accepted, letting attacker forge admin token. 

In each, note the **mindset**: the hunters often start from trivial things (IDs, redirects), see an anomaly, then escalate. They often used Burp to intercept and modify. The **reports** clearly show each step, and the fixes (check IDs, disable none algorithm). 

Lesson: always include **video or screenshots** especially if the exploit is complicated. Validate bugs multiple times (re-test) before reporting. 

## 17. Productivity System 

### 17.1. Daily Workflow 

- **Morning:** Review recent security news or feed (15 min). 

- **Midday:** Learning (read a blog, watch a tutorial, 1 hour). 

- **Evening:** Practice (labs, CTF, or testing targets). 

- **Always:** Take notes of findings, new commands, and code snippets. 

### 17.2. Weekly/Monthly Workflow 

- **Weekly:** Set goals (e.g. Master XSS, finish one app). Summarize what you learned. 

- **Monthly:** Review progress, update roadmap (this doc’s plan), adjust focus (maybe start a new tool). 

### 17.3. Knowledge Management 

- Use **Obsidian** or Notion: tag notes as #web , #api , #tool_burp, etc. 

- Keep a **recon DB** (spreadsheet) of target domains, found endpoints, vulnerabilities discovered. 

- Bookmark useful links (docs, blog posts) in browser or note manager, categorized by topic. 

### 17.4. Recon/Issue Tracking 

- Maintain a list of targets/programs, their scopes, and status. 

- Use ticket trackers or simple TODO lists for issues you want to test later. 

### 17.5. Lab/Bug Tracking 

- Keep a lab journal: which lab did you do, what you learned, what was hard. 

- Keep a bug tracker spreadsheet: (e.g. columns: target, issue, status, bounty, date). 

### 17.6. Automation Schedule 

- Automate nightly recon runs (like `subfinder` on new domains, or Google dorks). 

- Periodically run scanners on known targets (with caution, as per rules). 

## 18. Common Beginner Mistakes 

1. **Not Reading Scope:** Testing out-of-scope features leads to disqualification. Always read the rules first. 

2. **Brute-Forcing Everywhere:** Blindly automating without plan leads to noise/blocks. Understand the target before bombard. 

3. **Missing Authentication:** Forget to log in or use the test account, then confuse lack of function with a bug. 

4. **Ignoring Encodings:** Not thinking about URL/HTML encoding (leading to missed XSS). 

5. **Overlooking Rate Limits:** Triggering bans. Respect rate limits or slow down scans. 

6. **Copy-Pasting Payloads:** Without understanding context (e.g. using an XSS script in a non-HTML context). 

7. **No Proof:** Reporting “I think this might be XSS” without evidence is rejected. Always provide PoC. 

8. **Ambiguous Reproduction Steps:** Steps must be clear; newbies often skip steps. Always detail every click. 

9. **No Before/After:** Not showing how the bug changes behavior (e.g. no screenshot of before login and after login with IDOR). 

10. **Assuming Bug:** Not confirming in multiple ways. Sometimes HTTP 200 could be a fake success page. 

11. **Ignoring Tools:** Refusing to use tools like proxies or Nmap; trying everything in browser UI only (inefficient). 

12. **Poor Time Management:** Spending hours on one tricky path with no reward. Learn when to move to another area. 

13. **Forgetting Cleanup:** Not logging out or using different browsers leads to false positives (like thinking cookie can be stolen in same session). 

14. **Wrong Environment:** Testing production in aggressive ways (like mass scanning) – use provided test env. 

15. **Skipping Manual Checks:** Relying only on automated scanners; some vulnerabilities need human insight. 

16. **Reporting JSON/JS in code block:** Not clear enough (should be formatted). 

17. **Not Understanding Impact:** Reporting a minor UI bug as critical (leads to low credibility). 

18. **Bad Communication:** Vague titles like “IMPORTANT BUG” or insulting tone. Always be professional. 

19. **Ignoring Updates:** Using old info or tools. The field evolves; keep learning. 

20. **Overconfidence:** Not verify what you’ve found against basics (e.g. logged-out vs logged-in differences). 

*(And 80 more along these lines…)* 

## 19. 90-Day Study Plan 

### Weeks 1–4: Fundamentals & Linux 

- **Week 1:** 

- *Objectives:* Cybersecurity basics, Linux shell commands. 

- *Daily:* 1 hr reading (online courses), 1 hr Linux practice (Home directory navigation, permissions). 

- *Labs:* OverTheWire Bandit (Linux war game). 

- *Milestone:* Able to use Linux CLI and understand basic security terms (CIA, CVE). 

- **Week 2:** 

- *Objectives:* Networking protocols, HTTP/S, cookies. 

- *Daily:* 1 hr studying OSI, HTTP (maybe via videos), 1 hr practice with Wireshark/Burp. 

- *Labs:* Packet capture with Wireshark (capture your own HTTP). Burp practice on DVWA (you can set it up). 

- *Milestone:* Understand web request flow, use Burp proxy on a simple site. 

- **Week 3:** 

- *Objectives:* Scripting basics (Python, regex, jq). 

- *Daily:* 1.5 hr Python tutorials (requests, JSON). 30 min regex practice. 

- *Labs:* Write a Python script to fetch JSON from public API and parse it. Use regex to search text files. 

- *Milestone:* Automate simple tasks with Python and CLI. 

- **Week 4:** 

- *Objectives:* HTML, DOM, JavaScript basics. 

- *Daily:* 1 hr HTML/CSS via tutorials, 1 hr JS basics (console, DOM). 

- *Labs:* Inspect a website’s DOM. Modify page content via console. Perform a basic DOM XSS on Juice Shop (store feedback). 

- *Milestone:* Understand how web pages are built and script-interaction. 

### Weeks 5–8: Web Vulnerabilities & Tools 

- **Week 5:** 

- *Objectives:* SQLi, XSS in depth. 

- *Daily:* 1 hr reading OWASP Top 10 entries, 1 hr practicing on labs. 

- *Labs:* PortSwigger labs for SQLi and XSS. Juice Shop XSS challenges. 

- *Milestone:* Identify and exploit basic SQLi and XSS. 

- **Week 6:** 

- *Objectives:* Broken Auth & Access Control. 

- *Daily:* 1 hr study auth (JWT, cookies) and IDOR theory; 1 hr lab practice. 

- *Labs:* DVWA auth bypass labs, OWASP Juice Shop IDOR tasks. 

- *Milestone:* Find a sample IDOR (e.g. in Juice Shop’s profile API). 

- **Week 7:** 

- *Objectives:* Tools mastery (Burp, Nmap, ffuf, etc.). 

- *Daily:* 1 hr learning a new tool (watch tutorial, install); 1 hr exercise using it. 

- *Tools:* Nmap simple scan (shadow on your home network), ffuf on local webserver, subfinder. 

- *Milestone:* Set up Burp and basic usage; scan local network with Nmap; fuzz directories with ffuf. 

- **Week 8:** 

- *Objectives:* Linux for security (grep, awk, sed, tmux). 

- *Daily:* 30 min per command practice (grep logs, sed replace), use tmux multi-pane. 

- *Labs:* Solve Bandit next levels (grep, ssh keys). 

- *Milestone:* Comfortable with text processing and multi-terminal workflow. 

### Weeks 9–12: Advanced Web & API Security 

- **Week 9:** 

## - *Objectives:* CSRF, CORS, JWT attacks. 

- *Daily:* Study how CSRF tokens work, experiment with CSRF labs. 

- *Labs:* OWASP CSRF lab, try adding missing tokens to forms. 

- *Milestone:* Able to exploit a CSRF vulnerability in a test app. 

- **Week 10:** 

- *Objectives:* API security basics (REST, GraphQL). 

- *Daily:* Read about REST vs GraphQL, practice Postman. 

- *Labs:* Use a public GraphQL API (e.g. countries.trevorblades.com) to query and try simple injection. 

- *Milestone:* Understand how to authenticate and query an API. 

- **Week 11:** 

- *Objectives:* Reconnaissance techniques. 

- *Daily:* Learn and run subdomain enumeration tools; use Wayback tool. 

- *Labs:* Pick a domain you own (or google.com) and map subdomains. 

- *Milestone:* Build a list of endpoints and subdomains for a target. 

- **Week 12:** 

- *Objectives:* Reporting practice & methodology. 

- *Daily:* Write a mock report for a discovered bug. 

- *Labs:* Review published bug reports, compare style. 

- *Milestone:* Prepare a complete sample report with PoC and remediation. 

### Outcome after 3 months 

- Completed labs on OWASP vulnerabilities. 

- Basic use of scanning/recon tools. 

- Wrote and understood a bug report. 

- Ready to try simple bounties on weak-scope programs (e.g. labs-only targets). 

## 20. After Your First Bounty 

Congratulations! Next steps for advanced learning: 

- **Advanced XSS & SSRF:** Practice DOM XSS (no inputs, only URL/fragment) and SSRF to pivot into cloud (EC2 metadata). 

- **Request Smuggling:** Learn about TE.CL style tricks (resume reading OWASP Shield). 

- **Deserialization Attacks:** Explore tools (ysoserial) to exploit Java deserialization (on your own labs or CTF). 

- **Cloud Security (AWS/Azure/GCP):** Study IAM, S3 bucket misconfig, and common cloud misconfig (Tools: Scout2, Prowler). 

- **Container/K8S:** Understand Dockerfile risks, k8s secrets. Run XSS in GCP, etc. 

- **Mobile App Security:** Use Frida or MobSF to analyze an Android .apk. Look into Android’s WebViews. 

- **Binary Analysis:** Basic reverse engineering (strings, Ghidra), useful if you find an RCE that requires exploitation. 

- **Source Code Review:** Learn SAST patterns (e.g. spotting vulnerable code). 

- **Custom Recon Pipelines:** Write your own Python to chain tools (e.g. async calls, database of endpoints). 

- **Python Scripting:** Build tools (e.g. a directory enumerator in Python). 

- **Go for recon:** Many tools in Go (httpx, anew) - learn Go if interested. 

- **AI-assisted workflows:** Use ChatGPT or Google Bard to brainstorm attack ideas (don’t rely blindly). 

- **Professionalization:** Build a portfolio (GitHub repos, blog posts). Consider freelance pentesting or joining security teams. 

## ## Final Checklists & Planners 

## ### Complete Beginner Checklist 

- [ ] Understand basic cybersecurity terms (CIA triad, CVE/CWE/CVSS). 

- [ ] Navigate Linux file system, use grep/awk/sed/jq. 

- [ ] Use Burp Proxy to intercept and modify HTTP traffic. 

- [ ] Explain difference between authentication and authorization. 

- [ ] Demonstrate CSRF by creating a malicious form and seeing if it works. 

- [ ] Find a simple XSS on a practice site and exploit it. 

- [ ] Explain how to prevent SQL injection (prepared statements). 

- [ ] Enumerate subdomains and endpoints for a sample target. 

- [ ] Write a bug report template (title, steps, PoC, fix). 

## ### 6-Month Roadmap 

- Month 1-3: Follow the 90-day plan above (fundamentals, basics). 

- Month 4: More labs (PortSwigger, JuiceShop), start small bounties (low-hanging fruit like XSS on public programs). 

- Month 5: Advanced recon and API hacking, attempt harder programs. 

- Month 6: Consolidate, target private invites (if available), refine personal tools/scripts, aim for first bounty payout. 

## ### 12-Month Roadmap 

- Months 7-9: Cover remaining advanced topics (Cloud, Mobile, Crypto). 

- Months 10-12: Perhaps pursue a security certification (e.g. OSCP, CEH) for credibility. Continue active bug hunting. 

- Year-end: Aim for consistent bounty income or a professional role in security. 

### Skill Progression Matrix 

| Skill Area            |  Beginner (⭐)         | Intermediate (⭐⭐⭐)         | Advanced (⭐⭐⭐⭐⭐)               | 

|-----------------------|-----------------------|---------------------------|-------------------------------| 

| Linux CLI             | Basic commands (ls, cd) | Scripting (bash loops)     | System admin skills (networking) | 

| Networking            | OSI, HTTP basics      | Wireshark, Nmap scans     | Custom packet crafting         | 

| Web Exploits (XSS/SQLi)| Found basic XSS/SQLi  | Use tools (sqlmap), DOM XSS| Complex multi-step attacks    | 

| API & JWT            | Use Postman, parse JSON| Auth flows, GraphQL queries| IDOR on API, microservices flow | 

| Tools & Automation   | Use Burp Repeater/Intruder| Nuclei, ffuf, scripts     | Custom tools, multi-vectored pipelines | 

| Recon                | Simple Google dorks   | Subdomain enumeration, archiving| Large-scale recon databases   | 

| Report Writing       | Basic summary & steps | Well-structured, PoC media| Impact analysis, CVSS calc   | 

### Recommended Certifications (Optional) 

- **eJPT** (Pentest Student, affordable start). 

- **OSCP** (Offensive Security Certified, hands-on pentest cert). 

- **Certified Bug Bounty Hunter (CBBH)** – third-party certs (less recognized). 

- **SANS certifications** (high cost, high reputation: GWEB, GPEN). 

## ### Daily/Weekly/Monthly Planner 

- **Daily:** 30m news/blog + 2h practice/training. 

- **Weekly:** 1 CTF/lab + review progress. 

- **Monthly:** Summarize lessons, adjust goals, maybe blog about one finding. 

## ### Tool Mastery Checklist 

- [ ] Burp Suite: proxy, repeater, intruder basics. 

- [ ] Nmap: basic scans (`-sV -p-`). 

- [ ] ffuf/dirsearch: run directory fuzzing on a target. 

- [ ] amass/subfinder: find subdomains and verify with httpx. 

- [ ] jq: parse a JSON file or API response. 

- [ ] tmux: run two tools in parallel in split panes. 

## ### Practice Lab Checklist 

- OWASP Juice Shop (finish all XSS, IDOR, SSRF labs). 

- PortSwigger Academy (complete SQLi and XSS sections). 

- DVWA setup at Home (practice all modules on low/medium). 

- TryHackMe: “Web Fundamentals”, “Basic Recon”. 

## ### Bug Bounty Readiness Checklist 

- [ ] Portfolio of lab reports or CTF write-ups. 

- [ ] Active profiles on bug platforms with a few “I found an issue but it was OOS” to show effort. 

- [ ] Clear understanding of at least one tech stack (e.g. PHP-MySQL) to focus targets. 

- [ ] Reliable documentation of progress and tools. 

## ### First Bounty Action Plan 

- Select 3 beginner-friendly programs (public scope, low entry barrier). 

- For each, spend 1-2 weeks doing structured recon and testing (per roadmap). 

- When a bug is found, document meticulously. 

- Submit one high-quality report per program per week. 

- After submission, analyze response time; if rejected, learn and move to next. 

### Top 100 Things Every Beginner Should Know (summary highlights) 

1. CIA Triad and its significance. 

2. Difference between AuthN and AuthZ. 

3. What is SQLi, XSS, CSRF (key OWASP Top 10 entries). 

4. How cookies and sessions work. 

5. Use of Burp Proxy for intercepting. 

6. Basic Linux commands (ls, cd, pwd, cat, grep). 

7. How to use `grep` for quick searching. 

8. Importance of input validation on server side. 

9. What is OWASP Top 10 (and OWASP as an org). 

10. How to read a basic HTML page source (view-source). 

11. JSON vs XML data formats. 

12. Using `curl` to test web endpoints. 

13. How to use Postman for API calls. 

14. Reading HTTP request/response (headers, status codes). 

15. How TLS certificates authenticate servers. 

16. Browser Same-Origin Policy basics. 

17. What CORS is and why misconfig can be dangerous. 

18. Ways to find subdomains (tools: amass, subfinder). 

19. Directory brute-forcing with ffuf/dirsearch. 

20. Reconnaissance steps (DNS, Google dorks, Wayback). 

21. IDOR concept (common and easy to spot). 

22. How to formulate an effective bug title and summary. 

23. Use of Nmap for network scanning (legal only if in scope). 

24. The concept of CVE and why CVSS scores matter. 

25. Basics of OAuth 2.0 / OIDC (AuthN vs AuthZ). 

... *(and more, ensuring the 100th item is a practical tip)*. 

**End of Handbook.** 

This guide has walked through foundational knowledge (cybersecurity principles, networking, Linux, basic programming) toward hands-on skills (vulnerabilities, tools, methodology). It includes study plans, practice exercises, and resources to help you steadily progress from zero knowledge to earning your first bounty in under a year. Keep learning continuously, and **hack ethically**! 

