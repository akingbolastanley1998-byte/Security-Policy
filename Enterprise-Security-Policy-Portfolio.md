# ENTERPRISE NETWORK SECURITY POLICY FRAMEWORK

## Professional Security Architecture & Governance Design

---

## Document Control

| Field | Details |
|-------|---------|
| **Client Sector** | Financial Services (UK) |
| **Project Type** | Enterprise Security Policy Design & Implementation |
| **Regulatory Scope** | PCI DSS v4.0, UK GDPR, FCA SYSC, DORA |
| **Project Duration** | 6 weeks |
| **Role** | Lead Security Consultant |
| **Deliverables** | Policy Framework, Technical Standards, Operational Procedures |
| **Classification** | Portfolio Case Study (Anonymized) |

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Risk Assessment & Threat Modeling](#risk-assessment)
3. [Network Security Policy](#network-security-policy)
4. [Technical Security Standards](#technical-standards)
5. [Operational Procedures](#operational-procedures)
6. [Architecture Design](#architecture-design)
7. [Implementation Outcomes](#outcomes)

---

## 1. Project Overview

### 1.1 Client Background

**Industry:** Financial Technology / Payment Processing  
**Scale:** Mid-tier UK financial institution  
**Customer Base:** 250,000+ customers  
**Services:** Retail banking, investment management, payment processing  
**Regulatory Bodies:** Financial Conduct Authority (FCA), Prudential Regulation Authority (PRA)

### 1.2 Project Objectives

The client required a comprehensive security governance framework to:

1. **Achieve regulatory compliance** with PCI DSS v4.0, UK GDPR, and FCA operational resilience requirements
2. **Implement defense-in-depth architecture** across enterprise network infrastructure
3. **Establish security baseline** aligned with ISO/IEC 27001:2022 and NIST CSF 2.0
4. **Document operational procedures** for incident response, change control, and access management
5. **Enable disaster recovery** with secure site-to-site connectivity between primary (London) and DR (Manchester) facilities

### 1.3 Scope of Work

**Deliverables:**
- Enterprise risk assessment with STRIDE threat modeling
- Complete network security policy framework
- Technical implementation standards (segmentation, cryptography, monitoring)
- Operational security procedures with four-eyes control
- Network architecture design with zone-based segmentation
- Compliance traceability matrix

**Constraints:**
- Policy must support existing Cisco-based infrastructure
- Zero-downtime requirement for implementation
- Must maintain PCI DSS compliance throughout transition
- Integration with existing SIEM (Splunk Enterprise Security)

---

## 2. Risk Assessment & Threat Modeling

### 2.1 Asset Inventory & CIA Classification

Critical information assets were classified using the CIA triad (Confidentiality, Integrity, Availability) in accordance with ISO/IEC 27001:2022 Annex A. Classification directly informed zone placement and control selection.

| Asset Category | Network Zone | C | I | A | Justification |
|----------------|-------------|---|---|---|---------------|
| Customer PII & Account Data | Core Operations | Critical | Critical | Critical | GDPR Article 32 protected data |
| Payment Card Data (PAN/CVV) | Core Operations | Critical | Critical | High | PCI DSS Cardholder Data Environment |
| Core Banking Applications | Core Operations | High | Critical | Critical | Transaction processing, fraud risk |
| Transaction Databases | Core Operations | Critical | Critical | Critical | Financial record integrity |
| Employee Workstations | Access Zone | Medium | High | High | Primary phishing vector |
| Internet-Facing Portal | Distribution Zone | High | High | Critical | Customer-facing service |
| Edge Network Devices | Distribution Zone | High | Critical | Critical | Perimeter security controls |
| SIEM Infrastructure | Core Operations | High | Critical | High | Forensic evidence preservation |
| Site-to-Site VPN | Distribution Zone | High | Critical | Critical | DR connectivity |
| DHCP/DNS Services | Core Operations | Medium | High | Critical | Network infrastructure integrity |
| Backup Systems | Core Operations | Critical | Critical | High | Business continuity requirement |

### 2.2 Data Classification Framework

| Tier | Classification | Description | Required Controls |
|------|---------------|-------------|-------------------|
| 1 | CRITICAL | Regulated data: PAN, CVV, National Insurance numbers, biometric credentials | AES-256 encryption, TLS 1.3, MFA, comprehensive logging |
| 2 | CONFIDENTIAL | PII and sensitive business data: account balances, salary records, audit findings | Encryption at rest and in transit, RBAC |
| 3 | INTERNAL | Non-public business data: policies, network diagrams, project documentation | Access restrictions, need-to-know basis |
| 4 | PUBLIC | Approved external content: interest rates, branch locations, annual reports | Integrity controls only |

### 2.3 Threat Identification Using STRIDE

STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) was applied to identify primary threat scenarios:

| ID | Threat Scenario | STRIDE Category | Attack Path | Likelihood | Impact | Risk Level | Primary Control |
|----|----------------|-----------------|-------------|------------|--------|-----------|-----------------|
| T1 | Ransomware via phishing with lateral encryption of Core servers | Tampering / DoS | Access → Core | High | Critical | **CRITICAL** | Network segmentation |
| T2 | Lateral movement from compromised endpoint to Core databases | Elevation of Privilege | Access → Core | High | Critical | **CRITICAL** | ACL + MFA |
| T3 | Insider misuse of privileged credentials for PII exfiltration | Information Disclosure / Repudiation | Core Operations | Medium | Critical | **HIGH** | Comprehensive logging |
| T4 | Man-in-the-Middle attack on site-to-site VPN | Spoofing / Info Disclosure | Distribution (VPN) | Medium | High | **HIGH** | IPsec with strong crypto |
| T5 | DDoS against internet-facing customer portal | Denial of Service | Distribution | High | High | **HIGH** | Edge ACL filtering |
| T6 | Rogue DHCP server injecting malicious gateway addresses | Spoofing | Access | Low | High | **MEDIUM** | DHCP snooping |
| T7 | Repudiation of admin configuration changes | Repudiation | All Zones | Medium | High | **HIGH** | SIEM + TACACS+ |

### 2.4 Control Objectives Mapped to NIST CSF 2.0

| Ref | Control Objective | CIA Protection | NIST CSF 2.0 Function | Mitigates Threats |
|-----|------------------|----------------|----------------------|-------------------|
| CO1 | Zone segmentation with default-deny posture | C, I, A | Protect (PR.AC-5) | T1, T2 |
| CO2 | Multi-factor authentication + named accounts | C, I | Protect (PR.AC-1, PR.AC-4) | T2, T3 |
| CO3 | Encryption (TLS/IPsec) for data in transit | C | Protect (PR.DS-2) | T4 |
| CO4 | Centralized SIEM logging | C, I | Detect (DE.CM-1), Respond (RS.AN-1) | T1, T3, T7 |
| CO5 | DHCP security hygiene | I, A | Protect (PR.AC-5) | T2, T6 |
| CO6 | Edge traffic filtering and NAT | A | Protect (PR.AC-5) | T5 |
| CO7 | Four-eyes change control | I | Govern (GV.OV-2) | T3, T7 |

### 2.5 Regulatory Compliance Requirements

| Regulation / Standard | Applicability | Control Areas |
|----------------------|---------------|---------------|
| **UK GDPR / DPA 2018** | Mandatory - processes personal data | Data classification, encryption, access control, logging, breach notification |
| **PCI DSS v4.0** | Mandatory - processes payment card data | Network segmentation, default-deny rules, TLS encryption, SIEM logging |
| **FCA SYSC 8 / DORA** | Mandatory - FCA-regulated entity | Availability controls, incident response, disaster recovery, VPN security |
| **NCSC Cyber Essentials Plus** | Recommended - PRA guidance | ACL configuration, system hardening, patch management, access control |
| **ISO/IEC 27001:2022** | Organizational alignment | All control domains including A.5 (organizational), A.8 (technical) |

---

## 3. Network Security Policy

### 3.1 Policy Statement & Governance

**Purpose:**  
This Network Security Policy establishes the security governance framework to protect information assets across the enterprise network infrastructure. It applies to all employees, contractors, and third-party providers with network access.

**Authority:**  
- Approved by: Board Risk Committee
- Issued by: Chief Information Security Officer (CISO)
- Replaces: All previous network security policies
- Review Cycle: Annual (or within 30 days of major regulatory/architectural change)

**Objectives:**  
Ensure confidentiality, integrity, and availability of information assets in accordance with regulatory requirements and board risk appetite.

### 3.2 Policy Scope

**Applicable Systems:**
- All routers, switches, firewalls, VPN gateways
- DHCP, DNS, logging, and monitoring infrastructure
- All three network zones (Access, Core Operations, Distribution)
- All user accounts with logical or physical access
- Remote connections including London-Manchester VPN link
- Third-party provider connections

**Exclusions:**  
Systems not connected to the enterprise network are governed by separate policies.

### 3.3 Governing Principles

| Principle | Policy Statement |
|-----------|-----------------|
| **Least Privilege** | Access granted only to the minimum extent necessary for business function. Default inter-zone posture is deny-all; permitted flows are explicitly whitelisted. Any/any rules are prohibited. |
| **Defense in Depth** | Multiple independent security controls cascade such that no single failure creates unacceptable risk. Perimeter ACLs, NGFW stateful inspection, WAF, and endpoint security operate independently. |
| **Segregation of Duties** | No individual has sole authority to implement and approve changes. All changes require two named authorized individuals (four-eyes control). |
| **Auditability** | All security events including permit/deny decisions, authentication attempts, and configuration changes are logged with accurate timestamps and retained for forensic analysis. |
| **Fail Secure** | Upon control failure (e.g., NGFW crash), default behavior is to deny traffic. Fail-open configurations are prohibited. |
| **Cryptographic Hygiene** | Deprecated protocols (SSLv3, TLS 1.0/1.1, DES, 3DES, MD5, RC4) are prohibited. Only approved algorithms specified in Technical Standards may be used. |

### 3.4 Roles & Responsibilities

| Role | Security Responsibilities |
|------|--------------------------|
| **CISO** | Policy ownership, exception approval for high/critical risks |
| **Network Security Manager (NSM)** | Firewall rule base maintenance, quarterly audits |
| **Network Engineers (L2/L3)** | Implementation of approved changes, evidence documentation |
| **Change Advisory Board (CAB)** | Change approval for medium+ risk modifications |
| **Security Operations Centre (SOC)** | 24/7 monitoring, incident detection and response |
| **Data Protection Officer (DPO)** | GDPR compliance oversight |
| **All Staff** | Mandatory incident reporting |
| **Third-Party Suppliers** | Contractual obligation to comply with policy |

### 3.5 Exception Management Process

1. **Request Submission:** Requestor submits Policy Exception Request Form (PERF) via ServiceNow including business justification, affected systems, compensating controls, and requested duration (maximum 90 days)

2. **Risk Assessment:** NSM completes risk assessment within 5 working days and determines residual risk rating

3. **Approval Authority:**
   - Low/Medium residual risk: NSM approval
   - High/Critical residual risk: CISO sign-off required

4. **Registration:** Approved exceptions recorded in Exception Register with expiry date

5. **Expiry Enforcement:** Expired exceptions automatically revoked after 24-hour grace period with requestor notification

### 3.6 Enforcement & Sanctions

**Compliance is mandatory** for all employees, contractors, and third parties.

**Enforcement Actions:**
- Immediate account suspension for material breach
- Disciplinary action up to and including termination for employees
- Contract termination and access revocation for contractors/vendors
- Law enforcement referral for violations of Computer Misuse Act 1990 or DPA 2018
- Immediate CISO escalation for circumvention of security controls

**Quarterly Review:** NSM reviews enforcement effectiveness and reports to Board Risk Committee.

### 3.7 Logging & Retention Requirements

| Event Category | Online Retention | Archive Retention | Storage Type |
|----------------|-----------------|-------------------|--------------|
| Firewall permit/deny logs | 12 months | 7 years | WORM (Write Once Read Many) |
| Authentication events (success/failure) | 12 months | 7 years | WORM |
| VPN session establishment/teardown | 12 months | 7 years | Standard archive |
| Configuration changes (TACACS+) | Indefinite | N/A | Git repository |
| DHCP lease assignments | 6 months | N/A | Standard storage |
| NAT translation logs | 6 months | N/A | Standard storage |

**Access Controls:** Log access restricted to SOC, NSM, and CISO only. All log access is itself logged (meta-logging).

### 3.8 Change Control Governance

**Change Categories:**
- **Standard:** Pre-approved low-risk changes (e.g., routine password rotation)
- **Normal:** Require risk assessment and CAB approval
- **Emergency:** Active incident; verbal NSM approval, retrospective CAB within 48 hours

**Mandatory Requirements:**
- **Four-eyes principle:** One person implements, independent second person verifies. Self-approval prohibited.
- **Evidence requirement:** Post-implementation evidence (screenshots, ACL hit counters, log samples) attached to change ticket within 4 hours
- **Rollback readiness:** All changes must include documented rollback procedure

### 3.9 Compliance Auditing Schedule

| Audit Activity | Frequency | Conducted By | Deliverable |
|----------------|-----------|--------------|-------------|
| Firewall rule base review | Quarterly | NSM + independent engineer | Annotated rule export, discrepancy CRs |
| Privileged account review | Quarterly | NSM | Signed Access Review Register |
| SIEM source health check | Monthly | SOC Lead | Source health dashboard report |
| Exception register review | Quarterly | NSM | Updated register to CISO |
| PCI DSS compliance validation | Annually | CISO + External QSA | Report on Compliance (RoC) or SAQ |
| Internal security audit | Annually | Internal Audit + CISO | Audit report with remediation plan to Board |

---

## 4. Technical Security Standards

### 4.1 Network Segmentation & Default-Deny Standard

#### 4.1.1 Zone Architecture

| Zone | Trust Level | Primary Function | Subnet Allocation |
|------|-------------|------------------|-------------------|
| **Access Zone** | Low | End-user devices, employee workstations | 10.10.10.0/24 (London), 10.20.10.0/24 (Manchester) |
| **Distribution Zone** | Medium | Internet edge, DMZ, external-facing services | 10.10.1.0/24 (London), 10.20.1.0/24 (Manchester) |
| **Core Operations Zone** | High | Critical systems, databases, PCI CDE | 10.10.20.0/24 (London), 10.20.20.0/24 (Manchester) |

**Segmentation Requirements:**
- Each zone uses separate subnet and VLAN
- Inter-zone routing permitted only through controlled Layer-3 enforcement points
- No flat network segments spanning multiple zones

#### 4.1.2 Inter-Zone Traffic Matrix (Default: DENY ALL)

| Source Zone | Destination Zone | Protocol/Port | Decision | Justification |
|-------------|------------------|---------------|----------|---------------|
| Access | Distribution | TCP 443 (HTTPS) | **PERMIT** | Web portal access |
| Access | Distribution | TCP 80 (HTTP) | **DENY** | Force encrypted connections |
| Access | Core Operations | TCP 443 (HTTPS) | **PERMIT (restricted)** | Application access via proxy |
| Access | Core Operations | TCP 5432 (PostgreSQL) | **DENY** | No direct database access |
| Access | Core Operations | TCP 22 (SSH) | **DENY** | No direct admin access |
| Distribution | Core Operations | TCP 443, 8443 | **PERMIT (restricted)** | Application server communication |
| Distribution | Core Operations | ANY other | **DENY** | Default deny |
| Core Operations | Distribution | TCP 443 | **PERMIT (restricted)** | Outbound API calls |
| Core Operations | Access | ANY | **DENY** | Prevent reverse connections |
| External (Internet) | Distribution | TCP 443 | **PERMIT** | Customer portal |
| External (Internet) | Distribution | ANY other | **DENY** | Edge filtering |
| VPN Peer (Manchester) | Core Operations | TCP 443, 5432, 22 | **PERMIT (restricted)** | DR replication, jump server |
| ANY | ANY | ICMP (except echo-reply) | **DENY** | Prevent reconnaissance |

**Enforcement Rules:**
1. All DENY decisions must be explicitly configured (no implicit deny without logging)
2. Any/any rules are strictly prohibited
3. All permit and deny events must generate syslog entries
4. ACL hit counters must be reviewed during quarterly audits
5. VLAN-based segmentation enforced at Layer 2

### 4.2 Identity & Administrative Access Standard

**Authentication Requirements:**
- Multi-factor authentication (MFA) mandatory for all administrative access
- Named individual accounts only - shared/generic accounts prohibited
- SSH version 2.0 minimum (SSHv1 disabled)
- Administrative access restricted to dedicated management VLAN
- TACACS+ centralized authentication with command accounting enabled

**Session Management:**
- Just-in-time (JIT) administrative sessions with automatic timeout
- Maximum session duration: 8 hours
- Idle timeout: 15 minutes
- Concurrent session limit: 2 per admin account

**Access Review:**
- Quarterly review of all administrative accounts
- Annual recertification of privileged access
- Immediate revocation upon role change or termination

**Audit Trail:**
- All administrative commands logged to SIEM via TACACS+
- Timestamped with NTP-synchronized clocks
- Privileged command execution requires business justification in ticket reference

### 4.3 Cryptographic Standard

This standard specifies minimum cryptographic requirements for network communications, remote access, and data protection.

#### 4.3.1 TLS Requirements

| Use Case | Minimum Version | Prohibited Versions | Approved Cipher Suites |
|----------|----------------|---------------------|----------------------|
| **Internal HTTPS** (apps, APIs) | TLS 1.2 | SSLv3, TLS 1.0, TLS 1.1 | TLS_AES_256_GCM_SHA384<br>TLS_CHACHA20_POLY1305_SHA256 |
| **External HTTPS** (customer portal) | TLS 1.3 (preferred)<br>TLS 1.2 (fallback) | SSLv3, TLS 1.0, TLS 1.1 | TLS 1.3 mandatory ciphers<br>TLS 1.2: ECDHE+AES-GCM only |
| **Administrative SSH** | SSH 2.0 | SSH 1.x | aes256-gcm@openssh.com<br>chacha20-poly1305<br>ecdh-sha2-nistp384 (KEX) |
| **Inter-server API** | TLS 1.2 | SSLv3, TLS 1.0, TLS 1.1 | ECDHE-RSA-AES256-GCM-SHA384<br>Mutual TLS (mTLS) for Core-to-Core |

#### 4.3.2 IPsec VPN Site-to-Site Standard

| Parameter | Required Configuration | Prohibited Configurations |
|-----------|----------------------|--------------------------|
| **IKE Version** | IKEv2 mandatory | IKEv1 prohibited |
| **Phase 1 Encryption** | AES-256 | DES, 3DES, AES-128 |
| **Phase 1 Integrity** | SHA-384 or SHA-512 | MD5, SHA-1 |
| **Phase 1 DH Group** | Group 20 (384-bit ECP) or Group 21 | Groups 1, 2, 5, 14 (Logjam vulnerable) |
| **Phase 2 Encryption** | AES-256-GCM (preferred)<br>AES-256-CBC+HMAC-SHA-256 | DES, 3DES, AES-128-CBC without HMAC |
| **Perfect Forward Secrecy** | Mandatory - DH Group 20 minimum | Disabled PFS |
| **Phase 1 Lifetime** | 86,400 seconds (24 hours) | Values exceeding 24 hours |
| **Phase 2 Lifetime** | 3,600 seconds (1 hour) | Values exceeding 1 hour |
| **Authentication** | RSA 4096-bit certificate from internal CA (production)<br>PSK (lab/testing only) | MD5 authentication<br>Plaintext PSK storage |
| **Dead Peer Detection** | Enabled (interval: 30s, retry: 5) | Disabled DPD |

#### 4.3.3 General Cryptographic Requirements

- **Data at Rest:** AES-256 minimum
- **Hashing/Integrity:** SHA-256 minimum
- **Certificate Authority:** RSA 4096-bit for root CA certificates
- **Elliptic Curve:** ECDSA P-384 and P-521 preferred for new implementations
- **Key Storage:** All cryptographic keys stored in Core Operations Zone Hardware Security Module (HSM)
- **Certificate Validity:** Maximum 398 days; expiry alerts generated 60 days prior to expiration

### 4.4 Security Monitoring & Logging Standard

**SIEM Platform:** Splunk Enterprise Security deployed in Core Operations Zone (10.10.20.10)

**Log Transport:**
- TLS-encrypted syslog only (TCP port 6514)
- Unencrypted syslog (UDP port 514) disabled network-wide
- Mutual authentication between log sources and SIEM

**Real-time Correlation:** Centralized correlation engine with automated alerting and forensic dashboards

| Logging Source | Events to Capture | Priority Level |
|----------------|-------------------|----------------|
| **Firewalls & NGFWs** | All permit/deny decisions on inter-zone traffic<br>Firewall rule base modifications<br>Interface state changes | Critical |
| **Routers & L3 Switches** | ACL hit events<br>Routing protocol neighbor changes<br>Interface up/down events<br>Configuration saves | High |
| **Authentication Systems** | Login success/failure<br>MFA acceptance/rejection<br>Account lockout events<br>Privilege escalation attempts | Critical |
| **VPN Gateways** | Tunnel establishment/teardown<br>IKE negotiation failures<br>Dead Peer Detection timeouts<br>Certificate validation failures | High |
| **Core Banking Servers** | Application authentication events<br>Privileged account activity<br>PCI CDE data access | Critical |
| **DHCP Servers** | Lease assignments and renewals<br>DHCP snooping violations<br>Scope exhaustion alerts<br>Rogue DHCP server detection | Medium |
| **NAT Devices** | NAT table creation/deletion<br>NAT pool exhaustion warnings | Medium |
| **NTP Services** | Stratum synchronization status<br>Clock synchronization failures<br>Stratum drift alerts | Medium |

**Time Synchronization:**
- All devices synchronized to Core Operations Zone Stratum 2 NTP server (10.10.20.15)
- NTP server synchronized to UK government Stratum 1 time sources
- Maximum permitted clock skew: 500ms (exceeding triggers Critical SIEM alert)
- Log buffering: 24-hour local buffer if SIEM becomes unreachable

### 4.5 Vulnerability & Patch Management Standard

#### Vulnerability Scanning Schedule

| Scope | Scan Frequency | Authentication | Tooling | Remediation SLA |
|-------|---------------|----------------|---------|-----------------|
| All network devices | Weekly | Authenticated | Tenable Nessus / Qualys | Critical: 48h<br>High: 7 days<br>Medium: 30 days<br>Low: 90 days |
| Distribution Zone (external-facing) | Daily (unauthenticated)<br>Weekly (authenticated) | Both | Qualys WAS + Nessus | Critical: 4h<br>High: 24h<br>Medium: 7 days |
| VPN gateway configurations | Monthly | CIS Benchmark compliance | CIS-CAT Pro | Non-compliance: 14 days |
| Core Operations servers | Fortnightly | Authenticated | Tenable Nessus | Critical: 48h<br>High: 7 days |

#### Patch Management Process

**Testing Requirements:**
- All patches tested in non-production lab environment for minimum 5 working days
- Exception: Zero-day patches use Emergency change process with reduced testing window

**Patch Windows:**
- **Access/Distribution Zones:** Every second Saturday, 00:00-04:00 UK time
- **Core Operations Zone:** Every fourth Saturday, 00:00-06:00 UK time

**Post-Patch Verification:**
1. Device functionality confirmed
2. Routing tables validated
3. ACL correctness verified
4. VPN tunnel status confirmed
5. SIEM log reception validated
6. Evidence attached to change ticket within 4 hours

**Change Control:**
All firewall rules, ACLs, VPN configurations, DHCP settings, and routing changes require:
- One implementer (hands-on execution)
- One independent approver (verification)
- Approver validates no introduction of prohibited permit rules or denial of required flows per Traffic Matrix (Section 4.1.2)

---

## 5. Operational Security Procedures

### 5.1 Firewall/ACL Rule Change Procedure

All steps specify exact systems, forms, and commands. Four-eyes control enforced at Steps 2 and 5.

| Step | Action | System/Tool | Responsible | Evidence Required |
|------|--------|-------------|-------------|-------------------|
| **1** | Engineer creates Change Request via ServiceNow using template NET-FW-CHANGE. Mandatory fields: business justification, source/destination IP, protocol/port, zone boundary, rollback commands, risk score. | ServiceNow - NET-FW-CHANGE template | Requesting Engineer | CR ticket with all mandatory fields populated |
| **2** | NSM reviews CR against Inter-Zone Traffic Matrix (Section 4.1.2). Verifies: (a) no any/any permits, (b) rollback commands provided, (c) flow not already denied without valid exception. Approves/denies with written rationale. **(Four-eyes principle)** | ServiceNow CR approval workflow | NSM (independent approver) | CR status set to 'Approved'<br>NSM name, timestamp, rationale recorded |
| **3** | Normal changes (Medium+ risk) escalated to CAB. Emergency changes receive verbal NSM approval with retrospective CAB review within 48 hours. | SharePoint CAB minutes / Emergency CAB email | CAB / NSM | CAB approval record attached to CR |
| **4** | Engineer configures ACL in non-production lab (Packet Tracer or EVE-NG). Performs positive test (permitted traffic passes, permit log captured) and negative test (blocked traffic denied, ACL hit counter increments). Screenshots captured. | Packet Tracer / EVE-NG<br>CLI: `show access-lists`<br>`show logging` | Implementing Engineer | Lab permit log + deny counter screenshots attached to CR |
| **5** | Engineer configures in production during maintenance window. Second engineer observes **(four-eyes)**. Configuration saved: `write memory`. Committed to Git: `git commit -m 'CR#[n] - [description]'` | Production router/firewall CLI<br>GitLab | Implementing Engineer + Observer | Production ACL export<br>Git commit hash recorded in CR |
| **6** | Within 4 hours: Engineer re-runs positive/negative tests in production. Captures `show access-lists` (hit counters) and Splunk query: `index=network src_ip=[X] dest_ip=[Y]` confirming permit/deny logs received. | Production CLI<br>Splunk SIEM | Implementing Engineer | ACL hit counter screenshot<br>Splunk log query results attached to CR |
| **7** | NSM reviews all evidence, confirms tests passed, closes CR. Updates Network Change Log (SharePoint: /Network/ChangeLog.xlsx) with CR number, date, engineer, device, change summary, Git commit hash. | ServiceNow CR closure<br>SharePoint Change Log | NSM | CR closed<br>Change Log updated |

### 5.2 Security Incident Triage Procedure

All steps specify exact escalation paths and regulatory notification thresholds.

| Step | Action | System/Tool | Responsible | Timeframe |
|------|--------|-------------|-------------|-----------|
| **1** | SOC analyst creates Security Incident Record in ServiceNow (template SEC-INC). Records: alert source, affected devices, source/destination IPs, UTC timestamp, initial description. | Splunk SIEM alert<br>ServiceNow SEC-INC | SOC Analyst T1 | Within 5 minutes |
| **2** | Analyst triages: checks Splunk for corroborating events, confirms not false positive. Classifies: P1 (active breach), P2 (imminent exploitation), P3 (contained anomaly), P4 (informational). False positive closed with documented rationale. | Splunk correlation search<br>Incident Classification Matrix | SOC Analyst T1/T2 | Within 15 minutes |
| **3** | P1/P2 incidents: Analyst phones SOC Lead; SOC Lead phones NSM. NSM assesses isolation requirement. Confirmed lateral movement, C2 beacon, or active exfiltration triggers Step 4. | Phone escalation<br>ServiceNow incident update | SOC Lead / NSM | P1: 30 min<br>P2: 1 hour |
| **4** | NSM implements containment in order: (a) Deny ACL: `ip access-list extended BLOCK / deny ip host [X] any log`, (b) Null route: `ip route [X] 255.255.255.255 Null0`, (c) VLAN shutdown: `interface vlan [X] / shutdown`. All commands logged with timestamp in ServiceNow. | Production router/firewall CLI<br>ServiceNow | NSM / Network Engineer | P1: 1 hour<br>P2: 2 hours |
| **5** | CISO notified by phone for P1/P2. DPO assesses GDPR breach against 72-hour ICO notification threshold. NSM/CISO assess FCA DORA material disruption against 4-hour notification threshold. All decisions documented in ServiceNow. | ServiceNow<br>Phone to CISO/DPO | NSM / CISO / DPO | P1: 1 hour<br>P2: 2 hours |
| **6** | SOC T2/T3 reconstructs kill chain. Splunk query: `index=network \| transaction src_ip maxspan=1h`. Packet captures via Wireshark on SPAN port. Forensic artifacts saved to WORM storage with chain of custody documentation. | Splunk transaction search<br>Wireshark SPAN<br>WORM storage | SOC Tier 2/3 | Within 24h of containment |
| **7** | Incident closed in ServiceNow. Post-Incident Review (PIR) completed within 5 working days using template (SharePoint: /Security/PIR-Template.docx). PIR submitted to CISO. Control improvements initiated via formal Change Request. | ServiceNow closure<br>PIR template | NSM / CISO | PIR within 5 working days |

### 5.3 User Onboarding & Offboarding

#### Network Administrator Onboarding

| Step | Action | System | Timeframe |
|------|--------|--------|-----------|
| 1 | HR sends notification to NSM at least 5 working days prior to start date | Email / ServiceNow | -5 days |
| 2 | NSM initiates Access Provisioning Request (APR) in ServiceNow with access level (Read-only / Engineer / Senior Engineer / NSM) and business justification | ServiceNow APR | Within 24h of notification |
| 3 | CISO approves APR with digital signature | ServiceNow approval | Within 48h |
| 4 | Individual named account created in RADIUS/TACACS+ AAA server with specific privilege group assignment. No generic accounts permitted. | RADIUS/TACACS+ server | Day -1 (before start) |
| 5 | MFA enrollment: TOTP or FIDO2 hardware key registered. Backup codes stored in physical safe. | RADIUS/TACACS+ + MFA system | Day 1 (first day) |
| 6 | Account added to Privileged Access Management (PAM) system with role-based session duration limits | PAM system | Day 1 |
| 7 | Account added to Quarterly Access Review Register | Access Review spreadsheet | Day 1 |

#### Network Administrator Offboarding

| Step | Action | System | Timeframe |
|------|--------|--------|-----------|
| 1 | HR notifies NSM within 1 hour of termination, role change, or suspension | Email / ServiceNow | Within 1 hour |
| 2 | NSM immediately disables account in RADIUS/TACACS+ AAA server and deregisters MFA token | RADIUS/TACACS+ + MFA | Within 1 hour of notification |
| 3 | VPN certificate revoked via internal CA. OCSP and CRL updated immediately. Propagation confirmed within 15 minutes. | PKI / Internal CA | Within 1 hour |
| 4 | PAM system access terminated. All active sessions forcibly disconnected. | PAM system | Within 1 hour |
| 5 | NSM sends confirmation email to HR, CISO, DPO within 2 hours of completion | Email | Within 2 hours |
| 6 | Account retained in disabled state for 90 days, then permanently deleted. Deletion recorded in Access Review Register. | RADIUS/TACACS+ | 90 days post-termination |

### 5.4 Backup & Disaster Recovery Verification

| Step | Action | Frequency | Responsible |
|------|--------|-----------|-------------|
| **1** | Network device configurations backed up nightly to Git repository with AES-256 encryption. Version-tagged with engineer ID, hostname, UTC timestamp. | Daily (automated) | Ansible automation<br>NSM weekly verification |
| **2** | NSM confirms backup files are non-zero size, decrypt correctly, match last known good config hash (SHA-256). | Weekly | NSM |
| **3** | Partial restore test: Restore one non-production device config from backup into lab environment. Verify routing tables, ACL correctness, VPN tunnel configuration. | Monthly | Engineer + NSM (four-eyes) |
| **4** | Full DR failover test: Simulate primary site loss. Activate Manchester DR site. Verify VPN re-establishment, routing convergence, DHCP/DNS service continuity. Measure against RTO target (4 hours). | Annually + post-major-change | NSM + CISO + DR Team |
| **5** | DR test results documented in DR Test Report. RTO miss or identified gap triggers remediation Change Request with defined SLA. | Per test schedule | NSM |

---

## 6. Network Architecture Design

### 6.1 Architecture Overview

The security architecture implements a **three-zone defense-in-depth model** with strictly controlled inter-zone traffic flows. Each zone operates at a different trust level with dedicated enforcement points at every boundary.

**Key Architectural Principles:**
- **Zone-based segmentation:** Access, Distribution, and Core Operations zones with separate subnets and VLANs
- **Default-deny posture:** All inter-zone traffic denied unless explicitly permitted via Traffic Matrix
- **Stateful inspection:** Next-Generation Firewall (NGFW) at Distribution/Core boundary
- **Layer-3 enforcement:** ACLs applied at inter-zone router interfaces
- **No direct Core access:** All Access Zone users reach Core Operations only via NGFW enforcement
- **Disaster recovery:** Secure site-to-site IPsec VPN between London (primary) and Manchester (DR)

### 6.2 Logical Zone Diagram

```
                              ┌─────────────────┐
                              │ Internet / WAN  │
                              └────────┬────────┘
                                       │
                              ┌────────┴────────┐
                              │  Edge Router R1 │
                              │  203.0.113.1    │
                              └────────┬────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
    ┌─────┴─────┐            ┌────────┴────────┐        ┌─────────┴──────────┐
    │    NAT    │            │  VPN Gateway    │        │ Web Application FW │
    │  Firewall │            │   (GRE/IPsec)   │        │      (WAF)         │
    └───────────┘            └─────────────────┘        └────────────────────┘
          │                            │
          └────────────────────────────┴───────────────────────┐
                                                                │
                                        ┌───────────────────────┴───────────────────────┐
                                        │         Distribution Zone (DMZ)               │
                                        │              10.10.1.0/24                     │
                                        │   ┌──────────────────────────────────────┐   │
                                        │   │  Application Servers / Proxy / Jump  │   │
                                        │   └──────────────────────────────────────┘   │
                                        └───────────────────┬───────────────────────────┘
                                                            │
                                                  ┌─────────┴─────────┐
                                                  │   NGFW (Stateful  │
                                                  │    Inspection)    │
                                                  └─────────┬─────────┘
                                                            │
          ┌─────────────────────────────────────────────────┴─────────────────────────────────────────────┐
          │                                    Core Operations Zone                                        │
          │                                       10.10.20.0/24                                            │
          │   ┌──────────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────┐  ┌────────────┐              │
          │   │ Transaction  │  │   Banking   │  │  Splunk  │  │   NTP   │  │ DHCP Server│              │
          │   │  Database    │  │ Application │  │   SIEM   │  │  Server │  │  (Central) │              │
          │   │(PostgreSQL)  │  │   Servers   │  │10.10.20.10│ │10.10.20.│  │ 10.10.20.5 │              │
          │   └──────────────┘  └─────────────┘  └──────────┘  └─────────┘  └────────────┘              │
          └──────────────────────────────────────────────────────────────────────────────────────────────┘
                                                            │
                                                            │ (via DHCP relay)
                                                            │
          ┌─────────────────────────────────────────────────┴─────────────────────────────────────────────┐
          │                                   Access Zone (Untrusted)                                       │
          │                                      10.10.10.0/24                                              │
          │   ┌──────────────┐  ┌──────────────┐  ┌───────────┐  ┌──────────┐                            │
          │   │   Network    │  │   Employee   │  │ IP Phones │  │ Printers │                            │
          │   │Access Control│  │ Workstations │  │           │  │          │                            │
          │   │   (802.1X)   │  │              │  │           │  │          │                            │
          │   └──────────────┘  └──────────────┘  └───────────┘  └──────────┘                            │
          └────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Architecture Design Rationale

The following table justifies key security design decisions and explains rejected alternatives:

| Design Decision | Security Rationale | Alternative Rejected & Why |
|-----------------|-------------------|---------------------------|
| **NGFW at Distribution/Core boundary (not only WAN edge)** | Single perimeter firewall creates flat network. If Distribution Zone host compromised (e.g., web server), attacker gains full Core database access. Placing NGFW at Distribution/Core boundary enforces default-deny for internal traffic, directly mitigating T2 (lateral movement) and fulfilling PCI DSS Requirement 1 for CDE isolation. | **Rejected:** Single WAN-edge firewall only. Does not protect against threats originating inside perimeter (phishing, insider - T3). Fails PCI DSS Req. 1. |
| **SIEM in Core Operations Zone (not Distribution)** | SIEM contains complete forensic audit trail. Placing in Distribution Zone (partially internet-facing) exposes integrity to T5 (DDoS) and T4 (MitM). Core Operations Zone is fully trusted with inbound access only from approved sources via ACLs. | **Rejected:** SIEM in Distribution Zone. DDoS or compromise of Distribution device could destroy forensic evidence needed to investigate that same incident. |
| **DHCP server in Core Operations (serves all zones via relay)** | DHCP server in Access Zone is trivially compromised. Placing in Core Operations ensures even fully compromised Access Zone cannot redirect gateway/DNS (T6 rogue DHCP). DHCP snooping on Access switch provides secondary defense. | **Rejected:** DHCP in Access Zone. Direct T6 attack vector. Rogue DHCP injection for default gateway enables full MitM on all Access Zone traffic. |
| **VPN terminates at Distribution edge (not Core)** | Traffic decrypted at perimeter and passed to NGFW for inspection prior to Core arrival. DR replication traffic still traverses inter-zone Traffic Matrix, denying compromised Manchester DR site access to Core with valid VPN credentials alone. | **Rejected:** VPN terminating at Core Operations router. Completely bypasses NGFW inspection. Compromised DR site gains direct, unfiltered Core access. |
| **RIPv2 internally; static default at WAN edge** | Automatic convergence via RIPv2 for lab topology without OSPF/BGP overhead. Static default route prevents internet routes being injected. RIP MD5 authentication stops rogue route announcements (T2 network enumeration). | **Rejected:** OSPF/BGP throughout. Adds complexity without security benefits. BGP requires AS number management, unsuitable for internal three-zone environment. |
| **NTP master in Core Operations; all devices sync inward** | Timestamps must match across systems for forensic analysis. 1-second difference invalidates SIEM correlation. Internal NTP eliminates WAN dependency (T5 DDoS could take down external NTP) and prevents NTP amplification attacks. | **Rejected:** All devices sync to internet NTP. Adds WAN dependency for log integrity. Devices susceptible to NTP amplification attacks if authentication not enforced. |

### 6.4 Network Parameters

#### London Primary Site

| Component | Configuration |
|-----------|--------------|
| **Edge Router** | R1 - WAN: 203.0.113.1, LAN: 10.10.1.1 |
| **VPN Tunnel** | Tunnel0: 172.16.0.1/30 (GRE/IPsec) |
| **Access Zone** | 10.10.10.0/24 (VLAN 10) |
| **Distribution Zone** | 10.10.1.0/24 (VLAN 1) |
| **Core Operations** | 10.10.20.0/24 (VLAN 20) |
| **DHCP Server** | 10.10.20.5 (serves all VLANs via relay) |
| **SIEM (Splunk)** | 10.10.20.10 (centralized logging) |
| **NTP Server** | 10.10.20.15 (Stratum 2 master) |
| **Internal CA/PKI** | 10.10.20.25 (device and VPN certificates) |
| **Dynamic Routing** | RIPv2 - redistributes 10.10.0.0/16 subnets |

#### Manchester DR Site

| Component | Configuration |
|-----------|--------------|
| **Edge Router** | R3 - WAN: 198.51.100.1, LAN: 10.20.1.1 |
| **VPN Tunnel** | Tunnel0: 172.16.0.2/30 (GRE/IPsec) |
| **Access Zone** | 10.20.10.0/24 (VLAN 10) |
| **Distribution Zone** | 10.20.1.0/24 (VLAN 1) |
| **Core Operations** | 10.20.20.0/24 (VLAN 20) |
| **DHCP Server** | 10.20.20.5 (serves all VLANs via relay) |
| **SIEM** | Forwards to London SIEM (10.10.20.10) via VPN |
| **NTP Server** | Synchronizes from London NTP via VPN |
| **Dynamic Routing** | RIPv2 - mirror configuration |

#### VPN Interesting Traffic

| Direction | Traffic Scope |
|-----------|--------------|
| **London → Manchester** | 10.10.20.0/24 (Core) → 10.20.20.0/24 (DR replication) |
| **Manchester → London** | 10.20.20.0/24 → 10.10.20.0/24 (failover traffic) |

### 6.5 Control-to-Threat Traceability Matrix

This matrix demonstrates how architectural controls map to identified threats:

| Threat | STRIDE Category | Policy Reference | Control Objective | Implementation | Validation Evidence |
|--------|----------------|------------------|-------------------|----------------|---------------------|
| **T1:** Ransomware via phishing | Tampering / DoS | Section 3.3, 3.6 | CO-1, CO-4 | Default-deny ACL between Access→Core; backups on isolated VLAN | **Negative test:** TCP 5432 Access→Core DENIED; ACL hit counter increment |
| **T2:** Lateral movement | Elevation of Privilege | Section 4.1 | CO-1, CO-2, CO-5 | Inter-zone ACL; DHCP snooping on Access switch; named admin accounts | **Positive:** TCP 443 PERMITTED; **Negative:** TCP 5432 DENIED; DHCP lease screenshot |
| **T3:** Insider threat / privilege abuse | Info Disclosure / Repudiation | Section 3.4, 3.8, 4.2 | CO-2, CO-7 | TACACS+ command accounting; MFA enforcement; four-eyes change control | TACACS+ accounting log; admin session screenshot; CR approval record |
| **T4:** VPN MitM attack | Spoofing / Info Disclosure | Section 4.3.2 | CO-3 | IKEv2 IPsec with AES-256-GCM; certificate-based authentication | `show crypto isakmp sa`; `show crypto ipsec sa`; traceroute via tunnel |
| **T5:** DDoS against customer portal | Denial of Service | Section 4.1.2, 3.3 | CO-6 | Edge ingress ACL deny-all except TCP 443; NAT/PAT at WAN edge | NAT translation table; edge ACL deny counter; permit log for TCP 443 |
| **T6:** Rogue DHCP server | Spoofing | Section 4.1, 4.2 | CO-5 | DHCP snooping on Access switch; trusted port configuration to Core DHCP | DHCP lease screenshots; snooping violation log if triggered |
| **T7:** Log tampering / repudiation | Repudiation | Section 3.7, 4.4 | CO-4 | TLS syslog to SIEM with WORM storage; TACACS+ command accounting | SIEM log ingestion screenshot; NTP sync confirmation; WORM config |

---

## 7. Implementation Outcomes

### 7.1 Project Deliverables

**Policy Documentation:**
- ✅ Complete Network Security Policy (Section 3)
- ✅ Technical Security Standards (Section 4)
- ✅ Operational Security Procedures (Section 5)
- ✅ Architecture design with zone diagrams (Section 6)

**Technical Specifications:**
- ✅ Inter-zone traffic matrix with default-deny enforcement
- ✅ Cryptographic standards (TLS 1.2/1.3, IPsec IKEv2)
- ✅ SIEM logging requirements and retention schedules
- ✅ Vulnerability and patch management SLAs

**Governance Framework:**
- ✅ Four-eyes change control process
- ✅ Policy exception management workflow
- ✅ Security incident triage procedure
- ✅ Quarterly compliance audit schedule

### 7.2 Regulatory Alignment

| Regulation | Requirements Addressed | Controls Implemented |
|------------|----------------------|---------------------|
| **PCI DSS v4.0** | Req. 1: Network segmentation<br>Req. 2: Vendor defaults<br>Req. 8: Access control<br>Req. 10: Logging | Default-deny ACLs<br>DHCP snooping<br>MFA + TACACS+<br>Splunk SIEM with 7-year retention |
| **UK GDPR** | Art. 32: Security measures<br>Art. 33: Breach notification | AES-256 encryption<br>TLS 1.3 for data in transit<br>72-hour breach notification procedure |
| **FCA SYSC 8** | Operational resilience<br>Outsourcing governance | DR site with 4-hour RTO<br>Site-to-site VPN<br>Backup verification testing |
| **ISO 27001:2022** | A.5: Organizational controls<br>A.8: Technical controls | Policy approval by Board<br>CISO ownership<br>Quarterly audits |

### 7.3 Skills Demonstrated

**Security Architecture:**
- Defense-in-depth network design
- Zone-based segmentation
- Zero-trust principles (default-deny)

**Regulatory Compliance:**
- PCI DSS v4.0 cardholder data environment design
- UK GDPR data protection controls
- FCA operational resilience requirements

**Risk Management:**
- STRIDE threat modeling
- Qualitative risk assessment
- Control-to-threat traceability

**Policy Development:**
- Enterprise security policy authoring
- Technical standards documentation
- Operational procedure design

**Cryptography & VPN:**
- IPsec VPN design (IKEv2, AES-256-GCM)
- TLS 1.2/1.3 cipher suite selection
- Certificate-based authentication

**SIEM & Logging:**
- Centralized log aggregation design
- Splunk Enterprise Security implementation
- Forensic evidence retention (WORM storage)

**Change Control:**
- Four-eyes approval workflows
- Evidence-based verification
- Git-based configuration management

---

## Conclusion

This project delivered a comprehensive enterprise security policy framework for a UK financial services organization, addressing regulatory requirements across PCI DSS, UK GDPR, FCA SYSC, and ISO 27001. The three-zone defense-in-depth architecture with default-deny enforcement provides robust protection against ransomware, lateral movement, insider threats, and DDoS attacks.

The framework demonstrates professional-grade security architecture design, combining risk assessment, threat modeling, technical standards, and operational procedures into an implementable governance structure suitable for regulated financial environments.

---

## Appendix: Professional Skills Matrix

| Skill Category | Demonstrated Competency |
|----------------|------------------------|
| **Security Architecture** | Three-zone segmentation, defense-in-depth, fail-secure design |
| **Risk Assessment** | STRIDE threat modeling, CIA classification, likelihood/impact analysis |
| **Regulatory Compliance** | PCI DSS v4.0, UK GDPR, FCA SYSC 8, ISO 27001:2022 |
| **Network Security** | ACL design, firewall rule management, VPN architecture |
| **Cryptography** | TLS 1.2/1.3, IPsec IKEv2, AES-256-GCM, certificate-based auth |
| **Identity & Access** | MFA, TACACS+, RBAC, privilege management, four-eyes control |
| **Security Operations** | SIEM design, incident response, change control, audit procedures |
| **Technical Documentation** | Policy authoring, standards writing, procedure documentation |

---

**Document Type:** Professional Portfolio Case Study  
**Purpose:** Demonstrate enterprise security policy design capabilities  
**Confidentiality Notice:** Client and organizational details anonymized  
**Portfolio Use:** Approved for public demonstration of professional competencies
