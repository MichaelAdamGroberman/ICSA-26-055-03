> **Customer / journalist / regulator entry point:** [**gardyn-security-incident.info**](https://gardyn-security-incident.info)
>
> | If you are... | Go to |
> |---|---|
> | A Gardyn customer | [What was exposed and what to do](https://gardyn-security-incident.info/for-customers/) |
> | A journalist | [Press kit, on-record contact, source materials](https://gardyn-security-incident.info/for-press/) |
> | Looking for the timeline | [October 14, 2025 first contact through CISA Update A](https://gardyn-security-incident.info/timeline/) |
> | Looking for the public-record discrepancies | [Vendor statements vs. CISA findings](https://gardyn-security-incident.info/discrepancies/) |
> | A researcher | [Per-CVE technical detail](https://gardyn-security-incident.info/for-researchers/) |
>
> This GitHub repository remains the canonical primary-source technical record. The site above is the customer-and-press-facing layer over it.

---

> **CERT/CC VU#653116** | [CISA Advisory ICSA-26-055-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-055-03)

# ICSA-26-055-03 -- Gardyn Home Kit IoT Vulnerabilities (Update A)

**CISA ICS Advisory:** [ICSA-26-055-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-055-03)
**CERT/CC:** VU#653116
**Researcher:** Michael Groberman — Gr0m
**Contact:** [michael@groberman.tech](mailto:michael@groberman.tech) · [LinkedIn](https://www.linkedin.com/in/michael-adam-groberman/)
**Published:** 2026-02-24 | **Updated:** 2026-04-02 (Update A)

> **Update A (2026-04-02):** Added vulnerabilities (CVE-2025-10681, CVE-2026-28766, CVE-2026-25197, CVE-2026-32646, CVE-2026-28767, CVE-2026-32662). Modified mitigations as recommended by Gardyn. Associated affected products with relevant vulnerabilities. Updated product version numbers.

Additional findings beyond this advisory are pending coordinated disclosure.

---

## Key Takeaways

- **10 CVEs** (4 Critical, 4 High, 2 Medium) across firmware, mobile app, and cloud API
- **134,215 user records** — described by CISA as "all user account information" — were accessible without authentication, including names, email addresses, phone numbers, and the `last_four` partial credit card field (CVE-2026-28766)
- The `iothubowner` Azure IoT Hub administrative credential (CVE-2025-1242) combined with command injection in `upgrade()` (CVE-2025-29631) provides unauthenticated remote code execution as root on registered devices
- **138,160+ registered IoT devices** affected across Gardyn Home Kit and Studio product lines
- The IoT Hub administrative credential was present in API responses since at least May 2019 (~6 years prior to disclosure) and was retained across a hub migration
- Administrative API endpoints (`/api/admin/*`) accessible without authentication (CVE-2026-32646, CVE-2026-28767)
- Development endpoints accessible in production without authentication (CVE-2026-32662)
- The vendor stated to CISA that no access logging existed on the affected endpoints during the exposure window
- Vendor remediation: firmware **master.622+**, mobile application **2.11.0+**, cloud API **2.12.2026+**
- CVE-2025-29631 is remediated in firmware **master.622** (the version released after master.619).

---

## Overview

Successful exploitation of these vulnerabilities could allow unauthenticated users to access and control edge devices, access cloud-based devices and user information without authentication, and pivot to other edge devices managed in the Gardyn cloud environment.

## CVEs

| CVE | Severity | CWE | Title |
|-----|----------|-----|-------|
| [CVE-2026-28766](CVE-2026-28766.md) ([Repo](https://github.com/MichaelAdamGroberman/CVE-2026-28766) · [CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-28766)) | 9.3 Critical | CWE-306 | Missing Authentication -- User Account Endpoint |
| [CVE-2025-1242](CVE-2025-1242.md) ([Repo](https://github.com/MichaelAdamGroberman/CVE-2025-1242) · [CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-1242)) | 9.1 Critical | CWE-798 | Use of Hard-coded Credentials |
| [CVE-2025-29631](CVE-2025-29631.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-29631)) | 9.1 Critical | CWE-78 | OS Command Injection |
| [CVE-2026-25197](CVE-2026-25197.md) ([Repo](https://github.com/MichaelAdamGroberman/CVE-2026-25197) · [CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-25197)) | 9.1 Critical | CWE-639 | Authorization Bypass via User-Controlled Key (IDOR) |
| [CVE-2025-10681](CVE-2025-10681.md) ([Repo](https://github.com/MichaelAdamGroberman/CVE-2025-10681) · [CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-10681)) | 8.6 High | CWE-798 | Hardcoded Azure Blob Storage Account Key |
| [CVE-2025-29628](CVE-2025-29628.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-29628)) | 8.3 High | CWE-319 | Cleartext Transmission of Sensitive Information |
| [CVE-2025-29629](CVE-2025-29629.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-29629)) | 8.3 High | CWE-1392 | Use of Default Credentials |
| [CVE-2026-32646](CVE-2026-32646.md) ([Repo](https://github.com/MichaelAdamGroberman/CVE-2026-32646) · [CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-32646)) | 7.5 High | CWE-306 | Missing Authentication -- Admin Device Management |
| [CVE-2026-28767](CVE-2026-28767.md) ([Repo](https://github.com/MichaelAdamGroberman/CVE-2026-28767) · [CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-28767)) | 5.3 Medium | CWE-306 | Missing Authentication -- Admin Notifications |
| [CVE-2026-32662](CVE-2026-32662.md) ([Repo](https://github.com/MichaelAdamGroberman/CVE-2026-32662) · [CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-32662)) | 5.3 Medium | CWE-489 | Active Debug Code in Production |

## Affected Product

**Vendor:** Gardyn
**Product:** Gardyn Home Kit (Models 1.0, 2.0, 3.0, 4.0), Gardyn Studio (Models 1.0, 2.0)
**Sector:** Food and Agriculture
**Registered Devices:** 138,160+

| Component | Vulnerable Versions | Applicable CVEs |
|-----------|-------------------|-----------------|
| Firmware | < master.622 | CVE-2025-1242, CVE-2025-10681, CVE-2025-29628, CVE-2025-29629, CVE-2025-29631 |
| Mobile Application | < 2.11.0 | CVE-2025-1242, CVE-2025-10681, CVE-2025-29628 |
| Cloud API | < 2.12.2026 | CVE-2025-1242, CVE-2025-10681, CVE-2026-28766, CVE-2026-25197, CVE-2026-32646, CVE-2026-28767, CVE-2026-32662 |

## Remediation Status

Per CISA ICSA-26-055-03 (Update A, 2026-04-02), all 10 CVEs in this advisory are remediated. Fix versions per CVE:

| CVE | Fix Version |
|-----|-------------|
| CVE-2025-1242 | Cloud API 2.12.2026, Mobile App 2.11.0, Firmware master.622 |
| CVE-2025-10681 | Cloud API 2.12.2026, Mobile App 2.11.0, Firmware master.622 |
| CVE-2025-29628 | Mobile App 2.11.0, Firmware master.622 |
| CVE-2025-29629 | Firmware master.622 |
| CVE-2025-29631 | Firmware master.622 (released after master.619) |
| CVE-2026-25197 | Cloud API 2.12.2026 |
| CVE-2026-28766 | Cloud API 2.12.2026 |
| CVE-2026-28767 | Cloud API 2.12.2026 |
| CVE-2026-32646 | Cloud API 2.12.2026 |
| CVE-2026-32662 | Cloud API 2.12.2026 |

The vendor stated to CISA that no access logging existed on the affected endpoints during the exposure window.

## Coordinated Disclosure Timeline

This timeline includes only (a) events published by CISA in ICSA-26-055-03, (b) the researcher's own disclosure actions, (c) observable changes in vendor API behavior or credentials, and (d) firmware compile/deployment dates derived from public version strings. Content from the CERT/CC VINCE coordination platform is embargoed and not included.

| Date | Event | Type |
|------|-------|------|
| 2025-10-14 | Initial disclosure to vendor — included the mass PII exposure on `/api/users` (CVE-2026-28766) | Researcher action |
| 2025-12-11 | Disclosure to CERT/CC (58 days after initial vendor disclosure) | Researcher action / observable communication gap |
| 2025-12-18 | `/api/users` endpoint stopped returning data to unauthenticated requests (CVE-2026-28766) | Observable vendor action |
| 2026-01-19 | Firmware master.583 deployed (build date encoded in version string `master.583.20260119`) | Firmware deployment |
| 2026-01-22 | `iothubowner` Azure IoT Hub administrative credential rotated (CVE-2025-1242 — previously distributed key stopped working) | Observable vendor action |
| 2026-02-24 | Vendor's public security page published at https://mygardyn.com/security/ | Vendor public statement |
| 2026-02-24 | **CISA ICSA-26-055-03 published (initial — 4 CVEs)** | CISA |
| 2026-02-24 | Vendor announces firmware master.619 deployment | Vendor public statement |
| 2026-04-02 | **CISA ICSA-26-055-03 Update A (10 CVEs total; CVE-2025-29631 remediated in firmware master.622)** | CISA |

## Attack Chains

**Chain 1 -- Unauthenticated Remote Root (any device)**
CVE-2025-1242 (hardcoded `iothubowner` credential) + CVE-2025-29631 (command injection in `upgrade()`) = unauthenticated remote root on any device in the fleet (~138,160 registered devices).

**Chain 2 -- Mass PII Exposure (all users)**
CVE-2026-28766 (`/api/users` endpoint accessible without authentication) and CVE-2026-25197 (`/api/user/{id}` returns any user's profile data when given sequential integer IDs) together provide PII access for all 134,215 user records, including names, email addresses, phone numbers, and the `last_four` partial payment card field.

## Prior Work

CVE-2025-29628, CVE-2025-29629, and CVE-2025-29631 were originally discovered and disclosed by [mselbrede](https://github.com/mselbrede) in February 2025, with technical details and proof-of-concept published in July 2025. This advisory builds on that prior CVE work.

mselbrede's published research includes vulnerable source code, default credentials, and a proof-of-concept for device takeover via Man-in-the-Middle attack. Technical details for the overlapping CVEs are available in their repository.

- [mselbrede/gardyn](https://github.com/mselbrede/gardyn) (original research)
- [kristof-mattei/gardyn-hack](https://github.com/kristof-mattei/gardyn-hack) (mirror)

## Revision History

| Date | Revision | Changes |
|------|----------|---------|
| 2026-02-24 | Initial Publication | CVE-2025-1242, CVE-2025-29628, CVE-2025-29629, CVE-2025-29631 |
| 2026-04-02 | Update A | Added vulnerabilities (CVE-2025-10681, CVE-2026-28766, CVE-2026-25197, CVE-2026-32646, CVE-2026-28767, CVE-2026-32662). Modified mitigations as recommended by Gardyn. Associated affected products with relevant vulnerabilities. Updated product version numbers. |

## Related Repositories

- [VU653116](https://github.com/MichaelAdamGroberman/VU653116) — CERT/CC vulnerability note repository (parent case record)
- Individual CVE writeups: [CVE-2025-1242](https://github.com/MichaelAdamGroberman/CVE-2025-1242) · [CVE-2025-10681](https://github.com/MichaelAdamGroberman/CVE-2025-10681) · [CVE-2026-25197](https://github.com/MichaelAdamGroberman/CVE-2026-25197) · [CVE-2026-28766](https://github.com/MichaelAdamGroberman/CVE-2026-28766) · [CVE-2026-28767](https://github.com/MichaelAdamGroberman/CVE-2026-28767) · [CVE-2026-32646](https://github.com/MichaelAdamGroberman/CVE-2026-32646) · [CVE-2026-32662](https://github.com/MichaelAdamGroberman/CVE-2026-32662)

## References

- [CISA Advisory ICSA-26-055-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-055-03)
- [CSAF JSON](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-055-03.json)
- CERT/CC VU#653116
- [Gardyn Security Update](https://mygardyn.com/security/)
