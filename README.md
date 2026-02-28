> **Full disclosure: [CERT/CC VU#653116](https://github.com/MichaelAdamGroberman/VU653116)** -- 29 vulnerabilities, 4 attack chains, complete coordination timeline

# ICSA-26-055-03 -- Gardyn Home Kit IoT Vulnerabilities

**CISA ICS Advisory:** [ICSA-26-055-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-055-03)
**CERT/CC:** [VU#653116](https://www.kb.cert.org/vuls/id/653116) | [VINCE Case](https://kb.cert.org/vince/case/653116/)
**Researcher:** Gr0m
**Published:** 2026-02-24

This is an initial advisory. Additional findings are pending coordinated disclosure.

## Overview

Successful exploitation of these vulnerabilities could allow unauthenticated users to access and control edge devices, access cloud-based devices and user information without authentication, and pivot to other edge devices managed in the Gardyn cloud environment.

## CVEs

| CVE | Severity | CWE | Title |
|-----|----------|-----|-------|
| [CVE-2025-1242](CVE-2025-1242.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-1242)) | 9.1 Critical | CWE-798 | Use of Hard-coded Credentials |
| [CVE-2025-10681](CVE-2025-10681.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-10681)) | 8.6 High | CWE-798 | Hardcoded Azure Blob Storage Account Key |
| [CVE-2025-29628](CVE-2025-29628.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-29628)) | 8.3 High | CWE-319 | Cleartext Transmission of Sensitive Information |
| [CVE-2025-29629](CVE-2025-29629.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-29629)) | 8.3 High | CWE-1392 | Use of Default Credentials |
| [CVE-2025-29631](CVE-2025-29631.md) ([CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-29631)) | 9.1 Critical | CWE-78 | OS Command Injection |

### Related CVE (not in this advisory)

| CVE | CWE | Title | Researcher |
|-----|-----|-------|------------|
| [CVE-2025-29630](https://www.cve.org/CVERecord?id=CVE-2025-29630) | CWE-798 | SSH Key Backdoor | [mselbrede](https://github.com/kristof-mattei/gardyn-hack/blob/master/CVE-2025-29630.md) |

## Affected Product

**Vendor:** Gardyn
**Product:** Gardyn Home Kit (Models 1.0, 2.0, 3.0), Gardyn Studio (Models 1.0, 2.0)
**Sector:** Food and Agriculture
**Registered Devices:** 138,160+

| Component | Vulnerable Versions |
|-----------|-------------------|
| Firmware | < master.619 |
| Mobile Application | < 2.11.0 |
| Cloud API | < 2.12.2026 |

## Prior Work

CVE-2025-29628, CVE-2025-29629, CVE-2025-29630, and CVE-2025-29631 were originally discovered and disclosed by [mselbrede](https://github.com/mselbrede) in February 2025, with technical details and proof-of-concept published in July 2025. This advisory builds on that prior CVE work.

mselbrede's published research includes vulnerable source code, default credentials, and a proof-of-concept for device takeover via Man-in-the-Middle attack. Technical details for the overlapping CVEs are available in their repository.

- [mselbrede's original research (mirror)](https://github.com/kristof-mattei/gardyn-hack)

## References

- [CISA Advisory ICSA-26-055-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-055-03)
- [CSAF JSON](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-055-03.json)
- [CERT/CC VU#653116](https://www.kb.cert.org/vuls/id/653116)
- [VINCE Case VU#653116](https://kb.cert.org/vince/case/653116/)
- [Gardyn Security Update](https://mygardyn.com/security/)
- [Full Disclosure -- VU#653116 (29 findings)](https://github.com/MichaelAdamGroberman/VU653116)
