# Third-Party Software Notices and License Attribution — ITSA Network OS
> **Document ID:** DOC-TPN-001  > **Task:** TASK-018 (Compliance Audit & Attribution)  > **Audit Date:** 2026-10-29T17:42:00Z  > **Baseline Commit:** `1fcf56804af4a20b97167d81fe1f7c09d4b8c53e`  > **Project:** ITSA Network OS v0.1.0  
---
## 1. Overview and Legal Disclaimer
This document contains third-party software notices, copyright attributions, and license terms applicable to dependencies and bundled components utilized by or declared for **ITSA Network OS**.
> [!IMPORTANT]
> **Technical Compliance Notice:** This document represents an evidence-based technical inventory compiled during TASK-018. It does NOT constitute a formal legal opinion, warranty of merchantability, or official certification that the software is legally cleared for unrestricted commercial redistribution. Unresolved licensing matters (such as NPSL terms for Nmap or proprietary firmware redistribution) must be reviewed by qualified legal counsel prior to commercial release.

### 1.1 Separation of Verified Capabilities from Planned Editions
In strict compliance with project governance and truth-in-advertising guidelines, the platform clearly delineates implemented features from planned commercial offerings:
- **Community Edition (Current Verified Implementation)**: Open source core under the permissive MIT License. Full CLI diagnostic toolchain (CIDR subnet, DNS, latency, route parser, bandwidth monitor, Dijkstra SPF simulator, local port auditor, client TLS inspector, educational packet dissection lab), 14-view PySide6 desktop GUI shell, passive MNDP and ONVIF broadcast listeners governed by fail-closed `ScopeGuard`, SQLite persistence engine, unified `AssetGraph` and `AssetDetailInspector` with 5 facet tabs, asynchronous GUI worker execution, and truthful runtime health indicators.
- **Professional Edition (Planned / Not Implemented)**: Commercial add-on features including automated white-label PDF/HTML reporting, persistent multi-session topology differential tracking, and live 802.11 RF waterfall canvas visualizer.
- **Enterprise Edition (Planned / Not Implemented)**: Certified multi-vendor hardware integration packs (Cisco, Juniper, Aruba, Fortinet), automated CIS/NIST compliance reporting, centralized fleet synchronization, and dedicated hardware appliances.

---
## 2. Primary Project License
The core application source code of **ITSA Network OS** is licensed under the permissive MIT License:

```
MIT License

Copyright (c) 2026 ITSA Network OS Maintainers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---
## 3. Python Runtime & GUI Framework Dependencies

### 3.1 PySide6 & Qt 6 Framework
- **Components:** `PySide6` (6.12.0), `PySide6_Essentials` (6.12.0), `PySide6_Addons` (6.12.0), `PySide6_WebEngine` (6.12.0.140), `PySide6_Pdf` (6.12.0.140), `shiboken6` (6.12.0)
- **Declared License:** `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`
- **Copyright:** The Qt Company Ltd. and Qt for Python Team (`pyside@qt-project.org`)
- **Homepage:** [https://pyside.org](https://pyside.org) | Upstream Repository: [https://code.qt.io/cgit/pyside/pyside-setup.git/](https://code.qt.io/cgit/pyside/pyside-setup.git/)
- **Compliance & Dynamic Linking Architecture:**
  1. **Dynamic Linking Invariant:** ITSA Network OS utilizes PySide6 exclusively via dynamic Python runtime imports (`import PySide6.QtWidgets`, `import PySide6.QtCore`, etc.). No Qt C++ source code or C++ binaries are statically linked into proprietary or application binaries.
  2. **Relinking / Replacement:** Users and developers have the technical freedom to replace the provided PySide6 shared library wheels (`.so` shared objects in `.venv/lib/python3.13/site-packages/PySide6/`) with alternative, custom, or modified builds of PySide6/Qt6.
  3. **Reverse Engineering:** In compliance with LGPLv3 section 3 and section 4, reverse engineering of application components is permitted solely to debug modifications to dynamically linked LGPL components.
  4. **Source Code Availability:** Upstream source code for Qt 6 and PySide6 is publicly hosted and available from The Qt Company at `https://code.qt.io/cgit/pyside/pyside-setup.git/`.

### 3.2 Python Development and Testing Dependencies
*(Note: The following packages are strictly development/testing dependencies installed in the virtual environment. They are NOT required for the application runtime and will NOT be shipped in the production runtime ISO).* 

| Package Name | Version | License | Copyright / Authors | Homepage |
|---|---|---|---|---|
| **pytest** | `9.1.1` | MIT | Brianna Laugher, Bruno Oliveira, Floris Bruynooghe, Freya Bruhin, Holger Krekel, Ronny Pfannschmidt | [https://docs.pytest.org](https://docs.pytest.org) |
| **pytest-cov** | `7.1.0` | MIT | Marc Schlaich <marc.schlaich@gmail.com> | [https://github.com/pytest-dev/pytest-cov](https://github.com/pytest-dev/pytest-cov) |
| **coverage** | `7.16.2` | Apache-2.0 | Ned Batchelder and 263 contributors | [https://github.com/coveragepy/coveragepy](https://github.com/coveragepy/coveragepy) |
| **iniconfig** | `2.3.1` | MIT | Ronny Pfannschmidt, Holger Krekel | [https://github.com/pytest-dev/iniconfig](https://github.com/pytest-dev/iniconfig) |
| **packaging** | `26.3` | Apache-2.0 OR BSD-2-Clause | Donald Stufft <donald@stufft.io> | [https://packaging.pypa.io](https://packaging.pypa.io) |
| **pluggy** | `1.7.0` | MIT | Holger Krekel | [https://github.com/pytest-dev/pluggy](https://github.com/pytest-dev/pluggy) |
| **Pygments** | `2.21.0` | BSD-2-Clause | Georg Brandl <georg@python.org> | [https://pygments.org](https://pygments.org) |
| **pip** | `26.2.1` | MIT | The pip developers <distutils-sig@python.org> | [https://pip.pypa.io](https://pip.pypa.io) |

---
## 4. Debian 13 Host System Packages (Verified Locally)

The following system packages are installed on the local Debian 13 host environment and verified via `/usr/share/doc/<pkg>/copyright`:

| Package Name | License | Functional Role in ITSA | Local Evidence Source |
|---|---|---|---|
| **iproute2** | `GPL-2.0-only` | Linux network stack utilities (ip addr, ip route) | `/usr/share/doc/iproute2/copyright` |
| **iputils-ping** | `GPL-2.0-or-later AND BSD-3-Clause` | ICMP ping utilities | `/usr/share/doc/iputils-ping/copyright` |
| **traceroute** | `GPL-2.0-or-later AND LGPL-2.1-or-later` | Route tracing utility | `/usr/share/doc/traceroute/copyright` |
| **curl** | `curl AND ISC` | Command-line HTTP/REST client tool | `/usr/share/doc/curl/copyright` |
| **iptables** | `GPL-2.0-only` | IPv4/IPv6 packet filtering administration | `/usr/share/doc/iptables/copyright` |
| **nftables** | `GPL-2.0-only` | Kernel packet classification framework | `/usr/share/doc/nftables/copyright` |
| **ca-certificates** | `MPL-2.0 AND GPL-2.0-or-later` | Common CA certificates for TLS verification | `/usr/share/doc/ca-certificates/copyright` |
| **python3** | `PSF-2.0` | System Python 3.13 interpreter | `/usr/share/doc/python3/copyright` |
| **systemd** | `LGPL-2.1-or-later AND GPL-2.0-only` | System and service manager / journald | `/usr/share/doc/systemd/copyright` |

### 4.1 Upstream Source Code for Debian Packages
In accordance with the GNU General Public License (GPLv2, GPLv3) and GNU Lesser General Public License (LGPLv2.1, LGPLv3), complete corresponding machine-readable source code for all redistributed Debian binary packages is made available via official Debian source mirrors. Source packages can be downloaded on any Debian system using:
```bash
apt-get update && apt-get source <package-name>
```
Alternatively, source code tarballs and Debian patchsets are permanently archived at: [https://sources.debian.org/](https://sources.debian.org/)

---
## 5. Debian Live ISO Manifest Packages (Declared Candidate Inventory)

The following packages are declared in [`debian-live/config/package-lists/itsa.list.chroot`](file:///home/emorphi/Desktop/netF/itsa-network-os/debian-live/config/package-lists/itsa.list.chroot) for inclusion in future live ISO distribution media. Because no Live ISO has been built during this phase, these represent a **proposed distribution manifest** rather than verified shipped binaries:

| Package Name | Declared Role | Documented License | Status & Limitations |
|---|---|---|---|
| **live-boot** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **live-config** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **live-config-systemd** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **user-setup** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **sudo** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **systemd-sysv** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **dbus** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **locales** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **xorg** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **xfce4** | Lightweight desktop environment for Live ISO | `GPL-2.0-or-later` | UNVERIFIED_CHROOT_DECLARATION *(Issue None)* |
| **xfce4-terminal** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **lightdm** | Display manager / desktop login greeter | `GPL-3.0-or-later AND LGPL-2.0-or-later` | UNVERIFIED_CHROOT_DECLARATION *(Issue None)* |
| **python3-pip** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **python3-venv** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **python3-setuptools** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **python3-wheel** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **libgl1** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **libegl1** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **libxkbcommon0** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **libfontconfig1** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **libdbus-1-3** | Debian Live ISO system package | `NOASSERTION` | UNVERIFIED_CHROOT_DECLARATION |
| **dnsutils** | DNS lookup utilities (dig, nslookup) | `MPL-2.0` | UNVERIFIED_CHROOT_DECLARATION *(Issue None)* |
| **ethtool** | Network interface hardware & driver query utility | `GPL-2.0-only` | UNVERIFIED_CHROOT_DECLARATION *(Issue None)* |
| **tcpdump** | Command-line packet capture utility | `BSD-3-Clause` | UNVERIFIED_CHROOT_DECLARATION *(Issue None)* |
| **net-tools** | Legacy networking utilities (arp, route, netstat) | `GPL-2.0-only` | UNVERIFIED_CHROOT_DECLARATION *(Issue None)* |
| **sqlite3** | SQLite command-line interface tool | `Blessing / Public Domain` | UNVERIFIED_CHROOT_DECLARATION *(Issue None)* |
| **nmap** | Network exploration tool & security scanner (Live ISO desktop utility) | `NPSL (Nmap Public Source License)` | UNVERIFIED_CHROOT_DECLARATION *(Issue LIC-001)* |
| **tshark** | Terminal network traffic analyzer / Wireshark dissector | `GPL-2.0-or-later` | UNVERIFIED_CHROOT_DECLARATION *(Issue None (External binary execution only))* |

---
## 6. Register of Unresolved Licensing Questions for Legal Review

### LIC-001: Nmap Public Source License (NPSL) Commercial Redistribution Analysis
- **Target Component:** `nmap`
- **Declared License:** `NPSL`
- **Context & Risk Analysis:** nmap is listed in debian-live/config/package-lists/itsa.list.chroot for live ISO distribution. The core application (src/itsa_network_os/) does not invoke, link, or depend on nmap. However, bundling nmap on a commercial Live ISO alongside proprietary add-ons requires legal review to ensure it constitutes mere aggregation rather than a derivative product under NPSL terms.
- **Required Action:** Submit for qualified intellectual property counsel review before compiling commercial installation ISOs.

### LIC-002: Debian Non-Free Firmware Redistribution Verification
- **Target Component:** `non-free-firmware`
- **Declared License:** `Proprietary / Vendor EULA`
- **Context & Risk Analysis:** Debian 13 Live ISO configurations include non-free-firmware for physical hardware Wi-Fi/NIC driver support. Certain vendor firmware blobs grant redistribution only under strict binary-unmodified conditions.
- **Required Action:** Verify explicit redistribution grants for all included firmware packages during ISO build verification (TASK-017).

---
## 7. Complete License Texts of Included Permissive & Copyleft Software

### 7.Pygments — Pygments v2.21.0 (BSD-2-Clause)
Source file: `pygments-2.21.0.dist-info/licenses/AUTHORS` (SHA-256: `71a83872ad82f57b...`)

```
Pygments is written and maintained by Georg Brandl <georg@python.org>.

Major developers are Tim Hatch <tim@timhatch.com> and Armin Ronacher
<armin.ronacher@active-4.com>.

Other contributors, listed alphabetically, are:

* Sam Aaron -- Ioke lexer
* Jean Abou Samra -- LilyPond lexer
* João Abecasis -- JSLT lexer
* Ali Afshar -- image formatter
* Thomas Aglassinger -- Easytrieve, JCL, Rexx, Transact-SQL and VBScript
  lexers
* Maxence Ahlouche -- PostgreSQL Explain lexer
* Muthiah Annamalai -- Ezhil lexer
* Nikolay Antipov -- OpenSCAD lexer
* Kumar Appaiah -- Debian control lexer
* Andreas Amann -- AppleScript lexer
* Timothy Armstrong -- Dart lexer fixes
* Jeffrey Arnold -- R/S, Rd, BUGS, Jags, and Stan lexers
* Eiríkr Åsheim -- Uxntal lexer
* Jeremy Ashkenas -- CoffeeScript lexer
* José Joaquín Atria -- Praat lexer
* Stefan Matthias Aust -- Smalltalk lexer
* Lucas Bajolet -- Nit lexer
* Ben Bangert -- Mako lexers
* Max Battcher -- Darcs patch lexer
* Thomas Baruchel -- APL lexer
* Tim Baumann -- (Literate) Agda lexer
* Paul Baumgart, 280 North, Inc. -- Objective-J lexer
* Michael Bayer -- Myghty lexers
* Thomas Beale -- Archetype lexers
* John Benediktsson -- Factor lexer
* David Benjamin, Google LLC -- TLS lexer
* Trevor Bergeron -- mIRC formatter
* Vincent Bernat -- LessCSS lexer
* Christopher Bertels -- Fancy lexer
* Sébastien Bigaret -- QVT Operational lexer
* Jarrett Billingsley -- MiniD lexer
* Adam Blinkinsop -- Haskell, Redcode lexers
* Stéphane Blondon -- Procfile, SGF and Sieve lexers
* Frits van Bommel -- assembler lexers
* Pierre Bourdon -- bugfixes
* Martijn Braam -- Kernel log lexer, BARE lexer
* JD Browne, Google LLC -- GoogleSQL lexer
* Matthias Bussonnier -- ANSI style handling for terminal-256 formatter
* chebee7i -- Python traceback lexer improvements
* Hiram Chirino -- Scaml and Jade lexers
* Mauricio Caceres -- SAS and Stata lexers.
* Michael Camilleri, John Gabriele, sogaiu -- Janet lexer
* Daren Chandisingh -- Gleam lexer
* Ian Cooper -- VGL lexer
* David Corbett -- Inform, Jasmin, JSGF, Snowball, and TADS 3 lexers
* Leaf Corcoran -- MoonScript lexer
* Fraser Cormack -- TableGen lexer
* Gabriel Corona -- ASN.1 lexer
* Radu Costache -- Boogie and Civl Verifier lexer improvements
* Christopher Creutzig -- MuPAD lexer
* Daniël W. Crompton -- Pike lexer
* Pete Curry -- bugfixes
* Bryan Davis -- EBNF lexer
* Bruno Deferrari -- Shen lexer
* Walter Dörwald -- UL4 lexer
* Luke Drummond -- Meson lexer
* Giedrius Dubinskas -- HTML formatter improvements
* Owen Durni -- Haxe lexer
* Alexander Dutton, Oxford University Computing Services -- SPARQL lexer
* James Edwards -- Terraform lexer
* Nick Efford -- Python 3 lexer
* Sven Efftinge -- Xtend lexer
* Artem Egorkine -- terminal256 formatter
* Matthew Fernandez -- CAmkES lexer
* Paweł Fertyk -- GDScript lexer, HTML formatter improvements
* Michael Ficarra -- CPSA lexer
* James H. Fisher -- PostScript lexer
* Amanda Fitch, Google LLC -- GoogleSQL lexer
* William S. Fulton -- SWIG lexer
* Carlos Galdino -- Elixir and Elixir Console lexers
* Michael Galloy -- IDL lexer
* Naveen Garg -- Autohotkey lexer

[... Remaining license text preserved in package dist-info ...]
```

### 7.coverage — coverage v7.16.2 (Apache-2.0)
Source file: `coverage-7.16.2.dist-info/licenses/LICENSE.txt` (SHA-256: `0d542e0c8804e39a...`)

```
Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)

[... Remaining license text preserved in package dist-info ...]
```

### 7.iniconfig — iniconfig v2.3.1 (MIT)
Source file: `iniconfig-2.3.1.dist-info/licenses/LICENSE` (SHA-256: `3409fa91f7ace557...`)

```
The MIT License (MIT)

Copyright (c) 2010 - 2023 Holger Krekel and others

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 7.packaging — packaging v26.3 (Apache-2.0 OR BSD-2-Clause)
Source file: `packaging-26.3.dist-info/licenses/LICENSE` (SHA-256: `cad1ef5bd340d73e...`)

```
This software is made available under the terms of *either* of the licenses
found in LICENSE.APACHE or LICENSE.BSD. Contributions to this software is made
under the terms of *both* these licenses.
```

### 7.pip — pip v26.2.1 (MIT)
Source file: `pip-26.2.1.dist-info/licenses/AUTHORS.txt` (SHA-256: `4eb1fb1705e2def8...`)

```
@Switch01
A_Rog
Aakanksha Agrawal
Aarni Koskela
abdul rawoof
Abdul Rawoof Khan
Abhinav Sagar
ABHYUDAY PRATAP SINGH
abs51295
AceGentile
Adam Chainz
Adam Tse
Adam Turner
Adam Wentz
admin
Adolfo Ochagavía
Adrien Morison
Agus
ahayrapetyan
Ahilya
AinsworthK
Akash Srivastava
Alan Yee
Albert Tugushev
Albert-Guan
albertg
Alberto Sottile
Aleks Bunin
Ales Erjavec
Alessandro Molina
Alethea Flowers
Alex Gaynor
Alex Grönholm
Alex Hedges
Alex Loosley
Alex Morega
Alex Stachowiak
Alexander Regueiro
Alexander Shtyrov
Alexandre Conrad
Alexey Popravka
Aleš Erjavec
Alli
Aman
Ami Fischman
Ananya Maiti
Anatoly Techtonik
Anders Kaseorg
Andre Aguiar
Andrea Corna
Andreas Lutro
Andrei Geacar
Andrew Gaul
Andrew Shymanel
Andrey Bienkowski
Andrey Bulgakov
Andrés Delfino
Andy Freeland
Andy Kluger
Ani Hayrapetyan
Aniruddha Basak
Anish Tambe
Anrs Hu
Anthony Sottile
Antoine Lambert
Antoine Musso
Anton Ovchinnikov
Anton Patrushev
Anton Zelenov
Antonio Alvarado Hernandez
Antony Lee
Antti Kaihola
Anubhav Patel
Anudit Nagar
Anuj Godase
AQNOUCH Mohammed
AraHaan
Aren Siekmeier
arena
arenasys

[... Remaining license text preserved in package dist-info ...]
```

### 7.pluggy — pluggy v1.7.0 (MIT)
Source file: `pluggy-1.7.0.dist-info/licenses/LICENSE` (SHA-256: `d6b65e6c213a5d0b...`)

```
The MIT License (MIT)

Copyright (c) 2015 holger krekel (rather uses bitbucket/hpk42)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 7.pytest — pytest v9.1.1 (MIT)
Source file: `pytest-9.1.1.dist-info/licenses/LICENSE` (SHA-256: `ca836a5f9ecca3b2...`)

```
The MIT License (MIT)

Copyright (c) 2004 Holger Krekel and others

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 7.pytest-cov — pytest-cov v7.1.0 (MIT)
Source file: `pytest_cov-7.1.0.dist-info/licenses/AUTHORS.rst` (SHA-256: `d7390c793c73c362...`)

```
Authors
=======

* Marc Schlaich - https://github.com/schlamar (\http://www.schlamar.org)
* Rick van Hattem - http://wol.ph
* Buck Evan - https://github.com/bukzor
* Eric Larson - http://larsoner.com
* Marc Abramowitz - \http://marc-abramowitz.com
* Thomas Kluyver - https://github.com/takluyver
* Guillaume Ayoub - http://www.yabz.fr
* Federico Ceratto - \http://firelet.net
* Josh Kalderimis - \http://blog.cookiestack.com
* Ionel Cristian Mărieș - https://blog.ionelmc.ro
* Christian Ledermann - https://github.com/cleder
* Alec Nikolas Reiter - https://github.com/justanr
* Patrick Lannigan - https://github.com/plannigan
* David Szotten - https://github.com/davidszotten
* Michael Elovskikh - https://github.com/wronglink
* Saurabh Kumar - https://github.com/theskumar
* Michael Elovskikh - https://github.com/wronglink
* Daniel Hahler - https://github.com/blueyed (\https://daniel.hahler.de)
* Florian Bruhin - http://www.the-compiler.org
* Zoltan Kozma - https://github.com/kozmaz87
* Francis Niu - https://flniu.github.io
* Jannis Leidel - https://github.com/jezdez
* Ryan Hiebert - http://ryanhiebert.com/
* Terence Honles - https://github.com/terencehonles
* Jeremy Bowman - https://github.com/jmbowman
* Samuel Giffard - https://github.com/Mulugruntz
* Семён Марьясин - https://github.com/MarSoft
* Alexander Shadchin - https://github.com/shadchin
* Thomas Grainger - https://graingert.co.uk
* Juanjo Bazán - https://github.com/xuanxu
* Andrew Murray - https://github.com/radarhere
* Ned Batchelder - https://nedbatchelder.com/
* Albert Tugushev - https://github.com/atugushev
* Martín Gaitán - https://github.com/mgaitan
* Hugo van Kemenade - https://github.com/hugovk
* Michael Manganiello - https://github.com/adamantike
* Anders Hovmöller - https://github.com/boxed
* Zac Hatfield-Dodds - https://zhd.dev
* Mateus Berardo de Souza Terra - https://github.com/MatTerra
* Ganden Schaffner - https://github.com/gschaffner
* Michał Górny - https://github.com/mgorny
* Bernát Gábor - https://github.com/gaborbernat
* Pamela McA'Nulty - https://github.com/PamelaM
* Christian Riedel - https://github.com/Cielquan
* Chris Sreesangkom - https://github.com/csreesan
* Sorin Sbarnea - https://github.com/ssbarnea
* Brian Rutledge - https://github.com/bhrutledge
* Danilo Šegan - https://github.com/dsegan
* Michał Bielawski - https://github.com/D3X
* Zac Hatfield-Dodds - https://github.com/Zac-HD
* Ben Greiner - https://github.com/bnavigator
* Delgan - https://github.com/Delgan
* Andre Brisco - https://github.com/abrisco
* Colin O'Dell - https://github.com/colinodell
* Ronny Pfannschmidt - https://github.com/RonnyPfannschmidt
* Christian Fetzer - https://github.com/fetzerch
* Jonathan Stewmon - https://github.com/jstewmon
* Matthew Gamble - https://github.com/mwgamble
* Christian Clauss - https://github.com/cclauss
* Dawn James - https://github.com/dawngerpony
* Tsvika Shapira - https://github.com/tsvikas
* Marcos Boger - https://github.com/marcosboger
* Ofek Lev - https://github.com/ofek
* Art Pelling - https://github.com/artpelling
* Markéta Machová - https://github.com/MeggyCal
```

