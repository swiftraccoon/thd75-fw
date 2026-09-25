# Legal Disclaimer & Interoperability Notice

**This software is provided for amateur radio interoperability and educational research only.**

## Interoperability & Essentiality

The decryption and re-encryption implementations provided in this project are **required for interoperability** with the Kenwood TH-D75 transceiver. Without these technical measures, it is impossible for an owner of the device to:

1. **Analyze and verify** the firmware running on their own equipment (security research).
2. **Maintain and repair** their equipment by modifying or updating firmware outside of official, closed-source tools (right to repair).
3. **Develop independent software** that can interact with the radio's serial update protocol.

These implementations were derived through independent analysis of the publicly
distributed firmware updater, public Kenwood manuals, owner-operated hardware
observations, and openly published related-model reverse engineering. None of
those sources establishes undocumented TH-D75 behavior by itself; the project
records provenance and model-specific gaps where they matter.

## Reverse-Engineering Methodology

The project uses independent interoperability research methods:

- **Source material**: Publicly distributed Kenwood updater binaries and manuals,
  observations of personally controlled TH-D75 hardware, and public TH-D74
  research cited in this repository. Related-model material is reference
  evidence, not asserted as TH-D75 proof.
- **Tooling**: Only commercially licensed or open-source reverse engineering tools (e.g., IDA Pro, Ghidra, standard UNIX utilities). No Kenwood-proprietary tools, undisclosed utilities, or non-public debugging interfaces were used.
- **Non-use of confidential material**: No JVCKENWOOD source code, non-public
  internal documentation, NDA material, leaked material, or other confidential
  information was consulted.
- **No insider involvement**: No contributor to this project has any past or present employment, consulting relationship, contractual obligation, or non-disclosure agreement with JVCKENWOOD Corporation or any of its affiliates that bears on the subject matter of this work.

This methodology comports with the intermediate-copying-for-interoperability fair-use analysis established in *Sega Enterprises Ltd. v. Accolade, Inc.*, 977 F.2d 1510 (9th Cir. 1992), and with prevailing clean-room reverse engineering practice.

## Non-Distribution of Copyrighted Firmware

This repository **does not contain, embed, redistribute, or mirror** any portion of Kenwood firmware, voice data, image data, fonts, DSP code, or other copyrighted material owned by JVCKENWOOD Corporation. The tools provided operate exclusively on firmware updater binaries that the end user has independently obtained from JVCKENWOOD's official public distribution channels and is legally entitled to use on hardware they own. No copyrighted Kenwood output is generated, transmitted, or stored by this project itself.

## Compliance & Rights

Modification of lawfully acquired software for use on hardware owned by the user, and reverse engineering performed for the purpose of achieving interoperability, are protected under:

**United States:**
- **17 U.S.C. §117(a)** — the owner of a copy of a computer program may make or authorize the making of adaptations of that program as an essential step in its utilization in conjunction with a machine.
- **17 U.S.C. §1201(f)** ([DMCA interoperability exception](https://www.law.cornell.edu/uscode/text/17/1201)) — circumvention of technological protection measures is permitted for the sole purpose of enabling interoperability of an independently created computer program with other programs.
- **U.S. Copyright Office, 9th Triennial §1201 Rulemaking (2024)**, codified at 37 C.F.R. §201.40 — renewed and expanded [exemptions](https://www.copyright.gov/1201/) covering (i) good-faith security research on lawfully acquired software-enabled devices and (ii) diagnosis, maintenance, and repair of lawfully acquired consumer devices, including those incorporating computer programs.
- **15 U.S.C. §2302(c)** (Magnuson-Moss Warranty Act) — a warrantor may not condition warranty coverage on the consumer's use of articles or services identified by brand or trade name unless provided without charge or by FTC waiver; consumer warranty rights are preserved when third-party software or repair is used.
- Case law: *Chamberlain Group, Inc. v. Skylink Techs., Inc.*, 381 F.3d 1178 (Fed. Cir. 2004) (a §1201 claim requires a reasonable nexus between the access sought and protected rights under the Copyright Act); *Lexmark Int'l, Inc. v. Static Control Components, Inc.*, 387 F.3d 522 (6th Cir. 2004) (technological measures that lock out competing interoperable products, without protecting copyrighted expression, are not shielded by §1201); *Sega Enterprises Ltd. v. Accolade, Inc.*, 977 F.2d 1510 (9th Cir. 1992) (intermediate copying for the purpose of understanding unprotected functional elements is fair use); *Google LLC v. Oracle America, Inc.*, 593 U.S. 1 (2021) (transformative use of functional software interfaces is fair use).

**European Union:**
- [**Directive 2009/24/EC**](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), **Articles 5(3) and 6** — the lawful acquirer of a program may observe, study, and test its functioning, and may decompile it where necessary to achieve interoperability with an independently created program.
- **Directive (EU) 2024/1799** (Right to Repair Directive, adopted 2024) and **Directive (EU) 2019/771** (Sale of Goods Directive) — consumer right to repair and continued use of lawfully acquired goods.

## User Responsibilities

- **Firmware ownership**: Users must obtain Kenwood firmware through legitimate means (e.g., from JVCKENWOOD's official website) and must possess the legal right to use and modify that firmware on hardware they own.
- **Non-infringement**: This tool is not intended to, and must not be used to, facilitate the unauthorized distribution of copyrighted works or to bypass access controls for the purpose of copyright infringement.
- **Regulatory compliance**: Users are solely responsible for ensuring any firmware modifications comply with applicable amateur radio regulations (e.g., FCC Part 97 in the United States; equivalent national regulations elsewhere). Transmitting outside one's licensed privileges — frequency, mode, bandwidth, or power — remains the user's sole responsibility regardless of what this software makes technically possible.

## Trademark Notice

"Kenwood" and "TH-D75" are trademarks of JVCKENWOOD Corporation. These marks are used here under **nominative fair use** solely to identify the equipment for which this interoperability tool is designed. This project is not affiliated with, endorsed by, or sponsored by JVCKENWOOD Corporation.

## Severability and Warranty

If any provision of this notice is held to be invalid or unenforceable in any jurisdiction, the remaining provisions shall remain in full force and effect, and the invalid provision shall be reformed only to the extent necessary to make it enforceable while preserving its intent.

**No warranty.** This software is provided "as is", without warranty of any kind, express or implied, including without limitation the warranties of merchantability, fitness for a particular purpose, and non-infringement. Reflashing radio firmware carries inherent risk and may render the device permanently inoperable. Use entirely at your own risk.


[Project overview](../README.md) · [GPL-3.0 license](../LICENSE)
