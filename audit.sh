#!/bin/bash
# Anonymisation audit for the v2.2 deliverables.
FILES="index.html user-guide.html Veeam_Advisor_v2.2.html CHANGELOG.md test-v2_2.js fixtures.js VeeamAdvisor-MapCapture.ps1 VeeamAdvisor-PowerShell.ps1 VeeamAdvisor-PowerShell-QA.ps1"
# Known non-identifying literals: Veeam built-in GUIDs, documented example / private /
# loopback IPs in the PowerShell help, and a browser UA version string.
BUILTIN="88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec|00000000-0000-0000-0000-000000000000|10\\.0\\.0\\.50|192\\.168\\.1\\.20|127\\.0\\.0\\.1|124\\.0\\.0\\.0|aaaa[0-9a-f]{4}-bbbb-cccc-dddd-eeee[0-9a-f]{4}ffff"
FAIL=0
chk(){ # label, pattern, extra-filter
  local hits
  hits=$(grep -ohEi "$2" $FILES 2>/dev/null | grep -Ev "$BUILTIN" | sort -u)
  if [ -n "$hits" ]; then echo "  FAIL  $1"; echo "$hits" | sed 's/^/          /'; FAIL=1
  else echo "  PASS  $1"; fi
}
echo "Anonymisation audit — v2.2"
chk "no customer hostnames (JBW*)"        "\bJBW[A-Za-z0-9_-]*"
chk "no bracketed machine names"          "MachineName: \[(?!LAB-)[A-Z]"
chk "no GUIDs beyond Veeam built-ins"     "\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
chk "no IPv4 literals"                    "\b(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\b"
chk "no uploads paths"                    "/mnt/user-data"
chk "no customer log filenames"           "VMC[-_.][A-Za-z0-9]*\.(log|txt)|hv-[ab]|vbr-sp"
chk "no vendor-specific drive models"     "HP Ultrium|HPE Ultrium|AUTOLDR"
chk "no personal email addresses"         "[A-Za-z0-9._%+-]+@(?!cheekylittlemoney)[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
# Known customer estate names from validation logs — must not appear even in comments,
# CHANGELOG prose, or test descriptions. Extend this list when new sample logs are used.
chk "no customer estate names"            "RANGITIKEI|Ashburton|Anzco|DigiArc|Starfleet|Tatua|Richo|procare|Enterprise Services|Elive|FNLAKL|FNLCHC|FNLDR|DRGVMBKP|WRHNBAK|VMC_BDC|VMC_PDC|life_style"
echo
[ $FAIL -eq 0 ] && echo "CLEAN — no customer-identifying data in any deliverable" || echo "REVIEW REQUIRED"
exit $FAIL
