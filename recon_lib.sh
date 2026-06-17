#!/usr/bin/env bash
# recon_libs.sh — Découverte de bibliothèques additionnelles dans un firmware
# ESP32/Xtensa strippé, SANS binaire de référence ni matching de signatures.
#
# Usage: ./recon_libs.sh chip_app_RE_stripped.elf
#
# Prérequis: binutils (strings, c++filt), python3 + pyelftools
#   pip install pyelftools --break-system-packages

set -euo pipefail
ELF="${1:?Usage: $0 <fichier.elf>}"
WORK="$(mktemp -d)"

echo "== [1] Lecture du app descriptor ESP-IDF (.flash.appdesc) =="
# Donne version IDF, nom de projet, date de build
python3 - "$ELF" <<'EOF'
import sys
from elftools.elf.elffile import ELFFile
with open(sys.argv[1], 'rb') as f:
    elf = ELFFile(f)
    sec = elf.get_section_by_name('.flash.appdesc')
    if sec:
        print(sec.data())
EOF

echo
echo "== [2] Extraction des noms de sections complets (non tronqués) =="
# readelf -S tronque les noms longs avec [...] -> on passe par pyelftools
python3 - "$ELF" > "$WORK/full_sections.txt" <<'EOF'
import sys
from elftools.elf.elffile import ELFFile
with open(sys.argv[1], 'rb') as f:
    elf = ELFFile(f)
    for sec in elf.iter_sections():
        print(sec.name)
EOF
wc -l "$WORK/full_sections.txt"

echo
echo "== [3] Isolement + démangling des symboles C++ encore présents =="
# strip(1) ne supprime QUE .symtab/.strtab ; les sections par-fonction
# .xt.lit.<nom_mangled> / .xt.prop.<nom_mangled> (COMDAT C++/templates)
# survivent et révèlent classes/fonctions appartenant aux libs.
grep '_Z' "$WORK/full_sections.txt" \
    | sed -E 's/^\.xt\.(lit|prop)\.//' \
    | sort -u > "$WORK/mangled.txt"
c++filt < "$WORK/mangled.txt" | sort -u > "$WORK/demangled.txt"
echo "Symboles C++ récupérés : $(wc -l < "$WORK/demangled.txt")"

echo
echo "== [4] Extraction des chaînes ASCII (>= 8 caractères) =="
strings -n 8 "$ELF" > "$WORK/strings.txt"
wc -l "$WORK/strings.txt"

echo
echo "== [5] Recherche de chemins source (révèlent le composant/lib d'origine) =="
grep -aE '/(IDF|components)/[A-Za-z0-9_./-]+\.(c|cpp|h)' "$WORK/strings.txt" | sort -u

echo
echo "== [6] Tableau récapitulatif : bibliothèque -> preuve -> fonctions associées =="
# Croise full_sections/demangled (symboles C++ qui ont survécu) et strings.txt
# (chemins source + noms de fonctions C littéraux dans les logs ESP_LOG) pour
# construire, par bibliothèque candidate, la liste des fonctions retrouvées.
python3 - "$WORK/demangled.txt" "$WORK/strings.txt" <<'EOF'
import sys, re

demangled_path, strings_path = sys.argv[1], sys.argv[2]
demangled = open(demangled_path, encoding="utf-8", errors="ignore").read().splitlines()
strings_  = open(strings_path,  encoding="utf-8", errors="ignore").read().splitlines()

# Chaque entrée: (Nom affiché, source, regex, evidence_regex_optionnelle)
#   source = "demangled"  -> on filtre demangled.txt (classes C++)
#   source = "strings"    -> on filtre strings.txt (noms de fonctions C littéraux,
#                             souvent injectés via __func__ dans les ESP_LOGx)
LIBS = [
    ("esp32-camera (driver caméra)", "strings",
     r'^(esp_camera_\w+|camera_\w+|ll_cam_\w+|set_framesize|the_camera_loop\w*)$',
     r'esp32-camera'),
    ("WebServer / RequestHandler (Arduino-ESP32)", "demangled",
     r'^(WebServer|RequestHandler|FunctionRequestHandler|StaticRequestHandler|Uri|HTTPUpload)::',
     None),
    ("ESPxWebFlMgr (code métier custom)", "demangled",
     r'ESPxWebFlMgr', None),
    ("FS / VFS (Arduino FS + ESP-IDF vfs)", "demangled",
     r'^(fs::File|VFSImpl|VFSFileImpl)', None),
    ("SD_MMC / FATFS / sdmmc (ESP-IDF)", "strings",
     r'^(sdmmc_\w+|ff_sdmmc_\w+|diskio_sdmmc\w*)$',
     r'/(sdmmc|fatfs)/'),
    ("ESPmDNS", "demangled",
     r'^MDNSResponder::', None),
    ("SNTP (lwIP)", "strings",
     r'^sntp_\w+$', r'sntp\.c'),
    ("WiFi (Arduino + esp_wifi/esp_netif)", "demangled",
     r'^(WiFiClient|WiFiServer|WiFiClientRxBuffer|WiFiEventCbList|WiFiClientSocketHandle|IPAddress)',
     None),
    ("NVS (nvs_flash / Preferences)", "demangled",
     r'^(nvs::|intrusive_list<nvs)', None),
    ("esp_http_server (httpd) + WebSocket", "strings",
     r'^httpd_\w+$', r'Sec-WebSocket|101 Switching Protocols'),
    ("app_update / esp_ota_ops", "strings",
     r'^esp_ota_\w+$', r'esp_ota_ops\.c'),
    ("mbedtls", "strings",
     r'^mbedtls_\w+$', r'mbedtls'),
]

rows = []
for name, source, func_re, evidence_re in LIBS:
    pool = demangled if source == "demangled" else strings_
    pat = re.compile(func_re)
    funcs = sorted({s.strip() for s in pool if pat.search(s.strip())})
    if not funcs and evidence_re is None:
        continue
    evidence = ""
    if evidence_re:
        m = next((s for s in strings_ if re.search(evidence_re, s)), None)
        evidence = m if m else ""
    if not funcs and not evidence:
        continue
    shown = funcs[:6]
    more = f" (+{len(funcs)-6} autres)" if len(funcs) > 6 else ""
    rows.append((name, evidence[:55], ", ".join(shown) + more if shown else "(voir preuve)"))

# affichage tableau
w1 = max(len(r[0]) for r in rows) + 2
w2 = max(len(r[1]) for r in rows) + 2
print(f"{'Bibliothèque'.ljust(w1)}{'Preuve (chemin/string)'.ljust(w2)}Fonctions associées")
print("-" * (w1 + w2 + 60))
for name, evidence, funcs in rows:
    print(f"{name.ljust(w1)}{evidence.ljust(w2)}{funcs}")
EOF

echo
echo "Terminé. Fichiers intermédiaires dans: $WORK"
