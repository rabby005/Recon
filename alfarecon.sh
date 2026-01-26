#!/bin/bash

# ==================================================

# AlfaRecon v2.0 — Full Deep Recon + Profiling

# Usage:

# ./alfarecon.sh check

# ./alfarecon.sh recon [example.com](http://example.com/)

# ==================================================

show_help() {
echo "Usage:"
echo "  ./alfarecon.sh check"
echo "  ./alfarecon.sh recon [example.com](http://example.com/)"
exit 1
}

# ------------------------

# CHECK MODE

# ------------------------

check_tools() {

tools=(
subfinder amass chaos assetfinder shuffledns puredns massdns fierce dnsrecon
dnsgen altdns gotator dnsx httpx gau waybackurls katana subjs nmap
cloud_enum trufflehog metabigor whatweb unfurl
)

echo "====== AlfaRecon Tool Check ======"

for t in "${tools[@]}"; do
if command -v $t >/dev/null 2>&1; then
echo "[✔] $t installed"
else
echo "[✘] $t missing"
fi
done

echo ""
echo "[!] Web/API based (manual/API needed):"
echo "[crt.sh](http://crt.sh/), github dorks, securitytrails, virustotal, shodan, s3scanner, gcpbucketbrute, lazys3, bgpview, linkfinder, regulator"
exit 0
}

# ------------------------

# RECON MODE

# ------------------------

run_recon() {

domain=$1
base="$HOME/alfarecon/$domain"
mkdir -p "$base"/{layer1,layer2,layer3,layer4,layer5,layer6}
cd "$base" || exit

echo "🔥 AlfaRecon v2 started on: $domain"

# =========================

# 🥇 Layer 1 — Passive

# =========================

echo "[L1] Passive recon..."

subfinder -d $domain -all -silent > layer1/subfinder.txt
amass enum -passive -d $domain -silent > layer1/amass_passive.txt
chaos -d $domain -silent > layer1/chaos.txt
assetfinder --subs-only $domain > layer1/assetfinder.txt

cat layer1/*.txt | sort -u > layer1/all_passive.txt

# =========================

# 🥈 Layer 2 — Active + Brute

# =========================

echo "[L2] Active + brute..."

amass enum -active -d $domain -silent > layer2/amass_active.txt
amass brute -d $domain -silent > layer2/amass_brute.txt
dnsrecon -d $domain -t brt | awk '{print $1}' > layer2/dnsrecon.txt
fierce --domain $domain | grep Found | awk '{print $2}' > layer2/fierce.txt

cat layer1/all_passive.txt layer2/*.txt | sort -u > layer2/all_active.txt

# =========================

# 🥉 Layer 3 — Permutation

# =========================

echo "[L3] Permutation..."

dnsgen layer2/all_active.txt > layer3/dnsgen.txt
altdns -i layer2/all_active.txt -o layer3/altdns.txt -w /usr/share/wordlists/dns.txt 2>/dev/null
gotator -sub layer2/all_active.txt -depth 1 > layer3/gotator.txt 2>/dev/null

cat layer3/*.txt | sort -u > layer3/all_permuted.txt

# =========================

# 🏅 Layer 4 — DNS resolve

# =========================

echo "[L4] DNS resolving..."

cat layer2/all_active.txt layer3/all_permuted.txt | sort -u > layer4/candidates.txt

puredns resolve layer4/candidates.txt -d $domain -q > layer4/puredns.txt
shuffledns -d $domain -list layer4/candidates.txt -silent > layer4/shuffledns.txt
dnsx -l layer4/candidates.txt -silent > layer4/dnsx.txt

cat layer4/*.txt | sort -u > layer4/resolved.txt

# =========================

# 🏆 Layer 5 — Deep Recon

# =========================

echo "[L5] Deep asset recon..."

gau $domain > layer5/gau.txt
waybackurls $domain > layer5/wayback.txt

cat layer5/gau.txt layer5/wayback.txt | grep ".js" | httpx -silent | subjs > layer5/subjs.txt

katana -u [https://$domain](https://$domain/) -silent > layer5/katana.txt
amass intel -d $domain -silent > layer5/amass_intel.txt
metabigor net --org $domain > layer5/metabigor.txt
nmap -sn $domain --script dns-brute > layer5/nmap_dns.txt

cat layer5/*.txt | sort -u > layer5/all_deep.txt

# =========================

# 🏆 Layer 6 — Profiling

# =========================

echo "[L6] URL + Tech profiling..."

cat layer5/gau.txt layer5/wayback.txt | sort -u > layer6/all_urls.txt

cat layer6/all_urls.txt | httpx -silent \
-status-code -title -tech-detect -server -ip \
-o layer6/url_status.txt

whatweb -i layer4/resolved.txt -v > layer6/technology.txt

cat layer6/all_urls.txt | unfurl keys | sort -u > layer6/parameters.txt

cat layer4/resolved.txt | httpx -silent -ip -server > layer6/server_map.txt

# =========================

# ✅ FINAL MERGE

# =========================

cat layer1/all_passive.txt layer2/all_active.txt layer4/resolved.txt layer5/all_deep.txt | sort -u > all_subdomains.txt

httpx -l all_subdomains.txt -https -silent -o livesubdomains.txt

echo ""
echo "======================================"
echo " AlfaRecon v2 Finished"
echo "======================================"
echo "All subs   : $base/all_subdomains.txt"
echo "Live subs  : $base/livesubdomains.txt"
echo "URLs       : $base/layer6/url_status.txt"
echo "Params     : $base/layer6/parameters.txt"
echo "Tech       : $base/layer6/technology.txt"
echo "Server map : $base/layer6/server_map.txt"
echo "======================================"
}

# ------------------------

# MAIN

# ------------------------

case "$1" in
check) check_tools ;;
recon) run_recon $2 ;;
*) show_help ;;
esac
