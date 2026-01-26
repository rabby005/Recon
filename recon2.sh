#!/bin/bash 

target=$1
cd ~/bugbounty2021
echo "------------creating directory ----------------------"
mkdir ~/bugbounty2022/$1
echo "-----------Find subdomain------------"
cd ~/Sublist3r
python3 sublist3r.py -d $1 -o ~/bugbounty2022/$1/subdomain1.txt
amass enum -ip -brute -d $1 -o ~/bugbounty2022/$1/subdomain2.txt
cd ~/Recon
./crt.sh $1 > ~/bugbounty2022/$1/subdomain3.txt
sort ~/bugbounty2022/$1/subdomain1.txt ~/bugbounty2022/$1/subdomain2.txt ~/bugbounty2022/$1/subdomain3.txt | uniq >> ~/bugbounty2022/$1/fainalsubdomain.txt
httpx -l ~/bugbounty2022/$1/fainalsubdomain.txt -o ~/bugbounty2022/$1/Subdomain.txt
cat ~/bugbounty2022/$1/Subdomain.txt | httpx -web-server -o ~/bugbounty2022/$1/version.txt
echo "-----------Finis subdomain------------
                         |
                         |"
echo "-----------------------Cheack 20 port-----------------"
naabu -p 20 -list ~/bugbounty2022/$1/Subdomain.txt | tee  ~/bugbounty2022/$1/20port.txt
echo "-----------------------Cheack 21 port-----------------"
naabu -p 21 -list ~/bugbounty2022/$1/Subdomain.txt | tee  ~/bugbounty2022/$1/21port.txt
echo "---------------- CHEACK CLOUDFAIF ------------------------"
cf-check -d ~/bugbounty2022/$1/Subdomain.txt | tee  ~/bugbounty2022/$1/Cloudfair Subdomain.txt

cat  ~/bugbounty2022/$1/Subdomain.txt | waybackurls | tee -a ~/bugbounty2022/$1/wayback.txt
#cd ~/dirsearch
#python3 dirsearch.py -l ~/bugbounty2022/$1/Subdomain.txt -t 100 --plain-txt-report ~/bugbounty2022/$1/dirsearch.txt
#namap -il ~/bugbounty2022/$1/fainalsubdomain.txt -p- --open -sV -oG ~/bugbounty2022/$1/Nmap.txt
echo "--------------------XSS peramiter-------------------
                              |
                              |
                              "
gf xss ~/bugbounty2022/$1/wayback.txt | tee ~/bugbounty2022/$1/gf-XSS peramiter.txt

echo "--------------------SQLI peramiter-------------------
                              |
                              |
                              "
gf sqli ~/bugbounty2022/$1/wayback.txt | tee ~/bugbounty2022/$1/gf-sql peramiter.txt
