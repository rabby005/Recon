#!/bin/bash

target=$1
cd ~/bugbounty2022
echo "------------creating directory ----------------------"
mkdir ~/bugbounty2022/$1
echo "-----------Find subdomain------------"
#cd ~/Sublist3r
#python3 [sublist3r.py](http://sublist3r.py/) -d $1 -o ~/bugbounty2022/$1/subdomain1.txt
subfinder -d $1 -all -o ~/bugbounty2022/$1/subdomain1.txt
amass enum -passive -config ~/.config/amass/config.ini -norecursive -noalts -d $1 -o ~/bugbounty2022/$1/subdomain2.txt
sort ~/bugbounty2022/$1/subdomain2.txt | uniq >> -o ~/bugbounty2022/$1/subdomain2.txt
#amass enum  -brute -d $1 -o ~/bugbounty2022/$1/subdomain2.txt
cd ~/faraby/Recon
./crt.sh $1 > ~/bugbounty2022/$1/subdomain3.txt
sort ~/bugbounty2022/$1/subdomain1.txt ~/bugbounty2022/$1/subdomain2.txt ~/bugbounty2022/$1/subdomain3.txt | uniq >> ~/bugbounty2022/$1/fainalsubdomain.txt
httpx -l ~/bugbounty2022/$1/fainalsubdomain.txt -o ~/bugbounty2022/$1/Subdomain.txt
cat ~/bugbounty2022/$1/Subdomain.txt | httpx -web-server -status-code -o ~/bugbounty2022/$1/version.txt
echo "-----------Wayback urls------------"
cat  ~/bugbounty2022/$1/Subdomain.txt | waybackurls | tee -a ~/bugbounty2022/$1/wayback.txt
cat ~/bugbounty2022/$1/wayback.txt | grep ".php" > ~/bugbounty2022/$1/php-file.txt
echo "-----------Finish subdomain------------"

                              |

                              |

echo "-----------------------I____M_____P Urls-----------------"
cat ~/bugbounty2022/$1/Subdomain.txt | hakrawler | tee ~/bugbounty2022/$1/IMP urls.txt
cat ~/bugbounty2022/$1/Subdomain.txt | hakrawler | tee ~/bugbounty2022/$1/IMP urls.txt
#cat ~/bugbounty2022/$1/IMP urls.txt | aquatone | tee ~/bugbounty2022/$1/Scrensorturls.txt
#cat ~/bugbounty2022/$1/IMP urls.txt | aquatone -out ~/bugbounty2022/$1/Scrensorturls.txt

echo "---------------- CHEACK CLOUDFAIF ------------------------"
cf-check -d ~/bugbounty2022/$1/Subdomain.txt | tee  ~/bugbounty2022/$1/Cloudfair Subdomain.txt

cat  ~/bugbounty2022/$1/Subdomain.txt | waybackurls | tee -a ~/bugbounty2022/$1/wayback.txt

echo "--------------------XSS peramiter-------------------"

                         |
                         |


gf xss ~/bugbounty2022/$1/wayback.txt | tee ~/bugbounty2022/$1/gf-XSS peramiter.txt

echo "-------------------- SQLI peramiter------------------- "

gf sqli ~/bugbounty2022/$1/wayback.txt | tee ~/bugbounty2022/$1/gf-sql peramiter.txt

echo "-------------------- LFI peramiter-------------------"

gf lfi ~/bugbounty2022/$1/wayback.txt | tee ~/bugbounty2022/$1/gf-LFI peramiter.txt
