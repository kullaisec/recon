#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_domain>"
    exit 1
fi

target_domain=$1

# Step 1: Subdomain enumeration
echo "[-] Enumerating subdomains..."
subdomains=$(subfinder -d $target_domain)
amass_enum=$(amass enum -d $target_domain)
assetfinder_enum=$(assetfinder $target_domain)
#knockpy_enum=$(python3 /root/tools/knockpy/knockpy.py $target_domain)
#gobuster_enum=$(gobuster dns -d $target_domain -w /path/to/wordlist.txt)

# Combine and sort subdomains
all_subdomains=$(echo -e "$subdomains\n$amass_enum\n$assetfinder_enum" | sort -u)

# Step 2: Subdomain takeover check
echo "[-] Checking for subdomain takeover..."
for subdomain in $all_subdomains; do
    if subzy -hide -targets $subdomain | grep -q "Vulnerable"; then
        echo "Vulnerable subdomain found: $subdomain"
        echo "echo \"$subdomain\" | notify" | bash
    fi
done

# Step 3: Find live URLs using HTTPX
echo "[-] Finding live URLs..."
live_urls=$(httpx -l $all_subdomains)

# Step 4: Nuclei CVE scan
echo "[-] Performing Nuclei CVE scan..."
nuclei -l $live_urls -t /root/nuclei-templates/http/cves/ -severity critical,high,medium,low | tee -a target_full_recon.txt | grep -qE "critical|high|medium|low" && echo "Vulnerabilities found." | notify

# Step 5: Nuclei vulnerability scan
echo "[-] Performing Nuclei vulnerability scan..."
nuclei -l $live_urls -t /root/nuclei-templates/http/vulnerabilities/ -severity critical,high,medium,low | tee -a target_full_recon.txt | grep -qE "critical|high|medium|low" && echo "Vulnerabilities found." | notify

# Step 6: Nuclei exposure scan
echo "[-] Performing Nuclei exposure scan..."
nuclei -l $live_urls -t /root/nuclei-templates/http/exposures/ -severity critical,high,medium,low | tee -a target_full_recon.txt | grep -qE "critical|high|medium|low" && echo "Exposures found." | notify

# Step 7: Nuclei exposed panels scan
echo "[-] Performing Nuclei panels scan..."
nuclei -l $live_urls -t /root/nuclei-templates/http/exposed-panels/ | tee -a target_full_recon.txt | grep -qE "critical|high|medium|low" && echo "Panels found." | notify

# Step 8: Nuclei misconfigurations scan
echo "[-] Performing Nuclei misconfigurations scan..."
nuclei -l $live_urls -t /root/nuclei-templates/http/misconfiguration/ | tee -a target_full_recon.txt | grep -qE "critical|high|medium|low" && echo "Misconfigurations found." | notify

# Step 9: Nuclei Fuzzing
echo "[-] Performing Nuclei Fuzzing scan..."
nuclei -l $live_urls -t /root/nuclei-templates/http/fuzzing/ | tee -a target_full_recon.txt | grep -qE "critical|high|medium|low" && echo "Fuzzing found." | notify

# Step 10: Nuclei miscellaneous
echo "[-] Performing Nuclei miscellaneous scan..."
nuclei -l $live_urls -t /root/nuclei-templates/http/miscellaneous/ | tee -a target_full_recon.txt | grep -qE "critical|high|medium|low" && echo "miscellaneous found." | notify

# Step 11: Ffuf
echo "[-] Running Dirsearch..."
while IFS= read -r subdomain; do
    # dirsearch -u $subdomain -w /path/to/dirsearch/wordlist.txt | tee -a target_full_recon.txt | grep -q "Status: 200" && echo "Status 200 found for $subdomain." | notify
    #ffuf -u https://$subdomain/WFUZZ -w /root/super.txt:WFUZZ -mode clusterbomb | tee -a target_full_recon.txt | grep -q "Status: 200" && echo "Status 200 found for $subdomain." | notify
    base_url="https://$subdomain/"
ffuf -u $base_url"FUZZ" -w /root/super.txt -e "$base_url"FUZZ -mode clusterbomb | grep -q "Status: 200" && echo "Status 200 found for $base_url." | notify

done <<< "$all_subdomains"


# Step 10: Save results to target_full_recon.txt
echo "$live_urls" > target_full_recon.txt

echo "[-] Full reconnaissance completed. Results saved to target_full_recon.txt."
echo "Reconnaissance on $target_domain completed. Results saved to target_full_recon.txt." | notify
