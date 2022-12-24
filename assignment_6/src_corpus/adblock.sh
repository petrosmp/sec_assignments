#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"

function resolve_DNS() {
    # pass nslookup's output to awk to only keep the IPs
    # associated with the given domain name
    # dig +short $i | grep -v ";"
    nslookup $1 | awk '/^Name:/ {c=2} !--c {print $2}'
}

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Find different and same domains in ‘domainNames.txt’ and ‘domainsNames2.txt’ files 
	# and write them in “IPAddressesDifferent.txt and IPAddressesSame.txt" respectively
        # Write your code here...

        # remove old files if they exist
        rm ${IPAddressesSame}  -f
        rm ${IPAddressesDifferent}  -f

        # get the domains that only appear in file1/file2 and combine them
        only1=$(comm <(sort "${domainNames}") <(sort "${domainNames2}") -2 -3)  # comm needs the files to be sorted
        only2=$(comm <(sort "${domainNames}") <(sort "${domainNames2}") -1 -3)  # comm needs the files to be sorted
        diff=("${only1[@]}" "${only2[@]}") # concatenate
        
        # get the domains that appear in both files
        same=$(comm <(sort "${domainNames}") <(sort "${domainNames2}") -1 -2)   # comm needs the files to be sorted

        c=1

        # for each domain, resolve its IP and write it to the file
        for i in ${same[@]}; do
            resolve_DNS $i >> ${IPAddressesSame} &
            printf "started job %s (pid: %s) (%s) \n" "$c" "$!" "$i"
            c=$(($c+1))
        done
        
        for i in ${diff[@]}; do
            resolve_DNS $i >> ${IPAddressesDifferent} &
            printf "started job %s (pid: %s) (%s) \n" "$c" "$!" "$i"
            c=$(($c+1))
        done
        
        wait
        echo "Done!"
        true
            
    elif [ "$1" = "-ipssame"  ]; then
        # Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.
        # Write your code here...
        # ...
        # ...
        true
    elif [ "$1" = "-ipsdiff"  ]; then
        # Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.
        # Write your code here...
        # ...
        # ...
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        # Write your code here...
        # ...
        # ...
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        # Write your code here...
        # ...
        # ...
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        # Write your code here...
        # ...
        # ...
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        # Write your code here...
        # ...
        # ...
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
	printf "  -ipsdiff\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
