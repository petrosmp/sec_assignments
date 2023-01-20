#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"

# regular expressions that match valid IPv4 and IPv6 addresses respectively
# generated by ChatGPT (https://chat.openai.com/chat) and tested at https://regexr.com/.
# 
# The IPv6 regex is not actually needed, since we could assume that all addresses we
# find in the files are valid, since we ourselves have created them, so if an address
# is not IPv4 it is IPv6.
#
# Also note that both regex's have to conform to POSIX extended regex rules (see link below)
# https://en.wikibooks.org/wiki/Regular_Expressions/POSIX-Extended_Regular_Expressions
IPv4RegEx="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
IPv6RegEx="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"



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

        # remove old versions of files if they exist
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
            printf "started job %s (pid: %s) (%s) \n" "$c" "$!" "$i"    # track the progress of the execution
            c=$(($c+1))
        done
        
        for i in ${diff[@]}; do
            resolve_DNS $i >> ${IPAddressesDifferent} &
            printf "started job %s (pid: %s) (%s) \n" "$c" "$!" "$i"    # track the progress of the execution
            c=$(($c+1))
        done
        
        # wait for the spawned processes to terminate, print message and exit
        wait
        echo "Done!"
        true
            
    elif [ "$1" = "-ipssame"  ]; then
        # Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.

        # get the IPs in an array
        addrs=$(cat "${IPAddressesSame}")

        # iterate through the addresses creating a new rule for each one
        for i in ${addrs[@]}; do

            # check the IP version of the address and use the appropriate iptables command
            if [[ $i =~ $IPv4RegEx ]]; then
                iptables -A INPUT -s "$i" -j DROP
            elif [[ $i =~ $IPv6RegEx ]]; then
                ip6tables -A INPUT -s "$i" -j DROP
            else
                printf "Error while creating rules: %s is not a valid IP address, skipping.\n" $i
            fi
        done
        true

    elif [ "$1" = "-ipsdiff"  ]; then
        # Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.

        # get the IPs in an array
        addrs=$(cat "${IPAddressesDifferent}")

        # iterate through the IPs creating a new rule for each one
        for i in ${addrs[@]}; do

            # check the IP version of the address and use the appropriate iptables command
            if [[ $i =~ $IPv4RegEx ]]; then
                iptables -A INPUT -s "$i" -j REJECT
            elif [[ $i =~ $IPv6RegEx ]]; then
                ip6tables -A INPUT -s "$i" -j REJECT
            else
                printf "Error while creating rules: %s is not a valid IP address, skipping.\n" $i
            fi
        done
        true

    elif [ "$1" = "-save"  ]; then
        # Save rules (both IPv4 and IPv6) to $adblockRules file. 
        iptables-save -f $adblockRules
        ip6tables-save >> $adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        
        # The adblockRules file may contain IPv4 rules, IPv6 rules,
        # or both (when saving, we append the IPv6 rules to the file
        # that contains the IPv4 ones, so we must handle that case,
        # however we cannot assume that this is always how things are).
        #
        # The problem is that iptables-restore and ip6tables-restore
        # cannot parse a file that contains rules that pertain to
        # addresses that are not consisent with the protocol version
        # they support (v4 and v6 respectively).
        #
        # In order to resolve this issue, in the case that the file
        # contains concatenated rules, we split them into 2 files,
        # determine the protocol version for each and run the
        # appropriate tool to restore the rules.

        # get the line where the second "section" (the one containing
        # IPv6 rules in the file generated by us) starts. This will
        # be empty if there is no second "section".
        secondInitLine="$(cat ./"${adblockRules}" | grep  filter --line-number --max-count 2 | cut -d: -f1 | tail +2)"
        
        if [[ $secondInitLine ]]; then
            # if there is a second "section", calculate where the
            # first one ends (2 lines before the second starts)
            firstFinishLine=$((secondInitLine-2))

            # split the file into 2
            head -n "${firstFinishLine}" "${adblockRules}" > __tmp_f1__
            tail -n +"$((firstFinishLine+1))" "${adblockRules}" > __tmp_f2__

            # set both files for restore
            filenames=("__tmp_f1__" "__tmp_f2__")
        else
            # just set the file for restore
            filenames=("$adblockRules")
        fi

        # for each file decide the protocol and restore accordingly
        for filename in ${filenames[@]}; do

            # to determine the protocol, choose the first rule line
            # (line 6) and keep the field with the address (field 4,
            # delimiter ' '), ommiting the part after the '/'
            line="$(cat $filename | tail -n +6 | head -1 | cut -d' ' -f4 | cut -d/ -f1)"
                
            # determine the version of the address and proceed accordingly
            if [[ $line =~ $IPv4RegEx ]]; then
                iptables-restore $filename
            elif [[ $line =~ $IPv6RegEx ]]; then
                ip6tables-restore $filename
            elif [[ $line = "COMMIT" ]]; then
                :   # nothing to restore, see README (RESTORE session)
            else
                printf "Error while restoring rules: %s is not a valid IP address.\n" $line
                printf "The restoration will skip every rule in the following file \"$filename\"\n"
                printf "Due to this error, restoration might be incomplete. \nManually checking \"$adblockRules\" as well as \"$filename\" is recommended.\n"
            fi

            # if this is not the standard file, its a temp file we need to delete
            if [[ $filename != $adblockRules ]]; then
                rm $filename
            fi

        done
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).

        # reset iptables for both versions of IP
        iptables -F     # Flush (delete) all chains
        ip6tables -F    # Flush (delete) all chains
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.

        # list iptables for both versions of IP
        iptables -L
        ip6tables -L
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