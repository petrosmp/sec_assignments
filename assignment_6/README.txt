This assignment was to develop a bash script that uses the iptables
interface in order to create a simple adblocking mechanism. The 
script performs a variety of operations depending on the option
that the user chooses when running it (see ./adblock.sh -help).





EXECUTION INSTRUCTIONS:
    - First of all, the script has to be executable, which can be
      achieved by running the following command:
        sudo chmod +x ./adblock.sh
    - Now the script is ready to run. For usage details and options
      use the -help parameter. Note that the script requires elevated
      priviledges to be run and so sudo is ALWAYS required (even when
      printing the help message)





RESULTS - EFFECTIVENESS OF THE TOOL:
    - Tests were done before and after configuring the firewall using
      the script that was developed in order to verify that it worked
      as intended.
        In popular websites like YouTube, the ads were not completely
        blocked, although finding their origin and adding it to the
        block domains did the trick.
        According to https://d3ward.github.io/toolz/adblock, on Firefox
        108.0 (with "Enhanced Tracking Protection" turned off), there
        is a 10-18% increase in the percentage of blocked hosts when the
        firewall is configured compared to when it is not.
    - It should be noted that the results do not depend on the correctness
      of the script as much as they do on the inclusivity of the list of
      the blocked domains. The better the list, the bigger the number of ads
      blocked by the firewall.





IMPLEMENTATION DETAILS:
    - The purpose of this script is to configure the linux kernel firewall
      to block traffic coming from certain domains. This is achieved by
      using the iptables utility, which acts as a frontend to the firewall.
    - The domains that will be blocked are found in domainNames.txt and 
      domainNames2.txt. This means that new domains can be added to those
      files in order to increase the adblocking effect.
    - The domain names need to be resolved to IP addresses before the
      firewall is configures, as the rules of the latter are enforced in the
      IP level (network layer), and thus have no use for domain names. The
      script uses the nslookup utility (part of the net-utils package) to
      query the DNS servers in order to find the addres(es) associated with
      each domain name.
    - Some of domain names provided as part of the project corpus could be
      resolved as IPv6 addresses (as well as IPv4 ones). This meant that the
      script should be able to handle IPv6 addresses correctly. The iptables
      interface only offers functionality regarding IPv4 addresses, so the
      ip6tables interface had to be used too. In order to decide what utility
      should be used each time, the following systems were implemented:
        > when parsing through the addresses to configure the rules, each
          address is identified as an IPv4 or IPv6 one (using a regular
          expression) and the appropriate utility is called.
        > when saving the firewall rules to a file, both utilities are called
          (first iptables and then ip6tables) and write to the same file.





RESTORE:
    - Because of the way that the script handles the "save rules to file"
      option (see IMPLEMENTATION DETAILS above), when restoring rules
      from a file, a dedicated check has to be made:
        - if the file only contains IPv4 (or IPv6) configuration, the
          appropriate utility is called to restore it.
        - if the file contains both IPv4 and IPv6 configurations, it is
          split into 2 files, and each configuration is restored by the
          appropriate utility.
          This can lead to the following situation:
            When the script is used with the -save option and the existing
            firewall only consists of IPv4 (or IPv6) rules and since both
            iptables-save and ip6tables-save are called, one will just produce
            the "template" output.
            This causes the 'COMMIT' statement (which is used interally by the
            restore utility of both iptables and ip6tables to indicate that
            all rules have been parsed and the change should be commited) to be
            where the first rule would be, if any rules existed.
            This allows us to recognize the situation and skip that file.





SOURCES:
    - For iptables and its usage:
        https://youtu.be/XKfhOQWrUVw
        https://man7.org/linux/man-pages/man8/iptables.8.html
        https://man7.org/linux/man-pages/man8/iptables-save.8.html
        https://man7.org/linux/man-pages/man8/iptables-restore.8.html

    - For other linux commands:
        https://man7.org/linux/man-pages/man1/awk.1p.html
        https://man7.org/linux/man-pages/man1/comm.1.html
        (and other man pages)
    
    - For regular expressions:
        https://chat.openai.com/chat
        https://regexr.com/

        (regular expressions that match valid IPv4 and IPv6 addresses
         were generated by the ChatGPT AI model and tested at regexr.com) 
