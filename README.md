# python-dns-checker

After learning of the SFP subdomain issue I wanted to create a simple tool that could help identify the problem and generate example records that could be added to close the gap.

## SYNOPSIS

dns-check.py [-h] [-v] [-c] domain [Resolver]

## DESCRIPTION
A tool to quickly review existing DNS records for specific and wildcard SPF and DKIM records and create example records that can be added. 

    -v, --verify
        Verify records exist for domain.

    -c, --create
        Create records for domain.

    -h, --help
        Display this help and exit.

    domain
        The DNS domain which to run this tool against.

    [resolver]
        The IP address of a preferred DNS resolver.