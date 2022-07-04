
# pip install dnspython

import argparse         # For the processing and handling of commandline arguments
import string           # For string types used in the random generator
import random           # For generating random numbers
import sys              # For access to the CMD arguments
import dns.resolver     # DURRRRRRRR


def print_title(name):
    name = ' ' + name + ' '
    y = int((80 - len(name)) / 2)
    print(y * '-' + name + y * '-')


def print_banner(name):
    print_title(name)
    print(80 * '-')


# Pass in the domain and return a dict of the result (Pass/Fail, Data[], Note) from checking the exact SPF
def check_spf(url):
    result = {'result': 'FAIL', 'data': []}
    try:
        answers = dns.resolver.query(url, 'TXT')
        for rdata in answers:
            if 'v=spf1' in str(rdata).lower() and result['result'] is 'PASS':
                result['data'].append(str(rdata))
                result['note'] = 'Warning: More than one records found!'
            elif 'v=spf1' in str(rdata).lower() and result['result'] is not 'PASS':
                result['data'].append(str(rdata))
                result['result'] = 'PASS'
    except dns.resolver.NXDOMAIN:
        result['data'].append((url, 'NXDOMAIN'))
    except dns.resolver.NoAnswer:
        result['data'].append((url, 'NOANSWER'))
    return result


def check_spf_sub_domain(url, r):
    return check_spf(r + '.' + url)


def check_dkim(url, r):
    result = {'result': 'Fail', 'data': []}
    try:
        answers = dns.resolver.query(r + '._domainkey.' + url, 'TXT')
        for rdata in answers:
            if 'v=dkim1;' in str(rdata).lower():
                return {'result': 'PASS', 'data': str(rdata)}
    except dns.resolver.NXDOMAIN:
        result['data'] = [(r + '._domainkey.' + url, 'NXDOMAIN')]

    return result


def check_dmarc(url):
    """
    a.my.domain.com
      my.domain.com
         domain.com
    """
    url_parts = url.split('.')
    result = {'result': 'Fail', 'data': []}
    while len(url_parts) > 1:
        try:
            answers = dns.resolver.query('_dmarc.' + '.'.join(url_parts), 'TXT')
            for rdata in answers:
                # print(rdata)
                if 'v=dmarc1;' in str(rdata).lower():
                    result['result'] = 'PASS'
                    result['data'].append(('.'.join(url_parts), str(rdata)))
                    url_parts = url_parts[1:]
                    continue
            result['data'].append(('.'.join(url_parts), 'None'))
        except dns.resolver.NXDOMAIN:
            result['data'].append(('.'.join(url_parts), 'NXDOMAIN'))
        url_parts = url_parts[1:]
    return result


def print_result(r):
    print('RESULT: ' + r['result'])
    if isinstance(r['data'], list):
        for e in r['data']:
            if isinstance(e, tuple):
                print('Domain: {:<20} Record: {}'.format(e[0], e[1]))
            elif isinstance(e, str):
                print('Data: ' + e)
    elif isinstance(r['data'], str):
        print('Data: ' + r['data'])

    if 'note' in r.keys():
        print('Note: ' + r['note'])
    print()

def create_spf(url):
    print('{:<30} {:<10} {}'.format(url, 'TXT', 'v=spf1 -all'))
    print('*.{:<28} {:<10} {}'.format(url, 'TXT', 'v=spf1 -all'))
    print()


def create_dkim_wildcard(url):
    print('*._domainkey.{:<17} {:<10} {}'.format(url, 'TXT', 'v=dkim1; p='))
    print()


def create_dmarc(url):
    print('{:<30} {:<10} {}'.format(url, 'TXT', 'v=DMARC1; p=none; rua=mailto:rua@' + url + '; ruf=mailto:ruf@' + url))
    print()


def do_verificatio():
    print_title('VERIFICATION')
    print_banner('TEST: SPECIFIC SPF RECORD')
    print_result(check_spf(args.url))
    print_banner('TEST: SUB DOMAIN/WILDCARD SPF RECORD')
    print_result(check_spf_sub_domain(args.url, rand))
    print_banner('TEST: WILDCARD DKIM RECORD')
    print_result(check_dkim(args.url, rand))
    print_banner('TEST: DMARC RECORD')
    print_result(check_dmarc(args.url))


def do_creation():
    print_title('RECORD CREATION')
    print_banner('SPF RECORDS ')
    create_spf(args.url)
    print_banner('DKIM RECORD ')
    create_dkim_wildcard(args.url)
    print_banner('DMARC RECORD')
    create_dmarc(args.url)



"""
my.domain.com               IN      A   1.1.1.1
my.domain.com               TXT         "v=spf1 -all"
*.my.domain.com             TXT         "v=spf1 -all"
*._domainkey.my.domain.com  TXT         "v=dkim1; p="
_dmarc.my.domain.com        TXT         "v=DMARC1; p=none; rua=mailto:rua@my.domain.com; ruf=mailto:ruf@my.domain.com"
"""

"""
./dns url.com           Create and Verify the domain records 
./dns -c url.com        Create the domain records 
./dns -v url.com        Verify the domain records exist
"""

# Beginning of the main program
# Start parsing the comanline args to setup the program

parser = argparse.ArgumentParser(description='Test and create DNS records for a given domain.')
parser.add_argument('url', metavar='my.domain.com', help='The string representation of the domain')
parser.add_argument('resolver', metavar='Resolver', nargs='?', help='The ip address of the DNS server to use')
parser.add_argument('-v', '-verify', action='store_true', help='Domain to verify records exist for')
parser.add_argument('-c', '-create', action='store_true', help='Domain to create records for')
args = parser.parse_args(sys.argv[1:])  # Pass in the cmd line agrs without the first arg(name of file)
print(args)


rand = ''.join([random.choice(string.ascii_letters) for n in range(6)])

if args.resolver is not None:
    print("TODO - validate the ip address and store")
    print()

if args.v is True:
    do_verificatio()
elif args.c is True:
    do_creation()
elif args.v is not True and args.c is not True:
    do_verificatio()
    do_creation()

"""
# This might only work on linux
print("\033[1;32;40m Bright Green  \n")
print("\033[1;31;40m Red  \n")

"""