import argparse         # For the processing and handling of command line arguments
import string           # For string types used in the random generator
import random           # For generating random numbers
import sys              # For access to the CMD arguments
import dns.resolver     # For doing the DNS resolution
import ipaddress        # Validation of the resolver IP Address

class FontColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

FAIL = f"{FontColors.FAIL}FAIL{FontColors.ENDC}"
PASS = f"{FontColors.GREEN}PASS{FontColors.ENDC}"

def print_title(name):
    name = ' ' + name + ' '
    print("{:#^80}".format(name))


def print_banner(name):
    print_title(name)
    print(80 * '-')


def check_spf(domain):
    """
    Queary a domain for a a text record. Check each result for the SPF flag
    exists in the record. When more than one SPF recorde exists add a warning.

    """
    result = {'result': FAIL, 'data': []}
    try:
        answers = dns_resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in str(rdata).lower() and result['result'] == PASS:
                result['data'].append(str(rdata))
                result['note'] = f"{FontColors.GREEN}Warning: More than one records found!{FontColors.ENDC}"
            elif 'v=spf1' in str(rdata).lower() and result['result'] != PASS:
                result['data'].append(str(rdata))
                result['result'] = PASS
    except dns.resolver.NXDOMAIN:
        result['data'].append((domain, 'NXDOMAIN'))
    except dns.resolver.NoAnswer:
        result['data'].append((domain, 'NOANSWER'))
    return result


def check_spf_sub_domain(domain, r):
    """
    Add a random subdomain to validate wildcard spf exists
    """
    return check_spf(r + '.' + domain)


def check_dkim(domain, r):
    """
    Check for a random dkim key to validate wildcard dkim exists
    """
    result = {'result': FAIL, 'data': []}
    try:
        answers = dns_resolver.resolve(r + '._domainkey.' + domain, 'TXT')
        for rdata in answers:
            if 'v=dkim1;' in str(rdata).lower():
                return {'result': PASS, 'data': str(rdata)}
    except dns.resolver.NXDOMAIN:
        result['data'] = [(r + '._domainkey.' + domain, 'NXDOMAIN')]
    return result


def check_dmarc(domain):
    """
    Check that dmark record exists for the exact domain and parrent domains
    a.my.domain.com
      my.domain.com
         domain.com
    """
    domain_parts = domain.split('.')
    result = {'result': 'Fail', 'data': []}
    while len(domain_parts) > 1:
        try:
            answers = dns_resolver.resolve('_dmarc.' + '.'.join(domain_parts), 'TXT',)
            for rdata in answers:
                if 'v=dmarc1;' in str(rdata).lower():
                    result['result'] = 'PASS'
                    result['data'].append(('.'.join(domain_parts), str(rdata)))
                    domain_parts = domain_parts[1:]
                    continue
            result['data'].append(('.'.join(domain_parts), 'None'))
        except dns.resolver.NXDOMAIN:
            result['data'].append(('.'.join(domain_parts), 'NXDOMAIN'))
        domain_parts = domain_parts[1:]
    return result


def print_result(r):
    """
    Print the returned result, data and note. Data can be a list of
    strings if more than one record was returned
    """
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

def create_spf(domain):
    print('{:<30} {:<10} {}'.format(domain, 'TXT', 'v=spf1 -all'))
    print('*.{:<28} {:<10} {}'.format(domain, 'TXT', 'v=spf1 -all'))
    print()


def create_dkim_wildcard(domain):
    print('*._domainkey.{:<17} {:<10} {}'.format(domain, 'TXT', 'v=dkim1; p='))
    print()


def create_dmarc(domain):
    print('{:<30} {:<10} {}'.format(domain, 'TXT', 'v=DMARC1; p=none; rua=mailto:rua@' + domain + '; ruf=mailto:ruf@' + domain))
    print()


def do_verification(domain):
    try:
        print_title('#')
        print_title('VERIFICATION')
        print_banner('TEST: SPECIFIC SPF RECORD')
        print_result(check_spf(domain))
        print_banner('TEST: SUB DOMAIN/WILDCARD SPF RECORD')
        print_result(check_spf_sub_domain(domain, rand))
        print_banner('TEST: WILDCARD DKIM RECORD')
        print_result(check_dkim(domain, rand))
        print_banner('TEST: DMARC RECORD')
        print_result(check_dmarc(domain))
    except dns.resolver.LifetimeTimeout as e:
        print('Error: Connection time received!')
        print(e)


def do_creation(domain):
    print_title('# # # #')
    print_title('RECORD CREATION')
    print_banner('SPF RECORDS')
    create_spf(domain)
    print_banner('DKIM RECORD')
    create_dkim_wildcard(domain)
    print_banner('DMARC RECORD')
    create_dmarc(domain)


# Beginning of the main program
# Start parsing the comanline args to setup the program

parser = argparse.ArgumentParser(description='Test and create DNS records for a given domain.')
parser.add_argument('domain', metavar='domain', help='The domain which to run verification or creation for')
parser.add_argument('resolver', metavar='Resolver', nargs='?', help='IP address of preferred DNS server')
parser.add_argument('-v', '--verify', default=False, action='store_true', help='Verify records exist for domain')
parser.add_argument('-c', '--create', default=False, action='store_true', help='Create records for domain')
args = vars(parser.parse_args(sys.argv[1:]))  # Pass in the cmd line agrs without the first arg(name of file)

rand = ''.join([random.choice(string.ascii_letters) for n in range(6)])

dns_resolver = dns.resolver.Resolver()
# Validate the IP of the DNS resolver that was passed in
if args.get('resolver') is not None:
    try:
        resolver_ip = ipaddress.ip_address(args.get('resolver'))
        dns_resolver = dns.resolver.make_resolver_at(str(resolver_ip))
    except ValueError as e:
        print(e)
        exit()


# Normalise the arguments to their long form
if args.get('v'):
    args['verify'] = args.get('v')
if args.get('c'):
    args['create'] = args.get('c')


if args.get('verify'):
    do_verification( args.get('domain'))
elif args.get('create'):
    do_creation( args.get('domain'))
elif not  args.get('verify') and not args.get('create'):
    do_verification( args.get('domain'))
    do_creation( args.get('domain'))
