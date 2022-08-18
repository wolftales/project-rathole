# Copyright (c) 2019 NetApp, Inc., All Rights Reserved

import argparse
import getpass
import json
import logging as log
import re
import subprocess
import signal
import sys
import urllib

# Enable input compatibility for both Python 2 and 3
try:
    input = raw_input
except NameError:
    pass

# Check if this environment supports SSL.
try:
    import ssl
except ImportError:
    log.fatal('This version of Python does not support SSL module. Must be 2.6 or newer')
    raise sys.exit(1)

if sys.version_info < (3, 0):
    from HTMLParser import HTMLParser
    import cookielib as cookiejar
    import urllib2 as urllib_request
    import urllib2 as urllib_error
    import urllib2 as urllib_parse
    import urllib as urllib_parse
else:
    from html.parser import HTMLParser
    import http.cookiejar as cookiejar
    import urllib.request as urllib_request
    import urllib.error as urllib_error
    import urllib.parse as urllib_parse


class SmartFormatter(argparse.HelpFormatter):
    '''Add capability to split help on LF'''

    def _split_lines(self, text, width):
        # Update width based on terminal size
        try:
            width = int(subprocess.check_output(['stty', 'size'],
                                                stderr=subprocess.STDOUT).split()[1]) - 26
        except(ValueError, IndexError, subprocess.CalledProcessError):
            width = 80 - 26

        lines = []
        if '\n' in text:
            for entry in text.splitlines():
                lines += argparse.HelpFormatter._split_lines(self, entry, width)
            return lines
        # this is the RawTextHelpFormatter._split_lines
        return argparse.HelpFormatter._split_lines(self, text, width)


class ArgParser(argparse.ArgumentParser):
    ''' Inherit from argparse.ArgumentParser so we can overload the error method'''

    def error(self, message):
        '''Redefine error method to print full usage when an error occurs'''
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(1)


class SAMLResponseParser(HTMLParser):

    def __init__(self, searchAttrs):
        HTMLParser.__init__(self)
        self.data = []
        self.tag = searchAttrs['tag']
        self.nametype = searchAttrs['nametype']
        self.name = searchAttrs['name']
        self.valtype = searchAttrs['valtype']

    def handle_starttag(self, tag, attributes):
        if tag != self.tag:
            return
        if (self.nametype, self.name) not in attributes:
            return
        for name, value in attributes:
            if name == self.valtype:
                self.data.append(value)
                break


class APICaller():
    '''Class that encapsulates and persists cookies and ssl context across API calls'''

    def __init__(self):
        self.cj = cookiejar.CookieJar()
        self.context = get_ssl_context()
        if self.context is None:
            handler = urllib_request.HTTPSHandler()
        else:
            handler = urllib_request.HTTPSHandler(context=self.context)

        self.opener = urllib_request.build_opener(
            urllib_request.HTTPCookieProcessor(self.cj),
            handler)

    def call(self, url, methods='GET', data=None,
             headers={'content-type': 'application/json'}, verbose=True):
        request = urllib_request.Request(url, data=data, headers=headers)

        self.__log_request(request, verbose)

        try:
            response = self.opener.open(request)
        except urllib_error.HTTPError as e:
            log.error('API call failed with status code: {}'.format(str(e)))
            raise
        except urllib_error.URLError:
            log.error('URL in request is invalid: {}'.format(url))
            raise

        self.__log_response(response)

        response_body = response.read()
        if response_body:
            # See if we have JSON
            if response.headers['Content-Type'] == 'application/json':
                try:
                    # decode forces compatibility with python3 stings (can't be done on binary data)
                    response_body = response_body.decode('utf-8')
                except UnicodeError:
                    # Was not decoded... Don't try anything else (raw result is in data)
                    pass
                try:
                    # Try JSON parsing
                    response_body = json.loads(response_body)
                except ValueError as e:
                    log.fatal("Failed to decode response data: " + str(e))
                    raise

        return response_body

    def __log_request(self, request, print_data=True):
        log.info('REQUEST')
        log.info('URL: {} {}'.format(request.get_method(), request.get_full_url()))
        log.info('Headers: {}'.format(request.headers))
        if print_data:
            log.info('Data: {}'.format(request.data))
        log.info('-' * 80)

    def __log_response(self, response):
        log.info('RESPONSE')
        log.info('HTTP: {} {}'.format(response.code, response.url))
        log.info('Headers:\n{}'.format(response.headers))


def get_ssl_context():
    ssl_context = None

    if args.get('insecure'):
        log.info('Using insecure mode...')
        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.check_hostname = False
        except AttributeError as e:
            # This string is detected in python 2.7.6 (during an exception)
            if "'module' object has no attribute 'SSLContext'" in str(e):
                pass
    else:
        # Set the API request mode to HTTPS
        if sys.version_info < (2, 7, 9):
            log.fatal('Current python version does not support SSL context.\
                Use argument \'--insecure\' to allow insecure HTTPS calls.')
            raise sys.exit(1)
        if sys.version_info < (3, 0):
            # HTTPS SSL context was added in 2.7.9, so use if for all later 2.x versions
            ssl_context = ssl.create_default_context()
        elif sys.version_info < (3, 2):
            # Python 3.x before 3.2 did not support SSL context
            log.fatal('Current python version does not support SSL context.\
                Use argument \'--insecure\' to allow insecure HTTPS calls.')
            raise sys.exit(1)
        else:
            # HTTPS SSL context and check_hostname are supported in 3.x starting at 3.2
            ssl_context = ssl.create_default_context()

    return ssl_context


def parse_arguments():
    global args
    parser = ArgParser(description='Script to help SAML SSO Authentication for StorageGRID',
                       formatter_class=SmartFormatter)
    # Optional global arguments
    parser.add_argument('--saml-user',
                        help='The username used in SAML authentication request.')
    parser.add_argument('--saml-domain',
                        help='The domain associated with the username in SAML authentication request.')
    parser.add_argument('--sg-address',
                        help='The IP address or hostname of an Admin Node on your StorageGRID instance.')
    parser.add_argument('--tenant-account-id', help='The tenant account ID on StorageGRID.')
    parser.add_argument('-v', '--verbose', help='Verbose output (shows raw http calls in <STDOUT>).',
                        action='store_true', default=False)
    parser.add_argument('--insecure', help='Allows insecure communication with the Admin Node and ADFS.',
                        action='store_true', default=False)
    parser.add_argument('--debug', help='Enable traceback to see most recent calls before exit.',
                        action='store_true', default=False)

    args = vars(parser.parse_args())
    # Get remaining missing arguments
    prompt_arguments()


def prompt_arguments():
    for key in args:
        if args[key] is None:
            args[key] = input(key + ': ')

    if sys.stdin.isatty():
        # Safely receive password without echoing input on terminal
        password = getpass.getpass('Enter the user\'s SAML password: ')
    else:
        password = sys.stdin.read()

    args['saml_password'] = password.rstrip()
    print('*' * 80 + '\n')


def parse_saml_response(response, searchAttrs):
    saml_parser = SAMLResponseParser(searchAttrs)
    response = str(response)
    saml_parser.feed(response)
    if (not saml_parser.data) or (not saml_parser.data[0]):
        log.error('Unable to get SAMLresponse, verify access from ADFS.')
        raise sys.exit(1)

    log.info('SAML Response: {}'.format(saml_parser.data[0]))

    return saml_parser.data[0]


def log_action(action):
    log.info('*' * 80)
    log.info(action)
    log.info('*' * 80)


def main():
    parse_arguments()

    if args.get('verbose'):
        log.basicConfig(level=log.INFO)

    if not args.get('debug'):
        sys.tracebacklimit = 0

    log.info('Using Python v.{}'.format(sys.version))
    caller = APICaller()

    # STEP 1: get signed authentication URL.
    log_action('Get signed authentication URL from SG')

    url = 'https://' + args.get('sg_address') + '/api/v3/authorize-saml'
    payload = {'accountId': args.get('tenant_account_id'), }

    response = caller.call(url, 'POST', data=json.dumps(payload).encode())

    saml_request = response['data']

    log.info('saml-request: {}\n\n'.format(saml_request))

    # STEP 2: Get full URL including client request ID from AD FS.
    log_action('Get a full URL that includes the client request ID from AD FS')

    response = caller.call(saml_request, 'GET')
    action = parse_saml_response(response, {
        'tag': 'form',
        'nametype': 'id',
        'name': 'loginForm',
        'valtype': 'action',
    })
    request_id_list = action.split('=')
    client_id = str(request_id_list[-1])

    # STEP 3: Send credentials to form action
    log_action('Send credentials to form action')

    saml_request_url = saml_request + '&client-request-id=' + client_id
    form_data = {
        'UserName': args.get('saml_user') + '@' + args.get('saml_domain'),
        'Password': args.get('saml_password'),
        'AuthMethod': 'FormsAuthentication'
    }

    response = caller.call(
        saml_request_url, 'POST',
        data=urllib_parse.urlencode(form_data).encode(),
        headers={'content-type': 'application/x-www-form-urlencoded'}, verbose=False)
    saml_response = parse_saml_response(response, {
        'tag': 'input',
        'nametype': u'name',
        'name': u'SAMLResponse',
        'valtype': 'value',
    })

    # STEP 4: make sgw /api/saml-response request to generate Auth token.
    log_action('Make SG /api/saml-response request to generate Auth token.')

    url = 'https://' + args.get('sg_address') + '/api/saml-response'
    payload = {
        'SAMLResponse': saml_response,
        'RelayState': args.get('tenant_account_id')
    }

    response = caller.call(url, 'POST', data=urllib_parse.urlencode(payload).encode(), headers={
                           'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded'})

    sg_auth_token = response['data']
    print('*' * 80)
    print('StorageGRID Auth Token: {}'.format(sg_auth_token))


def signal_handler(signal, frame):
    ''''Trap Ctrl+C'''
    sys.exit(1)


if __name__ == '__main__':
    # Catch Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    main()
