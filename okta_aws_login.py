#!/usr/bin/python

import sys
import boto3
import requests
import getpass
import ConfigParser
import base64
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse, urlunparse

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-west-2'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://nimbusscale.okta.com/home/amazon_aws/0oa1zacnfpCCu09Uc0x7/272'

# Uncomment to enable low level debugging
#logging.basicConfig(level=logging.DEBUG)

##########################################################################

def okta_login(username,password,idpentryurl,sslverification):
    """Parses the idpentryurl and performs a login with the creds 
    provided by the user. Returns a requests.Response object"""
    # Initiate session handler
    session = requests.Session()
    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    formresponse = session.get(idpentryurl, verify=sslverification)
    # Capture the idpauthformsubmiturl, 
    # which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url
    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text.decode('utf8'), "html5lib")
    payload = {}
    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        if "user" in name.lower():
            payload[name] = username
        elif "pass" in name.lower():
            payload[name] = password
        else:
            #Simply populate the parameter with the existing value
            #(picks up hidden fields in the login form)
            payload[name] = value
    # build the idpauthformsubmiturl by combining the scheme and hostname
    # from the entry url with the form action target
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        if action:
            parsedurl = urlparse(idpentryurl)
            idpauthformsubmiturl = "{scheme}://{netloc}{action}".format(
                                                scheme=parsedurl.scheme,
                                                netloc=parsedurl.netloc,
                                                action=action)
    # Performs the submission of the IdP login form with the above post data
    response = session.post(
        idpauthformsubmiturl, params=payload, verify=sslverification)
    return response

def get_saml_assertion(response):
    """Parses a requests.Response object that contains a SAML assertion.
    Returns an base64 encoded SAML Assertion"""
   # Decode the requests.Response object and extract the SAML assertion
    soup = BeautifulSoup(response.text.decode('utf8'), "html5lib")
    assertion = ''
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            #print(inputtag.get('value'))
            assertion = inputtag.get('value')
    # Better error handling is required for production use.
    if (assertion == ''):
        print 'Response did not contain a valid SAML assertion'
        sys.exit(0)
    return assertion

def get_arns_from_assertion(assertion):
    """Parses a base64 encoded SAML Assertion and extracts the role and 
    principle ARNs to be used when making a request to STS.
    Returns a dict with RoleArn, PrincipalArn & SAMLAssertion that can be 
    used to call assume_role_with_saml"""
    # Parse the returned assertion and extract the principle and role ARNs
    root = ET.fromstring(base64.b64decode(assertion))
    urn = "{urn:oasis:names:tc:SAML:2.0:assertion}"
    urn_attribute = urn + "Attribute"
    urn_attributevalue = urn + "AttributeValue"
    role_url = "https://aws.amazon.com/SAML/Attributes/Role"
    for saml2attribute in root.iter(urn_attribute):
        if (saml2attribute.get('Name') == role_url):
            for saml2attributevalue in saml2attribute.iter(urn_attributevalue):
                arns = saml2attributevalue.text
    # Create dict to be used to call assume_role_with_saml
    arn_dict = {}
    arn_dict['RoleArn'] = arns.split(',')[1]
    arn_dict['PrincipalArn'] = arns.split(',')[0]
    arn_dict['SAMLAssertion'] = assertion
    return arn_dict

def get_sts_token(RoleArn,PrincipalArn,SAMLAssertion):
    """Use the assertion to get an AWS STS token using Assume Role with SAML
    returns a Credentials dict with the keys and token"""
    sts_client = boto3.client('sts')
    response = sts_client.assume_role_with_saml(RoleArn=RoleArn,
                                                PrincipalArn=PrincipalArn,
                                                SAMLAssertion=SAMLAssertion)
    Credentials = response['Credentials']
    return Credentials

def write_aws_creds(configfile,access_key,secret_key,token,region,output):
    """ Writes the AWS STS token into the AWS credential file"""
    home = expanduser("~")
    filename = home + configfile
    # Read in the existing config file
    config = ConfigParser.RawConfigParser()
    config.read(filename)
    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section('saml'):
        config.add_section('saml')
    config.set('saml', 'output', output)
    config.set('saml', 'region', region)
    config.set('saml', 'aws_access_key_id', access_key)
    config.set('saml', 'aws_secret_access_key', secret_key)
    config.set('saml', 'aws_session_token', token)
    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)
    
def main():
    # Get the federated credentials from the user
    print "Username:",
    username = raw_input()
    password = getpass.getpass()
    print ''

    response = okta_login(username,password,idpentryurl,sslverification)
    assertion = get_saml_assertion(response)
    saml_dict = get_arns_from_assertion(assertion) 
    creds = get_sts_token(saml_dict['RoleArn'],
                          saml_dict['PrincipalArn'],
                          saml_dict['SAMLAssertion'])
    write_aws_creds(awsconfigfile,
                    creds['AccessKeyId'],
                    creds['SecretAccessKey'],
                    creds['SessionToken'],
                    region,
                    outputformat)

if __name__ == '__main__':
    main()

