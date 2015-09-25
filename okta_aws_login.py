#!/usr/bin/env python
import argparse
import base64
import configparser
import getpass
import logging
import math
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

import boto3
import requests
from bs4 import BeautifulSoup

##########################################################################
# Args

parser = argparse.ArgumentParser(
    description = "Gets a STS token to use for aws CLI based"
                  " on a SAML assertion from Okta")
parser.add_argument(
    '--username', '-u',
    help = "The username to use when logging into Okta. The username can \
            also be set via the OKTA_USERNAME env variable. If not provided \
            you will be prompted to enter a username."
)

parser.add_argument(
    '--profile', '-p',
    help = "The name of the profile to use when storing the credentials in \
            the AWS credentials file. If not provided then the name of \
            the role assumed will be used as the profile name"
)

parser.add_argument(
    '--verbose', '-v',
    action = 'store_true',
    help = "If set will print a message about the creds that were set"
)


args = parser.parse_args()

##########################################################################

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

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://nimbusscale.okta.com/home/amazon_aws/0oa1zacnfpCCu09Uc0x7/272'

##########################################################################

def okta_login(username,password,idpentryurl):
    """Parses the idpentryurl and performs a login with the creds 
    provided by the user. Returns a requests.Response object"""
    # Initiate session handler
    session = requests.Session()
    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    formresponse = session.get(idpentryurl, verify=True)
    # Capture the idpauthformsubmiturl, 
    # which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url
    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text, "html.parser")
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
        idpauthformsubmiturl, params=payload, verify=True)
    # Check to see if the sign in failed, if so notify user and exit
    if "Sign in failed!" in response.text:
        print("Sign in failed!")
        sys.exit(1)
    return response

def get_saml_assertion(response):
    """Parses a requests.Response object that contains a SAML assertion.
    Returns an base64 encoded SAML Assertion"""
   # Decode the requests.Response object and extract the SAML assertion
    soup = BeautifulSoup(response.text, "html.parser")
    assertion = ''
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            assertion = inputtag.get('value')
    # Better error handling is required for production use.
    if (assertion == ''):
        print("Response did not contain a valid SAML assertion")
        sys.exit(1)
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

def write_aws_creds(configfile,profile,access_key,secret_key,token,
                    region,output):
    """ Writes the AWS STS token into the AWS credential file"""
    home = expanduser("~")
    filename = home + configfile
    # Read in the existing config file
    config = configparser.RawConfigParser()
    config.read(filename)
    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, 'output', output)
    config.set(profile, 'region', region)
    config.set(profile, 'aws_access_key_id', access_key)
    config.set(profile, 'aws_secret_access_key', secret_key)
    config.set(profile, 'aws_session_token', token)
    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)
    
def main():
    # Get the federated credentials for the user
    # Check to see if the username arg has been set, if so use that
    if args.username is not None:
        username = args.username
    # Next check to see if the OKTA_USERNAME env var is set
    elif os.environ.get("OKTA_USERNAME") is not None:
        username = os.environ.get("OKTA_USERNAME")
    # Otherwise just ask the user
    else:    
        print("Username: ")
        username = raw_input()
    
    # Set prompt to include the user name, since username could be set
    # via OKTA_USERNAME env and user might not remember.
    passwd_prompt = "Password for {}: ".format(username)
    password = getpass.getpass(prompt=passwd_prompt)
    if len(password) == 0:
        print( "Password must be provided")
        sys.exit(1)

    response = okta_login(username,password,idpentryurl)
    assertion = get_saml_assertion(response)
    saml_dict = get_arns_from_assertion(assertion) 
    creds = get_sts_token(saml_dict['RoleArn'],
                          saml_dict['PrincipalArn'],
                          saml_dict['SAMLAssertion'])
    # Get role name to use for the name of the profile
    # check if profile arg has been set
    if args.profile is not None:
        profile_name = args.profile
    # otherwise just set it to the name of the role 
    else:
        profile_name = saml_dict['RoleArn'].split('/')[1]
    write_aws_creds(awsconfigfile,
                    profile_name,
                    creds['AccessKeyId'],
                    creds['SecretAccessKey'],
                    creds['SessionToken'],
                    region,
                    outputformat)

    # Print message about creds if verbose is set
    if args.verbose == True:
        now = datetime.now(timezone.utc)
        valid_duration = creds['Expiration'] - now
        valid_minutes = math.ceil(valid_duration / timedelta(minutes=1)) 
        cred_details = ("Credentials for the profile {} have been set. "
                        "They will expire in {} minutes.".format(profile_name,
                        valid_minutes)) 
        print(cred_details)

if __name__ == '__main__':
    main()

