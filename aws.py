#!/usr/bin/env python
#encoding: UTF-8

import sys,os
import hmac
import hashlib
import requests
from urllib2 import quote as UriEncode
from datetime import datetime
import BeautifulSoup as bs
import json
from random import sample as sp

from config import *

def user_exists( username ):
	for line in file( userdb ):
		user = line.strip('\r\n').split(':')[0]
		if user == username: return True
	return False

def build_canonical_query_string( kwargs ):
	query = []
	sorted_keys = sorted( kwargs.keys() )
	for key in sorted_keys:
		subquery = UriEncode( str(key) ) + '=' + UriEncode( str(kwargs[key]) )
		query.append( subquery )
	return '&'.join( query ) if query != [] else  ''
	
def build_canonical_headers( kwargs ):
	header = []
	sorted_keys = sorted( kwargs.keys() )
	for key in sorted_keys:
		subheader = str(key).lower() + ':' + str( kwargs[key] ).strip()
		header.append( subheader )
	return '\n'.join( header ) + '\n' if header != [] else ''

def build_signed_headers( kwargs ):
	sorted_keys = sorted( kwargs.keys() )
	return ';'.join( sorted_keys )

def sign(key, msg, hex=False):
    return hmac.new(key,msg.encode("utf-8"),hashlib.sha256).digest() if not hex else hmac.new(key,msg.encode("utf-8"),hashlib.sha256).hexdigest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, "aws4_request")
    return kSigning
	
def get_timestamps():
	current_time = datetime.utcnow()
	return (current_time.strftime("%Y%m%d"),current_time.strftime("%Y%m%dT%H%M%SZ"))

def get_password():
	passwd_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789'
	return sp(passwd_chars,16)
	
def build_authorization_header( host, datestamp='',amzdate='', path='/', query={}, service=''  ):
	access_key = ''
	secret_key = ''
	if service == 's3':
		access_key = s3_access_key
		secret_key = s3_secret_key
	elif service == 'iam':
		access_key = iam_access_key
		secret_key = iam_secret_key

	HTTPMethod = 'GET'
	CanonicalURI = UriEncode(path)
	CanonicalQueryString = build_canonical_query_string( query )
	headers = {
			'host':host,
			'x-amz-content-sha256': hashlib.sha256(''.encode('utf-8')).hexdigest(),
			'x-amz-date':amzdate,
		}
	
	CanonicalHeaders = build_canonical_headers( headers )

	SignedHeaders = build_signed_headers( headers )

	HashedPayload = hashlib.sha256(''.encode('utf-8')).hexdigest()

	CanonicalRequest = '''GET
{CanonicalURI}
{CanonicalQueryString}
{CanonicalHeaders}
{SignedHeaders}
{HashedPayload}'''.format(
	CanonicalURI=CanonicalURI,
	CanonicalQueryString=CanonicalQueryString,
	CanonicalHeaders=CanonicalHeaders,
	SignedHeaders=SignedHeaders,
	HashedPayload=HashedPayload,
	)

	scope = '{datestamp}/{region}/{service}/aws4_request'.format(
		datestamp=datestamp,
		region=region,
		service=service,
	)

	StringToSign = '''AWS4-HMAC-SHA256
{timestamp}
{scope}
{hash_CanonicalRequest}'''.format(
		timestamp=amzdate,
		scope=scope,
		hash_CanonicalRequest=hashlib.sha256( CanonicalRequest.encode('utf-8') ).hexdigest()
	)

	#calculate signature
	SigningKey = getSignatureKey(
		secret_key,
		datestamp,
		region,
		service,
	)

	final_signature = sign(SigningKey,StringToSign,hex=True)

	authorization_header = 'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={SignedHeaders}, Signature={final_signature}'.format(
		access_key=access_key,
		scope=scope,
		SignedHeaders=SignedHeaders,
		final_signature=final_signature,
	)
	
	return authorization_header
	
def list_bucket(info=False):

	host = s3_host
	endpoint = 'https://' + host
	path = '/'
	query = {
		'list-type':'2',
	}
	
	datestamp,amzdate = get_timestamps()
	authorization_header = build_authorization_header( host, datestamp, amzdate, path, query, service='s3' )
	CanonicalQueryString = build_canonical_query_string( query )

	http_header = {
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}
	
	request_url = endpoint + '?' + CanonicalQueryString

	resp = requests.get(request_url,headers = http_header)
	page = bs.BeautifulSoup(resp.text)
	contents = page.findAll('contents')
	return [(content.key.text,content.lastmodified.text) for content in contents]

def get_object(objname):
	host = s3_host
	endpoint = 'https://' + host
	path = '/' + objname
	
	query = {}

	datestamp,amzdate = get_timestamps()
	authorization_header = build_authorization_header( host, datestamp, amzdate, path, query, service='s3' )
	CanonicalQueryString = build_canonical_query_string( query )
	
	http_header = {
		'date':datestamp,
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}
	
	request_url = endpoint + path
	
	resp = requests.get(request_url,headers = http_header)
	return resp.text

def create_new_user( username ):
	host = iam_host
	endpoint = 'https://' + host
	path = '/'
	
	query = {
		'Action':'CreateUser',
		'UserName':username,
		'Version':iam_version,
	}

	datestamp,amzdate = get_timestamps()
	authorization_header = build_authorization_header( host, datestamp, amzdate, path, query, service='iam' )
	CanonicalQueryString = build_canonical_query_string( query )
	
	http_header = {
		'date':datestamp,
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}
	
	request_url = endpoint + '?' + CanonicalQueryString
	
	resp = requests.get(request_url,headers = http_header)
	user_text = resp.text
	page = bs.BeautifulSoup(resp.text)
	userid = page.find('userid').text
	return userid
	
def create_login_profile( username ):
	host = iam_host
	endpoint = 'https://' + host
	path = '/'
	# change user password
	new_password = get_password()
	query = {
		'Action':'CreateLoginProfile',
		'UserName':username,
		'Password':new_password,
		'Version':iam_version,
	}
	
	datestamp,amzdate = get_timestamps()
	authorization_header = build_authorization_header( host, datestamp, amzdate, path, query, service='iam' )
	CanonicalQueryString = build_canonical_query_string( query )
	http_header = {
		'date':datestamp,
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}
	
	request_url = endpoint + '?' + CanonicalQueryString
	resp = requests.get(request_url,headers = http_header)
	return new_password
	
def create_access_key( username ):
	host = iam_host
	endpoint = 'https://' + host
	path = '/'
	# create access key
	query = {
		'Action':'CreateAccessKey',
		'UserName':username,
		'Version':iam_version,
	}
	
	datestamp,amzdate = get_timestamps()
	authorization_header = build_authorization_header( host, datestamp, amzdate, path, query, service='iam' )
	CanonicalQueryString = build_canonical_query_string( query )
	http_header = {
		'date':datestamp,
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}
	request_url = endpoint + '?' + CanonicalQueryString
	resp = requests.get(request_url,headers = http_header)
	page = bs.BeautifulSoup(resp.text)
	user_access_key = page.find('accesskeyid').text
	user_secret_key = page.find('secretaccesskey').text

	return user_access_key,user_secret_key

def create_user( username ):
	userid = create_new_user( username )
	access_key,secret_key = create_access_key( username )
	user_password = create_user_password( username )
	return userid,access_key,secret_key,user_password

def put_user_policy( username ):
	host = iam_host
	endpoint = 'https://' + host
	path = '/'
	policy = {
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "VisualEditor0",
				"Effect": "Allow",
				"Action": "ses:SendEmail",
				"Resource": "*"
			}
		]
	}
	query = {
		'Action':'PutUserPolicy',
		'UserName':username,
		'PolicyName':'sendmail',
		'PolicyDocument':json.dumps( policy ),
		'Version':iam_version,
	}
	datestamp,amzdate = get_timestamps()
	authorization_header = build_authorization_header( host, datestamp, amzdate, path, query, service='iam' )
	CanonicalQueryString = build_canonical_query_string( query )
	http_header = {
		'date':datestamp,
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}
	request_url = endpoint + '?' + CanonicalQueryString
	resp = requests.get(request_url,headers = http_header)
	return resp.text
