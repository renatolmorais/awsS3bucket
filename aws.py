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

from config import *

endpoint = 'https://' + host

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
	return current_time.strftime("%Y%m%d"),current_time.strftime("%Y%m%dT%H%M%SZ")

def list_bucket():

	path = '/'
	query = {
		'list-type':'2',
	}
	
	datestamp,amzdate = get_timestamps()

	HTTPMethod = 'GET'
	CanonicalURI = UriEncode(path)
	#print 'CanonicalURI',CanonicalURI

	CanonicalQueryString = build_canonical_query_string( query )
	#print 'CanonicalQueryString',CanonicalQueryString
	request_url = endpoint + '?' + CanonicalQueryString

	headers = {
			'host':host,
			'x-amz-content-sha256': hashlib.sha256(''.encode('utf-8')).hexdigest(),
			'x-amz-date':amzdate,
		}

	CanonicalHeaders = build_canonical_headers( headers )
	#print 'CanonicalHeaders',CanonicalHeaders

	SignedHeaders = build_signed_headers( headers )
	#print 'SignedHeaders',SignedHeaders

	HashedPayload = hashlib.sha256(''.encode('utf-8')).hexdigest()
	#print 'HashedPayload',HashedPayload

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
	#print CanonicalRequest

	scope = '{datestamp}/{region}/{service}/aws4_request'.format(
		datestamp=datestamp,
		region=region,
		service=service,
	)
	#print 'scope',scope

	StringToSign = '''AWS4-HMAC-SHA256
{timestamp}
{scope}
{hash_CanonicalRequest}'''.format(
		timestamp=amzdate,
		scope=scope,
		hash_CanonicalRequest=hashlib.sha256( CanonicalRequest.encode('utf-8') ).hexdigest()
	)
	#print 'StringToSign',StringToSign

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

	http_header = {
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}

	resp = requests.get(request_url,headers = http_header)
	page = bs.BeautifulSoup(resp.text)

	keys = page.findAll('key')
	return [key.text for key in keys]

def get_object(objname):
	path = '/' + objname
	query = {}
	datestamp,amzdate = get_timestamps()
	headers = {
			'host':host,
			'x-amz-content-sha256': hashlib.sha256(''.encode('utf-8')).hexdigest(),
			'x-amz-date':amzdate,
		}
	
	CanonicalQueryString = build_canonical_query_string( query )
	SignedHeaders = build_signed_headers( headers )
	
	CanonicalRequest = '''GET
{CanonicalURI}
{CanonicalQueryString}
{CanonicalHeaders}
{SignedHeaders}
{HashedPayload}'''.format(
	CanonicalURI=UriEncode(path),
	CanonicalQueryString=CanonicalQueryString,
	CanonicalHeaders=build_canonical_headers( headers ),
	SignedHeaders=SignedHeaders,
	HashedPayload=hashlib.sha256(''.encode('utf-8')).hexdigest(),
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
	
	SigningKey = getSignatureKey( secret_key, datestamp, region, service )
	final_signature = sign(SigningKey,StringToSign,hex=True)
	
	authorization_header = 'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={SignedHeaders}, Signature={final_signature}'.format(
		access_key=access_key,
		scope=scope,
		SignedHeaders=SignedHeaders,
		final_signature=final_signature,
	)
	
	http_header = {
		'date':datestamp,
		'x-amz-date':amzdate,
		'x-amz-content-sha256':hashlib.sha256(''.encode('utf-8')).hexdigest(),
		'Authorization': authorization_header,
	}
	
	request_url = endpoint + path
	
	resp = requests.get(request_url,headers = http_header)
	return resp.text

if __name__ == '__main__':

	current_list = []
	if os.path.exists( filelistname ): current_list = json.load( file(filelistname) ).get('filelist',[])
#	if main_folder != '': os.chdir( main_folder )
	
	filelist = list_bucket()
	print 'found {0} files'.format(len(filelist))

	n_files = 0
	for filen in filelist:
		if filen in current_list: continue
		username,filename = filen.split('/')
		if not user_exists( username ): continue
		if maildir.format( username=username ) != '' and os.path.exists( maildir.format( username=username ) ): os.chdir( maildir.format( username=username ) )
		else: continue
		#if not os.path.exists(folder): os.mkdir(folder)
		if not os.path.exists( filename  + '.eml'):
			with open( filename + '.eml','wb') as fp:
				fp.write( get_object( filen ).encode( encoding ) )
				n_files += 1
				print '{filename} saved in {folder}.'.format(filename=filename,folder=maildir.format( username=username ))
	if n_files > 0:
		print 'saved {0} file(s)'.format(n_files)	
	else: print 'no file was saved'
	new_filelist = {'filelist': filelist,'n_files':len(filelist)}
	with open( filelistname, 'w' ) as fp: json.dump(new_filelist,fp)
