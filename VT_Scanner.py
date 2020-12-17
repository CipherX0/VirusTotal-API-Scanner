#!/usr/bin/python
import requests
import time
import json
import validators

client = requests.session()
api_key = '' # <= Put Your API Key Here

print("=============================================")
print("========== WELCOME TO VT_SCANNER ============")
print("============= By: Ahmed_Farhat ==============")
print("=============================================\n")
print("<~~~~~~~> Choose Your Target Please <~~~~~~~>\n")

resource = input(str("IP_address(I), Domain(D), File_Hash(F), URL(U): ")).lower()
resource_list = ['d', 'f', 'u', 'i', 'h', 'domain', 'ip', 'ip_address', 'file', 'hash', 'file_hash', 'url']
if resource == 'd' or resource == 'domain':
    # Sending Targets To VirusTotal For scanning
    domains = open("domains.txt", "r")                                     ## make sure you have this file existing  ## you can change the file path as you wish
    for domain in domains:
        if validators.domain(domain) == True:
            url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': api_key, 'url': domain}
            response = client.post(url, params=params)
            if response.status_code == 200:
                json_response = response.json()
                time.sleep(15)                                             # <= this delay because the public API has only (4) requests/minute
                if json_response['response_code'] != 1:                             ## If You Have A Private API Key Change It To (1) ##
                    print('There was an error submitting your domain for scanning.')
                    print(json_response['verbose_msg'])
                else:
                    pass
            elif response.status_code == 204:
                print('You may have exceeded your API request quota, try again later.')
                break
            elif response.status_code == 403:
                print('Check Your API Key Please.')
                break
            #end_of_scanner and getting a fresh report
            def domain_report(domain):
                url = 'https://www.virustotal.com/vtapi/v2/url/report'
                params = {'apikey': api_key, 'resource': domain}
                response = client.post(url, params=params)
                time.sleep(15)
                if response.status_code == 200:
                    json_response = response.json()
                    if json_response['response_code'] == 1:
                        pass
                    else:
                        print('There was an error submitting your domain for scanning.')
                    positives = json_response['positives']
                    if positives == 0:
                        result = ' => Clean'
                    else:
                        result = ' => Malicious'                                # a single detection qualifies for malicious
                    print(domain.rstrip('\n') + result)
                elif response.status_code == 204:
                    print('You may have exceeded your API request quota, try again later.')
            domain_report(domain)
        else:
            if domain.rstrip('\n') == '':
                continue
            else:
                print(domain.rstrip('\n') + " => invalid\n")
#==========================================================================================#
# Sending Targets To VirusTotal For scanning
elif resource == 'i' or resource == 'ip' or resource == 'ip_address':
    ips = open("ips.txt", "r")                                                    ## make sure you have this file existing 
    for ip in ips:
        if validators.ipv4(ip.rstrip('\n')) == True:
            url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': api_key, 'url': ip}
            response = client.post(url, params=params)
            if response.status_code == 200:
                json_response = response.json()
                #print("=> Scanning... " + ip )
                time.sleep(15)                                                                # <= this delay because the public API has only (4) requests/minute
                if json_response['response_code'] != 1:                                               ## If You Have A Private API Key Change It To (1) ##
                    print('There was an error submitting the ip_address for scanning.')
                    print(json_response['verbose_msg'])
                else:
                    pass
            elif response.status_code == 204:
                print('You may have exceeded your API request quota, try again later.')
                break
            elif response.status_code == 403:
                print('Check Your API Key Please.')
                break
            #end_of_scanner and getting a fresh report
            def ip_report(ip):
                url = 'https://www.virustotal.com/vtapi/v2/url/report'
                params = {'apikey': api_key, 'resource': ip}
                response = client.post(url, params=params)
                time.sleep(15)
                if response.status_code == 200:
                    json_response = response.json()
                    if json_response['response_code'] == 1:
                        pass
                    else:
                        print('There was an error submitting the ip_address for scanning.')
                    positives = json_response['positives']
                    if positives == 0:
                        result = ' => Clean'
                    else:
                        result = ' => Malicious'                                   # a single detection qualifies for malicious
                    print(ip.rstrip('\n') + result)
                elif response.status_code == 204:
                    print('You may have exceeded your API request quota, try again later.')
            ip_report(ip)
        else:
            if ip.rstrip('\n') == '':
                continue
            else:
                print(ip.rstrip('\n') + " => invalid\n")
#==========================================================================================#
#hash_scan
elif resource == 'f' or resource == 'hash' or resource == 'file_hash' or resource == 'file' or resource == 'h':
    def hash_scanner():
        hashs = open("hashs.txt", "r")                                   ## make sure you have this file existing
        i = 0
        for Hash in hashs:
            i+=1
            if Hash.rstrip('\n') == '':
                i-=1
                continue
            while i%5 == 0:
                print("\n#### waiting because of quota limitation ####\n")                 # <= this delay because the public API has only (4) requests/minute
                time.sleep(60)                                                                   ## If You Have A Private API Key Change It To (1) ##                                                         
                i+=1
            else:
                if validators.md5(Hash) == True or validators.sha1(Hash) == True or validators.sha256(Hash) == True:
                    url = 'https://www.virustotal.com/vtapi/v2/file/report'
                    params = {'apikey': api_key, 'resource': Hash}
                    response = requests.get(url, params=params)
                    if response.status_code == 200:
                        json_response = response.json()
                        if json_response['response_code'] == 1:
                            pass
                        else:
                            print('There was an error submitting the File_Hash for scanning.')
                        positives = json_response['positives']
                        if positives == 0:
                            result = ' => Clean'
                        else:
                            result = ' => Malicious'                           # a single detection qualifies for malicious
                        print(Hash.rstrip('\n') + result.rstrip('\n')) 
                    elif response.status_code == 204:
                        print('You may have exceeded your API request quota, try again later.')
                        break
                    elif response.status_code == 403:
                        print('Check Your API Key Please.')
                        break
                else:                                                       # [Usage] Your Hash Must Be 32 or 40 or 64 Alpha Numeric characters.
                    print(Hash.rstrip('\n') + " => invalid\n")                
    hash_scanner()
#==========================================================================================#
#url_scan
elif resource == 'u' or resource == 'url':
    def urlScaner():
        urls = open("urls.txt", "r")                                      ## make sure you have this file existing
        i = 0
        for uri in urls:
            i+=1
            if uri.rstrip('\n') == '':
                i-=1
                continue
            while i%5 == 0:
                print("\n#### waiting because of quota limitation ####\n")                  # <= this delay because the public API has only (4) requests/minute
                time.sleep(60)                                                                    ## If You Have A Private API Key Change It To (1) ## 
                i+=1
            else:
                if validators.url(uri) == True:
                    url = 'https://www.virustotal.com/vtapi/v2/url/report'
                    params = {'apikey': api_key, 'resource' : uri}
                    response = requests.get(url, params=params)
                    if response.status_code == 200:
                        json_response = response.json()
                        if json_response['response_code'] == 1:
                            pass
                        else:
                            print('There was an error submitting the URL for scanning.')
                        positives = json_response['positives']
                        if positives == 0:
                            result = ' => Clean'
                        else:
                            result = ' => Malicious'                           # a single detection qualifies for malicious
                        print(uri.rstrip('\n') + result)
                    elif response.status_code == 204:
                        print('You may have exceeded your API request quota, try again later.')
                        break
                    elif response.status_code == 403:
                        print('Check Your API Key Please.')
                        break
                else:                                                   # [Example]  http[s]://www.example.com or http[s]://example.com
                    print(uri + " => invalid\n")
    urlScaner()
else:    
    resource = input(str("IP_address(I), Domain(D), File_Hash(F), URL(U) ")).lower()