from base64 import b64decode, b64encode
import shodan
from threading import Thread
import subprocess
from matplotlib_venn import venn3
import matplotlib.pyplot as plt
import ipaddress
import os
import requests
import json
import re
from functools import reduce
from urllib.parse import quote
global uselessTimes
from urllib import request, parse
import sys
from censys.search import CensysHosts
# 
# from scripts import db as mydb
import datetime
record_db = '' # save records of device search engine

pattern_mongodb = '' # save patterns of device search engine
patternDB={}
for res in pattern_mongodb.find():
    patternName=res['patternName']
    patternDB[patternName]={
        "urlPattern": res['urlPattern'],
        "matchPattern": res['matchPattern'],
        "interactionMethod": res['interactionMethod'],
        "application": res['application'],
        "transportLayerProtocol": res['transportLayerProtocol'],
    }
    


global h, db, ip_leak_pattern, old_pattern_lists, censys_patterns, null_file_lists, all_valid_servers, all_records_sp

global key_count,key_valid_flag
key_count = 0
zoomeye_tokens = []
                
key_valid_flag = [1 for _ in range(len(zoomeye_tokens))]

fofa_token = ('', '')
SHODAN_API_KEY = ""
shodan_pattern = {  "MYSQL_v1": '"is not allowed to connect to" product:"MySQL"', "MYSQL_v2": '"is blocked because of many connection errors" product:"MySQL"',
                    "zookeeper": "zookeeper", "SIP": '"sip" "received"', "Redis": '"-ERR illegal address:"', "HTTP_v1": '"X-Request-Ip:"', "HTTP_v2": '"user_ip="',
                    "Tenor": '"Connected from IpAddr/Port"  "to Port"',
                    "HTTP_407": '"please add white ip"',
                    "HTTP_body1": '"cf-footer-ip"',
                    "HTTP_x_forwarded_for": 'X-forwarded-for',
                    "MS_SMTP_HELLO": 'product:"Microsoft Exchange smtpd" "hello"',
                    "HTTP_400_Node": '"Node information:" "400 Bad Request" "Request-Id" "IP:" "Error Times"',
                    "HTTP_400_WatchGuard": '"Please contact your administrator for assistance" "400 Bad request"',
                    "ZXFS_FTP": '"ZXFS Ftp Server"',
                    'ESMTP_HELLO': '"ESMTP Exim" "Hello"',
                    "ESMTP_MailEnable": '"ESMTP MailEnable Service"  "this server offers "',
                    "SMTP_PTR": '"No valid PTR for"',
                    "HTTP_X_Real_IP": "X-Real-IP",
                    "SMTP_Client_Reject": '"Client host rejected: Access denied"',
                    'SMTP_NOT_ACCEPT':'"does not accept mail from you"',
                    'ESMTP_Connection':'"Connection from" "ESMTP"',
                    'HTTP_Proxy_IP':'"Server: Proxy" "IP Address" "Auth Result"',
                    'HTTP_SRC_IP':'"Set-Cookie: <srcip>="',
                    'HTTP_client_ip':'"client-ip"',
                    'HTTP_CIP':'"CIP"',
                    'HTTP_Login_IP':'"Loginip"',
                    'HTTP_Header_SIP':'"Sia: SIP/2.0/"',
                    'HTTP_Header_Access_Deny':'"403 Access denied for"',
                    'HTTP_DSC_REAL_IP':'"dsc_real_ip="',
                    'HTTP_BD_IP':'"bd_ip="',
                    'HTTP_Remote_Addr':'"Remote_addr"',
                    'HTTP_CDN_User_IP':'"Cdn-User-Ip"',
                    'HTTP_Xhs-Real-Ip':'"Xhs-Real-Ip"',
                    'HTTP_Remote_Ip':'"Remote-Ip"',
                    'HTTP_X_Remote_Addr':'"X-Remote-Addr"',
                    'http_tc_web_cookies':'"tc_web_cookies_1"',
                    'http_snkz':'"snkz="',
                    'http_ip_address':'"ip_address="',
                    'http_client_address':'"Client-Address"',
                    'http_source_ip':'"Source_ip"',
                    'http_kt_ips':'"kt_ips="',
                    'http_X-Remote-Ip':'"X-Remote-Ip"',
                    'HTTP-X-Rate-Limit-Request-Remote-Addr':'"X-Rate-Limit-Request-Remote-Addr"',
                    'HTTP-Api-User-Ip':'"Api-User-Ip"',
                    'HTTP_Wx-Client':'"Wx-Client: mainland|cn|"',
                    'http_real_ipd':'"real_ipd="',
                    'http_yhip':'"yhip="',
                    'HTTP_X_Source_Ip':'"X-Source-Ip"',
                    'http-x-response-cinfo':'"X-Response-Cinfo"',
                    'http-x-your-address-is':'"X-Your-Address-Is"',
                    'http-x-wbx-about':'"X-Wbx-About"'
                    
                  }

fofa_pattern = {
    "SIP": 'cHJvdG9jb2w9InNpcCIgJiYgYmFubmVyPSJyZWNlaXZlZCI=',
    "zookeeper": 'cHJvdG9jb2w9Inpvb2tlZXBlciI=',
    "MYSQL_v1": 'cHJvdG9jb2w9Im15c3FsIiAmJiBiYW5uZXI9ImlzIG5vdCBhbGxvd2VkIHRvIGNvbm5lY3QgdG8i',
    "MYSQL_v2": 'cHJvdG9jb2w9Im15c3FsIiAmJiBiYW5uZXI9ImlzIGJsb2NrZWQgYmVjYXVzZSBvZiBtYW55IGNvbm5lY3Rpb24gZXJyb3JzIg==',
    "HTTP_v1": "IngtcmVxdWVzdC1pcCI=",  # "x-request-ip"
    # "user_ip=" && ("Set-Cookie" || "Location")
    "HTTP_v2": "InVzZXJfaXA9IiAmJiAoIlNldC1Db29raWUiIHx8ICJMb2NhdGlvbiIp",
    # ("Set-Cookie") && "user_ip" && banner!="user_ip=*"
    "HTTP_v4": "KCJTZXQtQ29va2llIikgJiYgInVzZXJfaXAiICYmIGJhbm5lciE9InVzZXJfaXA9KiI=",
    # header="Location" && header="user_ip" && banner!="user_ip=*"
    "HTTP_v5": "aGVhZGVyPSJMb2NhdGlvbiIgJiYgaGVhZGVyPSJ1c2VyX2lwIiAmJiBiYW5uZXIhPSJ1c2VyX2lwPSoi",
    "Redis": "Ii1FUlIgaWxsZWdhbCBhZGRyZXNzOiI=",  # "-ERR illegal address:"
    "HTTP_v6": "aGVhZGVyPSJ1c2VyX2lwIg==",       # header="user_ip"
    "HTTP_v7": "aGVhZGVyPSJYLVJlcXVlc3QtSXAi",    # header="X-Request-Ip"
    # "Connected from IpAddr/Port" && "to Port"
    "Tenor": 'IkNvbm5lY3RlZCBmcm9tIElwQWRkci9Qb3J0IiYmICJ0byBQb3J0Ig%3D%3D',
    "HTTP_407": "YmFubmVyPSJwbGVhc2UgYWRkIHdoaXRlIGlwIg%3D%3D",   # "please add white ip"
    "HTTP_x_forwarded_for": "aGVhZGVyPSJYLUZvcndhcmRlZC1Gb3I6ICIgJiYgaGVhZGVyIT0iVmFyeSIgJiYgaGVhZGVyIT0iQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVyIiAmJiBoZWFkZXIhPSJBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzIiAmJiBoZWFkZXIhPSJYLUZvcndhcmRlZC1Gb3I6IChudWxsKSI%3D",   # "please add white ip"
    # protocol="smtp" && banner!="192.168" && banner="hello" && product="Microsoft-Exchange" && banner!="10."
    "MS_SMTP_HELLO": "cHJvdG9jb2w9InNtdHAiICYmIGJhbm5lciE9IjE5Mi4xNjgiICYmIGJhbm5lcj0iaGVsbG8iICYmIHByb2R1Y3Q9Ik1pY3Jvc29mdC1FeGNoYW5nZSIgJiYgYmFubmVyIT0iMTAuIg%3D%3D",

    "HTTP_400_Node": 'YmFubmVyPSJOb2RlIGluZm9ybWF0aW9uOiIgJiYgYmFubmVyPSI0MDAgQmFkIFJlcXVlc3QiICYmIGJhbm5lcj0iUmVxdWVzdC1JZCIgJiYgYmFubmVyPSJJUDoiICYmIGJhbm5lcj0iRXJyb3IgVGltZXMi',
    "HTTP_400_WatchGuard": 'YmFubmVyPSJQbGVhc2UgY29udGFjdCB5b3VyIGFkbWluaXN0cmF0b3IgZm9yIGFzc2lzdGFuY2UiICYmIGJhbm5lcj0iUmVxdWVzdCBkZW5pZWQgYnkgV2F0Y2hHdWFyZCBIVFRQIFByb3h5IitiYW5uZXI6Ikhvc3Q6Ig%3D%3D',
    "ZXFS_FTP": 'YmFubmVyPSJaWEZTIEZ0cCBTZXJ2ZXIi',
    "ESMTP_HELLO": 'YmFubmVyPSJFU01UUCBFeGltIiAmJiBiYW5uZXI9IkhlbGxvIiAmJiBiYW5uZXIhPSIxOTIuMTY4IiAmJiBiYW5uZXIhPSIxMC4iICYmIGJhbm5lciE9IjE3Mi4xNiIgJiYgYmFubmVyIT0iMTcyLjMxIg%3D%3D',
    "ESMTP_MailEnable": 'YmFubmVyPSJFU01UUCBNYWlsRW5hYmxlIFNlcnZpY2UiICYmIGJhbm5lcj0idGhpcyBzZXJ2ZXIgb2ZmZXJzICIgJiYgYmFubmVyPSIyNTAtaG9tZSImJiBiYW5uZXIhPSIxMjcuMCIgJiYgYmFubmVyIT0iMTkyLjE2OCIgJiYgYmFubmVyIT0iMTAuIiAmJiBiYW5uZXIhPSIxNzIuMTYiICYmIGJhbm5lciE9IjE3Mi4zMSI%3D',
    "SMTP_PTR": 'YmFubmVyPSJObyB2YWxpZCBQVFIgZm9yIg%3D%3D',
    # header="X-Real-IP" && header!="Vary" && header!="127.0.0.1" && header!="192.168" && header!="10." && header!="172.16" && header!="172.31" && header!="Access-Control-Allow-Headers"
    "HTTP_X_Real_IP": 'aGVhZGVyPSJYLVJlYWwtSVAiICYmICBoZWFkZXIhPSJWYXJ5IiAmJiAgaGVhZGVyIT0iQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyI%3D',
    "SMTP_Client_Reject": 'IkNsaWVudCBob3N0IHJlamVjdGVkOiBBY2Nlc3MgZGVuaWVkIg%3D%3D',
    'SMTP_NOT_ACCEPT':'YmFubmVyPSJkb2VzIG5vdCBhY2NlcHQgbWFpbCBmcm9tIHlvdSI%3D',
    'ESMTP_Connection':'YmFubmVyPSJDb25uZWN0aW9uIGZyb20iICYmIGJhbm5lcj0iRVNNVFAi',
    'HTTP_Proxy_IP':'YmFubmVyPSJTZXJ2ZXI6IFByb3h5IiAmJiBiYW5uZXI9IklQIEFkZHJlc3MiICYmIGJhbm5lcj0iQXV0aCBSZXN1bHQiIA%3D%3D',
    'HTTP_SRC_IP':'YmFubmVyPSJTZXQtQ29va2llOiA8c3JjaXA%2BPSI%3D',
    'HTTP_client_ip':'aGVhZGVyPSJjbGllbnQtaXAi',
    'HTTP_CIP':'aGVhZGVyPSJjaXAi',
    'HTTP_Login_IP':'aGVhZGVyPSJMb2dpbmlwIg%3D%3D',
    'HTTP_Header_SIP':'aGVhZGVyPSJTaWE6IFNJUC8yLjAi',
    'HTTP_Header_Access_Deny':'aGVhZGVyPSJBY2Nlc3MgZGVuaWVkIGZvciI%3D',
    'HTTP_DSC_REAL_IP':'aGVhZGVyPSJkc2NfcmVhbF9pcD0i',
    'HTTP_BD_IP':'aGVhZGVyPSJiZF9pcD0i',
    'HTTP_Remote_Addr':'aGVhZGVyPSJSZW1vdGVfYWRkcjoiICYmIGhlYWRlciE9IlgtUmVhbC1JcCIgJiYgaGVhZGVyIT0iWC1Gb3J3YXJkZWQtRm9yIiAmJiBoZWFkZXIhPSIxNzIuIg%3D%3D',
    'HTTP_CDN_User_IP':'aGVhZGVyPSJDZG4tVXNlci1JcCI%3D',
    'HTTP_Xhs-Real-Ip':'aGVhZGVyPSJYaHMtUmVhbC1JcCI%3D',
    'HTTP_Remote_Ip':'aGVhZGVyPSJSZW1vdGUtSXAi',
    'HTTP_X_Remote_Addr':'aGVhZGVyPSJYLVJlbW90ZS1BZGRyIg%3D%3D',
    'http_tc_web_cookies':'aGVhZGVyPSIgdGNfd2ViX2Nvb2tpZXNfMT0i',
    'http_snkz':'aGVhZGVyPSJzbmt6PSI%3D',
    'http_ip_address':'aGVhZGVyPSJpcF9hZGRyZXNzPSI%3D',
    'http_client_address':'aGVhZGVyPSJDbGllbnQtQWRkcmVzcyI%3D',
    'http_source_ip':'aGVhZGVyPSJTb3VyY2VfaXAi',
    'http_X-Ms-Forbidden-Ip':'aGVhZGVyPSJYLU1zLUZvcmJpZGRlbi1JcCI%3D',
    'http_kt_ips':'aGVhZGVyPSJrdF9pcHM9Ig%3D%3D',
    'http_X-Remote-Ip':'aGVhZGVyPSJYLVJlbW90ZS1JcDoi',
    'http_flowIp':'aGVhZGVyPSJmbG93SXA9Ig%3D%3D',
    'HTTP-X-Rate-Limit-Request-Remote-Addr':'aGVhZGVyPSJYLVJhdGUtTGltaXQtUmVxdWVzdC1SZW1vdGUtQWRkciI%3D',
    'HTTP-Api-User-Ip':'aGVhZGVyPSJBcGktVXNlci1JcCIgJiYgaGVhZGVyIT0iQ2RuLVVzZXItSXAi',
    'HTTP_Wx-Client':'aGVhZGVyPSJXeC1DbGllbnQ6IG1haW5sYW5kIg%3D%3D',
    'http_real_ipd':'aGVhZGVyPSJyZWFsX2lwZD0iICYmIGhlYWRlciE9ImRzY19yZWFsX2lwIg%3D%3D',
    'http_yhip':'aGVhZGVyPSJ5aGlwPSI%3D',
    'HTTP_X_Source_Ip':'aGVhZGVyPSJYLVNvdXJjZS1JcCIgJiYgaGVhZGVyIT0iQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyI%3D',
    'http-x-response-cinfo':'aGVhZGVyPSJYLVJlc3BvbnNlLUNpbmZvIiAmJiBoZWFkZXIhPSJYLVJlcXVlc3QtSXAi',
    'http-x-your-address-is':'aGVhZGVyPSJYLVlvdXItQWRkcmVzcy1JcyI%3D',
    'http-x-wbx-about':'aGVhZGVyPSJYLVdieC1BYm91dCI%3D'
    # "Client host rejected: Access denied"
    # header="X-Real-IP" && header!="Vary" && header!="Access-Control-Allow-Headers"
    # banner="Node information:" && banner="400 Bad Request" && banner="Request-Id" && banner="IP:" && banner="Error Times"
    # "HTTP_v2":'YmFubmVyPSJ1c2VyX2lwPTE1MiIgfHwgYmFubmVyPSJ1c2VyX2lwPTE4NSI=',
    # "HTTP_v3":'InVzZXJfaXA9MTA2Ig=='
    # "user_ip=" && ("Set-Cookie" || "Location") ---> "InVzZXJfaXA9IiAmJiAoIlNldC1Db29raWUiIHx8ICJMb2NhdGlvbiIp"
    # "x-request-ip"---> "IngtcmVxdWVzdC1pcCI="
    # "-ERR illegal address:" --> Ii1FUlIgaWxsZWdhbCBhZGRyZXNzOiI=
    # ("Set-Cookie") && "user_ip" && banner!="user_ip=*" --> KCJTZXQtQ29va2llIikgJiYgInVzZXJfaXAiICYmIGJhbm5lciE9InVzZXJfaXA9KiI=
}

zoomeye_pattern = {
    "SIP": 'https://api.zoomeye.org/host/search?query=service%3A"SIP"%2Bbanner%3A"received"-banner%3A"xxx.xxx.xxx.xxx"',
    "zookeeper": 'https://api.zoomeye.org/host/search?query=app%3A"zookeeper"',
    "MYSQL_v1": 'https://api.zoomeye.org/host/search?query=app%3A"MySQL"%2Bbanner%3A"is%20not%20allowed%20to%20connect%20to"-banner%3A"xxx.xxx.xxx.xxx"',
    "MYSQL_v2": 'https://api.zoomeye.org/host/search?query=app%3A"MySQL"%2Bbanner%3A"is%20blocked%20because%20of%20many%20connection"-banner%3A"xxx.xxx.xxx.xxx"',
    "HTTP_v1": 'https://api.zoomeye.org/host/search?query=banner%3A"X-Request-Ip%3A"-banner%3A"xxx.xxx.xxx.xxx"',
    # "HTTP_v2":'https://api.zoomeye.org/host/search?query=banner%3A"user_ip%3D118"%20banner%3A"user_ip%3D103"'
    "HTTP_v2": 'https://api.zoomeye.org/host/search?query=banner%3A"user_ip%3D"-banner%3A"xxx.xxx.xxx.xxx"%2B(banner%3A"Location%3A"%20banner%3A"Set-Cookie%3A")',
    "Tenor": 'https://api.zoomeye.org/host/search?query=banner%3A"Connected%20from%20IpAddr%2FPort"%2Bbanner%3A"to%20Port"-banner%3A"xxx.xxx.xxx.xxx"',
    "HTTP_407": 'https://api.zoomeye.org/host/search?query=banner%3A"please%20add%20white%20ip"%20-banner%3A"xxx.xxx.xxx.xxx"',
    "HTTP_body1": 'https://api.zoomeye.org/host/search?query=%27<span%20class%3D"hidden"%20id%3D"cf-footer-ip">%27%2Bbanner%3A"Your%20IP%3A"%20%2Bcountry%3A"CN"-banner%3A"xxx.xxx.xxx.xxx"',
    "HTTP_x_forwarded_for": 'https://api.zoomeye.org/host/search?query=banner%3A"X-forwarded-for"-banner%3A"Vary"-banner%3A"Access-Control-Allow-Header"-banner%3A"Access-Control-Allow-Headers"-banner%3A"The%20X-Forwarded-For%20header"-banner%3A"HEADER_X_FORWARDED_FOR"-banner%3A"xxx.xxx.xxx.xxx"-banner%3A"header1%3A%20X-Forwarded-For"',
    # 'banner:"Microsoft ESMTP MAIL" +banner:"hello"-banner:"xxx.xxx.xxx.xxx"-banner:"192.168"'
    "MS_SMTP_HELLO": 'https://api.zoomeye.org/host/search?query=banner%3A"Microsoft%20ESMTP%20MAIL"%20%2Bbanner%3A"hello"-banner%3A"xxx.xxx.xxx.xxx"-banner%3A"192.168"&t=v4',

    # 'banner:"Node information:" +banner:"400 Bad Request" +banner:"Request-Id" +banner:"IP:" +banner:"Error Times" -banner:"xxx.xxx.xxx.xxx"'
    "HTTP_400_Node": 'https://api.zoomeye.org/host/search?query=banner%3A"Node%20information%3A"%20%2Bbanner%3A"400%20Bad%20Request"%20%2Bbanner%3A"Request-Id"%20%2Bbanner%3A"IP%3A"%20%2Bbanner%3A"Error%20Times"%20-banner%3A"xxx.xxx.xxx.xxx"&t=v4',

    "HTTP_400_WatchGuard": 'https://api.zoomeye.org/host/search?query=banner%3A"Please%20contact%20your%20administrator%20for%20assistance"%2Bbanner%3A"Request%20denied%20by%20WatchGuard%20HTTP%20Proxy"%2Bbanner%3A"400%20Bad%20request"-banner%3A"xxx.xxx.xxx.xxx"%2Bbanner%3A"Host%3A"-banner%3A"127.0.0.1"&t=v4',

    "ZXFS_FTP": 'https://api.zoomeye.org/host/search?query=banner%3A"ZXFS%20Ftp%20Server"-banner%3A"xxx.xxx.xxx.xxx"%20%2Bbanner%3A"your%20ip%20is"',
    "ESMTP_HELLO": 'https://api.zoomeye.org/host/search?query=banner%3A"hello"-banner%3A"xxx.xxx.xxx.xxx"%20%2Bapp%3A"Exim%20smtpd"-banner%3A"127.0"-banner%3A"192.168"-banner%3A"10.0"-banner%3A"172.16"-banner%3A"172.31"%20%2Bafter:"2023-01-01"%20%2Bbefore:"2024-01-01"&t=v4',
    "ESMTP_MailEnable": 'https://api.zoomeye.org/host/search?query=banner%3A"ESMTP%20MailEnable%20Service"%2Bbanner%3A"250-home"-banner%3A"xxx.xxx.xxx.xxx"-banner%3A"192.168"-banner%3A"10."-banner%3A"172.16"-banner%3A"172.31"-banner%3A"127.0.0.1"&t=v4',
    "SMTP_PTR": 'https://api.zoomeye.org/host/search?query=banner%3A"No%20valid%20PTR%20for"',
    "HTTP_X_Real_IP": 'https://api.zoomeye.org/host/search?query=banner%3A%20"X-real-ip"%20%20-banner%3A"Vary%3A"-banner%3A"Access-Control-Allow-Headers%3A"',
    "SMTP_Client_Reject": 'https://api.zoomeye.org/host/search?query=banner%3A"Client%20host%20rejected%3A%20Access%20denied"',
    
    'SMTP_NOT_ACCEPT':'https://api.zoomeye.org/host/search?query=banner%3A%22does%20not%20accept%20mail%20from%20you%22',
    # 'ESMTP_Logging':'https://api.zoomeye.org/host/search?query=banner%3A%22%20ESMTP%20Sendmail%22%20%2Bbanner%3A%22logging%20access%20from%22',
    'ESMTP_Connection':'https://api.zoomeye.org/host/search?query=banner%3A%22Connection%20from%22%20%2Bbanner%3A%22ESMTP%22',
    'HTTP_Proxy_IP':'https://api.zoomeye.org/host/search?query=banner%3A%22Server%3A%20Proxy%22%20%2Bbanner%3A%22IP%20Address%22',
    'HTTP_BLOCK_IP':'https://api.zoomeye.org/host/search?query=banner%3A"Your%20blocked%20IP%20address%20is"',
    'HTTP_Header_SIP':'https://api.zoomeye.org/host/search?query=banner%3A"Sia%3A%20SIP%2F2.0%2F"',
    'HTTP_Header_Access_Deny':'https://api.zoomeye.org/host/search?query=banner%3A"Access%20denied%20for"',
    'HTTP_DSC_REAL_IP':'https://api.zoomeye.org/host/search?query=banner%3A"dsc_real_ip%3D"',
    'http-x-response-cinfo':'https://api.zoomeye.org/host/search?query=banner%3A"X-Response-Cinfo"',
    'http-x-your-address-is':'https://api.zoomeye.org/host/search?query=banner%3A"X-Your-Address-Is"',
    'HTTP-X-Rate-Limit-Request-Remote-Addr':'https://api.zoomeye.org/host/search?query=banner%3A"X-Rate-Limit-Request-Remote-Addr"',
    'HTTP_CIP':'https://api.zoomeye.org/host/search?query=banner%3A"CIP%3A"',
    'HTTP_Login_IP':'https://api.zoomeye.org/host/search?query=banner%3A"Loginip"',
    'HTTP_Remote_Addr':'https://api.zoomeye.org/host/search?query=banner%3A"Remote_addr%3A"',
    'HTTP_X_Source_Ip':'https://api.zoomeye.org/host/search?query=banner%3A"X-Source-Ip%3A"%20-banner%3A"Access-Control-Allow-Headers"',
    'http_source_ip':'https://api.zoomeye.org/host/search?query=banner%3A"Source_ip%3A"',
    'http_client_address':'https://api.zoomeye.org/host/search?query=banner%3A"Client-Address%3A"',
    'http_yhip':'https://api.zoomeye.org/host/search?query=banner%3A"yhip%3D"',
    'http_real_ipd':'https://api.zoomeye.org/host/search?query=banner%3A"real_ipd%3D"',
    'HTTP-Api-User-Ip':'https://api.zoomeye.org/host/search?query=banner%3A"Api-User-Ip%3A"',
    'HTTP_Wx-Client':'https://api.zoomeye.org/host/search?query=banner%3A"Wx-Client: mainland|cn|"',
    'http_X-Remote-Ip':'https://api.zoomeye.org/host/search?query=banner%3A"X-Remote-Ip%3A"',
    'http_kt_ips':'https://api.zoomeye.org/host/search?query=banner%3A"kt_ips%3D"',
    'http_ip_address':'https://api.zoomeye.org/host/search?query=banner%3A"ip_address%3D"',
    'http_snkz':'https://api.zoomeye.org/host/search?query=banner%3A"snkz%3D"',
    'http_tc_web_cookies':'https://api.zoomeye.org/host/search?query=banner%3A"tc_web_cookies_1"',
    'HTTP_X_Remote_Addr':'https://api.zoomeye.org/host/search?query=banner%3A"X-Remote-Addr%3A"',
    'HTTP_Remote_Ip':'https://api.zoomeye.org/host/search?query=banner%3A"Remote-Ip%3A"',
    'HTTP_Xhs-Real-Ip':'https://api.zoomeye.org/host/search?query=banner%3A"Xhs-Real-Ip%3A"',
    'HTTP_CDN_User_IP':'https://api.zoomeye.org/host/search?query=banner%3A"Cdn-User-Ip%3A"',
    'HTTP_BD_IP':'https://api.zoomeye.org/host/search?query=banner%3A"bd_ip%3D"',
    'HTTP_client_ip':'https://api.zoomeye.org/host/search?query=banner%3A"client-ip"',
    'http-x-wbx-about':'https://api.zoomeye.org/host/search?query=banner%3A"X-Wbx-About"',
    'HTTP_SRC_IP':'https://api.zoomeye.org/host/search?query=banner%3A"Set-Cookie%3A%20<srcip>%3D"'

}   

enginePattern = {
    "shodan": shodan_pattern,
    "fofa": fofa_pattern,
    "zoomeye": zoomeye_pattern
}


def paddingPattern(engine: str, queryPattern: str):
    if engine == "zoomeye":
        queryPattern = queryPattern + '%2Bafter%3A"2023-01-01"%20%2Dbanner%3A"127.0.0.1"%2Dbanner%3A"172.16"%2Dbanner%3A"172.31"%2Dbanner%3A"10.0"%2Dbanner%3A"192.168"%20%2Dbanner%3A"xxx.xxx.xxx.xxx"&t=v4'
    elif engine == 'shodan':
        queryPattern = queryPattern + ' after:1/1/2023 has_ipv6:false'
    elif engine == 'fofa':
        # print(queryPattern)
        queryPattern=parse.unquote(queryPattern)
        # queryPattern = queryPattern.replace('%3D', '=')
        raw_pattern = b64decode(queryPattern.encode()).decode()
        if 'header' in raw_pattern:
            raw_pattern += '&& header!="127.0.0.1" && header!="172.16" && header!="172.31" && header!="10." && header!="192.168" && after="2023" && is_ipv6=false'
        else:
            raw_pattern += '&& banner!="127.0.0.1" && banner!="172.16" && banner!="172.31" && banner!="10." && banner!="192.168" && after="2023" && is_ipv6=false'
        queryPattern = b64encode(raw_pattern.encode()).decode()
        # queryPattern = queryPattern.replace('=', '%3D')
        queryPattern=parse.quote(queryPattern)
    return queryPattern

def paddingPatternImproved(engine: str, queryPattern: str):
    if engine == "zoomeye":
        queryPattern = queryPattern + '+ after:"2023-01-01" -banner:"127.0.0.1"-banner:"172.16"-banner:"172.31"-banner:"10."-banner:"192.168" -banner:"xxx.xxx.xxx.xxx"'
    elif engine == 'shodan':
        queryPattern = queryPattern + ' after:1/1/2023 has_ipv6:false'
    elif engine == 'fofa':
        # print(queryPattern)
        # queryPattern=parse.unquote(queryPattern)
        # queryPattern = queryPattern.replace('%3D', '=')
        # raw_pattern = b64decode(queryPattern.encode()).decode()
        raw_pattern = queryPattern
        if 'header' in raw_pattern:
            raw_pattern += '&& header!="127.0.0.1" && header!="172.16" && header!="172.31" && header!="10." && header!="192.168" && after="2023" && is_ipv6=false'
        else:
            raw_pattern += '&& banner!="127.0.0.1" && banner!="172.16" && banner!="172.31" && banner!="10." && banner!="192.168" && after="2023" && is_ipv6=false'
        queryPattern = b64encode(raw_pattern.encode()).decode()
        # queryPattern = queryPattern.replace('=', '%3D')
        queryPattern=parse.quote(queryPattern)
    return queryPattern



def is_ipv4_address(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def is_public_ip(address):
    try:
        ip = ipaddress.IPv4Address(address)
        if ip.is_private or ip.is_reserved or ip.is_loopback:
            return False
        return True
    except ipaddress.AddressValueError:
        return False


leak_patterns = {
    'sip': ['received=([\d\.]+)'],
    'mysql': ["Host '([\d\.]+)' is not allowed to connect to", "Host '([\d\.]+)' is blocked because of many connection errors"],
    'zookeeper': ["([\d\.]+):\d+\[0\]\(queued="],
    'redis': ["-ERR illegal address: ([\d\.]+)"],
    'http': ['user_ip=([\d\.]+)', "x-request-ip: ([\d\.]+)", "please add white ip ([\d\.]+)", '\\"cf-footer-ip\\">([\d\.]+)', 'X-Forwarded-For: ([\d\.]+)', 'IP: ([\d\.]+)', 'Host:</b> ([\d\.]+)'],
    'tenor': ["IpAddr/Port# ([\d\.]+)"],
    'smtp': ['Hello \[([\d\.]+)\]', '\[([\d\.]+)\]', 'home \[([\d\.]+)\]', 'No valid PTR for ([\d\.]+)\.in'],
    'ftp': ['your ip is ([\d\.]+)']
}


patternName2protocol = {
    "SMTP_PTR": "smtp",
    "ESMTP_MailEnable": "smtp",
    "ESMTP_HELLO": "smtp",
    "MS_SMTP_HELLO": "smtp",
    "ZXFS_FTP": "ftp",
    "HTTP_400_Node": "http",
    "HTTP_400_WatchGuard": "http",
    "HTTP_x_forwarded_for": "http",
    "HTTP_body1": "http",
    "HTTP_407": "http",
    "Tenor": 'tenor',
    "zookeeper": 'zookeeper',
    "MYSQL_v1": 'mysql',
    "MYSQL_v2": 'mysql',
    'SMTP_Client_Reject': 'smtp',
    'HTTP_X_Real_IP': 'http',
    "SIP": 'sip',
    "HTTP_Proxy_IP":'http',
    "ESMTP_Connection":'smtp',
    "SMTP_NOT_ACCEPT":'smtp',
    'HTTP_Remote_Addr':'http',
    'HTTP_BD_IP':'http',
    'HTTP_DSC_REAL_IP':'http',
    'HTTP_Header_Access_Deny':'http',
    'HTTP_Header_SIP':'http',
    'HTTP_Login_IP':'http',
    'HTTP_CIP':'http',
    'HTTP_client_ip':'http',
    'HTTP_SRC_IP':'http',
    'http-x-wbx-about':'http',
    'http-x-your-address-is':'http',
    'http-x-response-cinfo':'http',
    'HTTP_X_Source_Ip':'http',
    'http_yhip':'http',
    'http_real_ipd':'http',
    'HTTP_Wx-Client':'http',
    'HTTP-Api-User-Ip':'http',
    'HTTP-X-Rate-Limit-Request-Remote-Addr':'http',
    'http_flowIp':'http',
    'http_X-Remote-Ip':'http',
    'http_kt_ips':'http',
    'http_X-Ms-Forbidden-Ip':'http',
    'http_source_ip':'http',
    'http_client_address':'http',
    'http_ip_address':'http',
    'http_snkz':'http',
    'http_tc_web_cookies':'http',
    'HTTP_X_Remote_Addr':'http',
    'HTTP_Remote_Ip':'http',
    'HTTP_Xhs-Real-Ip':'http',
    'HTTP_CDN_User_IP':'http',
    'HTTP_Remote_Addr':'http',
}


def get_pattern_by_name(patternName: str):
    Name = patternName
    pattern = None
    if Name == 'SIP':
        pattern = 'received=([\d\.]+)'
    elif Name == "MYSQL_v2":
        pattern = "Host '([\d\.]+)' is blocked because of many connection errors"
    elif Name == "MYSQL_v1":
        pattern = "Host '([\d\.]+)' is not allowed to connect to"
    elif Name == 'zookeeper':
        pattern = "([\d\.]+):\d+\[0\]\(queued="
    elif Name == 'Redis':
        pattern = "-ERR illegal address: ([\d\.]+)"
    elif Name in ['HTTP_v1', 'HTTP_v7']:
        pattern = "x-request-ip: ([\d\.]+)"
    elif Name in ['HTTP_v2', "HTTP_v6", 'HTTP_v3', 'HTTP_v5', 'HTTP_v4']:
        pattern = 'user_ip=([\d\.]+)'
    elif Name.lower() == "tenor":
        pattern = "IpAddr/Port# ([\d\.]+)"
    elif Name.lower() in ['http_407']:
        pattern = "please add white ip ([\d\.]+)"
    elif Name.lower() in ['http_body1']:
        pattern = '\\"cf-footer-ip\\">([\d\.]+)'
    elif Name.lower() == "http_x_forwarded_for":
        pattern = 'X-Forwarded-For: ([\d\.]+)'
    elif Name.lower() in ['ms_smtp_hello']:
        pattern = 'Hello \[([\d\.]+)\]'
    elif Name.lower() in ['http_400_node']:
        pattern = 'IP: ([\d\.]+)'
    elif Name.lower() in ['http_400_watchguard']:
        pattern = 'Host:</b> ([\d\.]+)'

    elif Name.lower() in ['zxfs_ftp']:
        pattern = 'your ip is ([\d\.]+)'
    elif Name.lower() in ['esmtp_hello', 'smtp_client_reject']:
        pattern = '\[([\d\.]+)\]'
    elif Name.lower() in ['esmtp_mailenable']:
        pattern = 'home \[([\d\.]+)\]'
    elif Name.lower() in ['smtp_ptr']:
        pattern = 'No valid PTR for ([\d\.]+)\.in'
    elif Name.lower() in ['http_x_real_ip']:
        pattern = 'X-Real-Ip: ([\d\.]+)'
        
    elif Name.lower() in ['smtp_not_accept']:
        pattern = 'does not accept mail from you \(([\d\.]+)\)'
    elif Name.lower() in ['esmtp_connection']:
        pattern = 'connection from \[?([\d\.]+)\]?'
    elif Name.lower() in ['http_proxy_ip']:
        pattern = 'IP Address: ([\d\.]+)'    
    
    
    
    elif Name.lower() in ['http_src_ip']:
        pattern='<srcip>=([\d\.]+)'
        
    elif Name.lower() in ['http_client_ip']:
        pattern='client-ip[: =]{1,2}([\d\.]+)'
    
    elif Name.lower() in ['http_cip']:
        pattern='cip[: =]{1,2}([\d\.]+)'
    elif Name.lower() in ['http_login_ip']:
        pattern='Loginip[: =]{1,2}([\d\.]+)'
    
    elif Name.lower() in ['http_header_sip']:
        pattern='SIP/2.0/[TCPLS]{3} ([\d\.]+)'
    elif Name.lower() in ['http_header_access_deny']:
        pattern='Access denied for ([\d\.]+)'
    
    elif Name.lower() in ['http_dsc_real_ip']:
        pattern='dsc_real_ip=([\d\.]+)'
    
    elif Name.lower() in ['http_bd_ip']:
        pattern='bd_ip=([\d\.]+)'
    
    elif Name.lower() in ['http_remote_addr']:
        pattern='remote_addr[": ]{2,3}([\d\.]+)'
    
    elif Name.lower() in ['http_cdn_user_ip']:
        pattern='Cdn-User-Ip: ([\d\.]+)'
    
    elif Name.lower() in ['http_xhs-real-ip']:
        pattern='Xhs-Real-Ip: ([\d\.]+)'
    
    elif Name.lower() in ['http_remote_ip']:
        pattern='Remote-Ip: ([\d\.]+)'
    
    elif Name.lower() in ['http_x_remote_addr']:
        pattern='X-Remote-Addr: ([\d\.]+)'
    
    elif Name.lower() in ['http_tc_web_cookies']:
        pattern='tc_web_cookies_1=([\d\.]+)'
    
    elif Name.lower() in ['http_snkz']:
        pattern='snkz=([\d\.]+)'
    
    elif Name.lower() in ['http_ip_address']:
        pattern='ip_address=([\d\.]+)'
    elif Name.lower() in ['http_client_address']:
        pattern='Client-Address: ([\d\.]+)'
    
    elif Name.lower() in ['http_source_ip']:
        pattern='source_ip=([\d\.]+)'
    elif Name.lower() in ['http_x-ms-forbidden-ip']:
        pattern='X-Ms-Forbidden-Ip: ([\d\.]+)'
    
    elif Name.lower() in ['http_kt_ips']:
        pattern='kt_ips=([\d\.]+)'
    # kt_ips=106.75.137.214
    elif Name.lower() in ['http_x-remote-ip']:
        pattern='X-Remote-Ip: ([\d\.]+)'
    elif Name.lower() in ['http_flowip']:
        pattern='flowIp=([\d\.]+)'
    
    elif Name.lower() in ['http-x-rate-limit-request-remote-addr']:
        pattern='X-Rate-Limit-Request-Remote-Addr: ([\d\.]+)'
    
    elif Name.lower() in ['http-api-user-ip']:
        pattern='Api-User-Ip: ([\d\.]+)'
    
    elif Name.lower() in ['http_wx-client']:
        pattern='Wx-Client: mainland\|cn\|([\d\.]+)'
    elif Name.lower() in ['http_real_ipd']:
        pattern='real_ipd=([\d\.]+)'
    
    elif Name.lower() in ['http_yhip']:
        pattern='yhip=([\d\.]+)'
    
    elif Name.lower() in ['http_x_source_ip']:
        pattern='X-Source-Ip: ([\d\.]+)'
    
    elif Name.lower() in ['http-x-response-cinfo']:
        pattern='X-Response-Cinfo: ([\d\.]+)'
    
    elif Name.lower() in ['http-x-your-address-is']:
        pattern='X-Your-Address-Is: ([\d\.]+)'
    
    elif Name.lower() in ['http-x-wbx-about']:
        pattern='X-Wbx-About: CN, ([\d\.]+)'
    elif Name.lower() in ['http_block_ip']:
        pattern='Your blocked IP address is:[<b> ]{1,4}([\d\.]+)'
    
    
    return pattern


def matchSourceIPImproved(content: str, patternName: str):
    matchPattern=patternDB[patternName]['matchPattern']
    # print(matchPattern)
    application=patternDB[patternName]['application']
    if application == 'http':
        if '%2E' not in matchPattern:
            # matchPattern = matchPattern.replace('.', '%2E')
            content = content.replace('%2E', '.')
    res = re.findall(matchPattern, content, re.I)
    decodeRes=[x.replace('%2E', '.') for x in res if len(x)]
    
    # if Name.lower() in ['zxfs_ftp']:
    #     nres=[]
    #     for r in res:
    #         rsplit=r.split('.')
    #         rr='.'.join(rsplit[::-1])
    #         nres.append(rr)
    #     res=nres
    return decodeRes
    


def matchSourceIP(content: str, Name: str):
    # global uselessTimes
    xcontent = content
    if Name in ['HTTP_v2', "HTTP_v6", 'HTTP_v3', 'HTTP_v5', 'HTTP_v4','HTTP_SRC_IP'] or Name.lower() in ['http_client_ip','http_cip','http_login_ip','http_header_sip','http_header_access_deny','http_dsc_real_ip','http_bd_ip','http_remote_addr','http_cdn_user_ip','http_xhs-real-ip','http_remote_ip','http_x_remote_addr','http_tc_web_cookies','http_snkz','http_ip_address','http_client_address','http_source_ip','http_x-ms-forbidden-ip','http_kt_ips','http_x-remote-ip','http_flowip','http-x-rate-limit-request-remote-addr','http-api-user-ip','http_wx-client','http_real_ipd','http_yhip','http_x_source_ip','http-x-response-cinfo','http-x-your-address-is','http-x-wbx-about','http_src_ip']:
        xcontent = content.replace('%2E', '.')
        xcontent = xcontent.replace('[', '')
        xcontent = xcontent.replace(']', '')
        xcontent = xcontent.replace('::ffff:', '')

    pattern = get_pattern_by_name(Name)


    res = re.findall(pattern, xcontent, re.I)
    
    decodeRes=[x.replace('%2E', '.') for x in res]
    
    return decodeRes


def read_from_json(json_fp):
    with open(json_fp, 'r') as rf:
        content = json.load(rf)
    return content


def get_subnet(ip_address, subnet_mask='255.255.0.0'):

    network = ipaddress.IPv4Network(
        f"{ip_address}/{subnet_mask}", strict=False)
    return str(network.network_address) + '/' + str(network.prefixlen)


def get_subnet_statics(banner_ips_path):
    with open(banner_ips_path, 'r') as rf:
        iplists = eval(rf.read())
    num_dict = dict()
    for ip in iplists:
        if len(ip):
            subnet = get_subnet(ip)
            if subnet not in num_dict:
                num_dict[subnet] = 1
            else:
                num_dict[subnet] += 1
    number_dict = sorted(num_dict.items(), key=lambda x: x[1], reverse=True)
    return number_dict


def process_res_from_engine(resDict, engine):
    if engine == 'shodan':
        results = resDict['result']
    elif engine == 'fofa':
        results = resDict['results']
    elif engine == "zoomeye":
        results = resDict['matches']
    return results


def process_res_from_engine_improved(resDict, engine):
    if engine == 'shodan':
        results = resDict['matches']
    elif engine == 'fofa':
        results = resDict['results']
    elif engine == "zoomeye":
        results = resDict['matches']
    return results


def get_venn(setLists, nameTuple, title, pngName):
    # 绘制 Venn 图
    venn_diagram = venn3(setLists, set_labels=nameTuple)
    # 设置图表标题
    plt.title(title)
    # 显示图表
    plt.show()
    plt.savefig(pngName, dpi=500)


def extract_info_from_file(record: dict, engine: str):
    if engine == 'shodan':
        dst_ip = record['ip_str']
        dst_port = record['port']
    elif engine == 'zoomeye':
        dst_ip = record['ip']
        dst_port = record['portinfo']['port']
    elif engine == 'fofa':
        dst_ip = record[0]
        dst_port = int(record[2])
    return dst_ip, dst_port


def command_execute(command:str):
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=3)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output


def nc_ping(host: str, port: int):
    command = f'echo "get info" | nc {host} {port} -vvv -w 1'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=3)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output


def telnet_ping(host: str, port: int):
    command = f'(echo "HELO" ; sleep 3) | telnet {host} {port}'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=4)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output


def esmtp_windows_ping(host: str, port: int):
    command = f'(echo "EHLO" ; sleep 3) | telnet {host} {port}'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=4)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output


def ftp_ping(host: str, port: int):
    command = f'echo "get info" | nc {host} {port} -w 1'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=3)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output


def smtp_ping(host: str, port: int):
    command = f'echo "HELO" | nc {host} {port} -w 1'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=3)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output


def curl_ping(host: str, port: int, url=None):
    if url is None:
        command = f'curl "http://{host}:{port}" -v -k --connect-timeout 5 -m 10'
    else:
        command = f'curl "{url}" -v -k --connect-timeout 5 -m 10'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=5)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output


def curl_ping_domain(host: str, port: int):
    command = f'curl "{host}" -v -k --connect-timeout 5 -m 10'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=5)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output

def curl_ping_09(host: str, port: int):
    command = f'curl --http0.9 "http://{host}:{port}" -v -k --connect-timeout 5 -m 10'
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = '', ''
        stdout, stderr = process.communicate(timeout=5)
        output = stdout.decode()+stderr.decode()
    except Exception as e:
        output = str(stdout+stderr)+str(e)
    return output

def web_ping(host: str, port: int):
    url = f'http://{host}:{port}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'}
    try:
        resp = requests.get(url, headers=headers, timeout=4)
        content = resp.content
        if b'speaking plain HTTP to an SSL-enabled server port' in content:
            surl = f'https://{host}:{port}'
            resp = requests.get(surl, headers=headers, timeout=4)
        output = resp.content
        header = resp.headers
        output = header + output
    except Exception as e:
        output = e
    return str(output)


def checkLeak(filepath: str, patternName=None):
    with open(filepath, 'r') as rf:
        content = rf.read()
    content = content.replace('%2E', '.')
    res = matchSourceIP(content, patternName)
    reverseFlag = 0
    if len(res):
        if len(res) > 1 and len(set(res)) != 1:
            print(f'Multiple IP:{res}')
        for client_ip in res:
            if 'test_ip' in client_ip:
                reverseFlag = 1
            elif 'test_ip' in client_ip:
                reverseFlag = 3
            else:
                reverseFlag = 0
                return
    return reverseFlag


def checkLeakImproved(filepath: str, patternName=None):
    with open(filepath, 'r') as rf:
        content = rf.read()
    # content = content.replace('%2E', '.')
    res = matchSourceIPImproved(content, patternName)
    # res=[x for x in res if len(x)]
    reverseFlag = 0
    if len(res):
        if len(res) > 1 and len(set(res)) != 1:
            print(f'Multiple IP:{res}')
        for client_ip in res:
            if 'test_ip.' in client_ip:
                reverseFlag = 1
            elif 'test_ip' in client_ip:
                reverseFlag = 3
            else:
                reverseFlag = 0
                return
    return reverseFlag



def get_record_number(filedir: str, engine: str):
    sum = 0
    for root, ds, fs in os.walk(filedir):
        for f in fs:
            fp = os.path.join(root, f)
            with open(fp, 'r') as rf:
                results = json.load(rf)
                sum += len(process_res_from_engine(results, engine))
                # sum+=len(results['results'])
    return sum


def extract_http_content(engine, res, shodan_flag=0):
    if engine == "shodan":
        try:
            result = res["http"]['html']
        except Exception as e:
            result = res['data']
            if shodan_flag:
                result = ''
    elif engine == "fofa":
        result = res[1]
        if shodan_flag:
            result = res[-1]

    elif engine == 'zoomeye':
        result = res['portinfo']['banner']

    return result


def extract_info(engine: str, record):
    # time,server_ip,server_port,banner_ip=0
    if engine == 'zoomeye':
        server_ip = record['ip']
        banner = record['portinfo']['banner']
        server_port = record['portinfo']['port']
        time = record['timestamp']
    elif engine == 'fofa':
        server_ip = record[0]
        banner = record[3]
        server_port = record[2]
        time = record[4]
    elif engine == 'shodan':
        server_ip = record['ip_str']
        time = record['timestamp']
        server_port = record['port']
        if 'mysql' in record and 'error_message' in record['mysql']:
            banner = record['mysql']['error_message']
        elif 'data' in record:
            banner = record['data']
        else:
            banner = ''
    return server_ip, server_port, banner, time



def extract_info_improved(engine: str, record, query = None):
    # time,server_ip,server_port,banner_ip=0
    if engine == 'zoomeye':
        server_ip = record['ip']
        banner = record['portinfo']['banner']
        server_port = record['portinfo']['port']
        time = record['timestamp']
    elif engine == 'fofa':
        if 'header' in query:
            server_ip = record[0]
            banner = record[4]
            server_port = record[2]
            time = record[5]
        else:
            server_ip = record[0]
            banner = record[3]
            server_port = record[2]
            time = record[5]
    elif engine == 'shodan':
        server_ip = record['ip_str']
        time = record['timestamp']
        server_port = record['port']
        if 'mysql' in record and 'error_message' in record['mysql']:
            banner = record['mysql']['error_message']
        elif 'data' in record:
            banner = record['data']
        else:
            banner = ''
    return server_ip, server_port, banner, time



def get_record_number(workDir, engine):
    sum = 0
    for root, _, fs in os.walk(workDir):
        for f in fs:
            fp = os.path.join(root, f)
            with open(fp, 'r') as rf:
                results = json.load(rf)
                sum += len(process_res_from_engine(results, engine))
    return sum


def set_work_dir(save_dir=None, patternName=None):
    if save_dir is None:
        save_dir = './'
    workdir = os.path.join(save_dir, patternName)

    if not os.path.exists(workdir):
        os.makedirs(workdir)
    return workdir


def saveFileNameFunc(work_dir, pageNum): return (
    os.path.join(work_dir, f'res_{pageNum}.json'))


# ----------- shodan search ---------


def check_shodan_result(patternName, result):
    if 'mysql_v2'.lower() in patternName.lower():
        if 'mysql' in result and 'error_message' in result['mysql']:
            return True
        else:
            return False
    if 'zookeeper' in patternName.lower():
        if 'data' in result and 'Zookeeper version' in result['data']:
            return True
        else:
            return False
    if 'sip' in patternName.lower():
        if 'data' in result and 'received' in result['data']:
            return True
        else:
            return False
    return True


def get_shodan_crawler_ip_improved(patternName, save_dir=None, recordNum=10000):
    token = SHODAN_API_KEY
    # queryPattern = patternDB[patternName]['urlPattern']['fofa']
    leak_pattern = patternDB[patternName]['urlPattern']['shodan']
    leak_pattern = paddingPatternImproved('shodan',leak_pattern)
    api = shodan.Shodan(token)
    workdir = set_work_dir(save_dir, patternName)
    endPages = recordNum//100
    page = 1
    queueList = []
    for record in api.search_cursor(query=leak_pattern):
        if len(queueList) == 100:
            data = {"result": queueList}
            save_filename = os.path.join(workdir, f'res_{page}.json')
            with open(save_filename, 'w') as wf:
                json.dump(data, wf)
                page += 1
            queueList = []
        if check_shodan_result(patternName, record):
            queueList.append(record)
        if page > endPages:
            break
    if len(queueList):
        data = {"result": queueList}
        # save_filename = os.path.join(workdir, f'res_{page}.json')
        save_filename = saveFileNameFunc(workdir, page)
        with open(save_filename, 'w') as wf:
            json.dump(data, wf)
            page += 1


def get_shodan_crawler_ip(patternName, save_dir=None, recordNum=10000):
    token = SHODAN_API_KEY
    leak_pattern = enginePattern['shodan'][patternName]
    leak_pattern = paddingPattern('shodan',leak_pattern)
    api = shodan.Shodan(token)
    workdir = set_work_dir(save_dir, patternName)
    endPages = recordNum//100
    page = 1
    queueList = []
    for record in api.search_cursor(query=leak_pattern):
        if len(queueList) == 100:
            data = {"result": queueList}
            save_filename = os.path.join(workdir, f'res_{page}.json')
            with open(save_filename, 'w') as wf:
                json.dump(data, wf)
                page += 1
            queueList = []
        if check_shodan_result(patternName, record):
            queueList.append(record)
        if page > endPages:
            break
    if len(queueList):
        data = {"result": queueList}
        # save_filename = os.path.join(workdir, f'res_{page}.json')
        save_filename = saveFileNameFunc(workdir, page)
        with open(save_filename, 'w') as wf:
            json.dump(data, wf)
            page += 1

def get_reverse_ip(raw_ip:str):
    raw_ipsplit=raw_ip.split('.')
    raw_ipsplit.reverse()
    reverse_ip='.'.join(raw_ipsplit)
    return reverse_ip

def get_one_record_from_shodan(queryPattern, key_index=0):
    keyLength=len(SHODAN_API_KEYs)
    api = shodan.Shodan(SHODAN_API_KEYs[key_count % keyLength])
    results = api.search(queryPattern)
    
    rawData = []
    for res in results['matches']:
        if 'ssl' in res and 'cert' in res['ssl']:
            if 'serial' in res['ssl']['cert']:
                res['ssl']['cert']['serial'] = ''
        rawData.append(res)
    crawlTime = datetime.datetime.now()
    query = queryPattern
    assetMappingEngine = 'shodan'
    record_data={
        'rawData':rawData,
        'crawlTime':crawlTime,
        'query':query,
        'assetMappingEngine':assetMappingEngine
    }
    # print(rawData)
    # print('11asdasd',record_data)
    # return record_data
    try:
        record_db.insert_one(record_data)
    except UnicodeEncodeError as e:
        # print(e)
        print('UnicodeEncodeError')
    
    except OverflowError as e:
        print('OverflowError')
    return results


# ----------- shodan search ---------


# ----------- fofa search ---------
def generate_fofa_pattern(queryPattern: str, patternName: str,  page=1, page_size=100):
    rawPattern=b64decode(parse.unquote(queryPattern).encode()).decode()
    # queryPattern=parse.unquote(queryPattern)
    # queryPattern = queryPattern.replace('%3D', '=')
    # raw_pattern = b64decode(queryPattern.encode()).decode()
    
    queryPattern = paddingPattern('fofa', queryPattern)
    if 'header' in rawPattern:

        urlPattern = f'https://fofa.info/api/v1/search/all?email={fofa_token[0]}&key={fofa_token[1]}&qbase64={queryPattern}&fields=ip,host,port,header,lastupdatetime&size={page_size}&page={page}'
    else:
        urlPattern = f'https://fofa.info/api/v1/search/all?email={fofa_token[0]}&key={fofa_token[1]}&qbase64={queryPattern}&fields=ip,host,port,banner,lastupdatetime&size={page_size}&page={page}'

    return urlPattern


def generat_fofa_url_pattern(queryPattern:str,page=1, page_size=100):
    improvedPattern=paddingPatternImproved('fofa',queryPattern)
    if 'header' in improvedPattern:
        urlPattern = f'https://fofa.info/api/v1/search/all?email={fofa_token[0]}&key={fofa_token[1]}&qbase64={improvedPattern}&fields=ip,host,port,header,lastupdatetime&size={page_size}&page={page}'
    else:
        urlPattern = f'https://fofa.info/api/v1/search/all?email={fofa_token[0]}&key={fofa_token[1]}&qbase64={improvedPattern}&fields=ip,host,port,banner,lastupdatetime&size={page_size}&page={page}'
    return urlPattern


def get_fofa_crawler_ip_improved(patternName, save_dir=None, recordNum=10000):
    queryPattern = patternDB[patternName]['urlPattern']['fofa']
    workdir = set_work_dir(save_dir, patternName)
    endPages = recordNum//100
    for page in range(1, endPages+1):
        urlPattern = generat_fofa_url_pattern(
            queryPattern,  page, page_size=100)
        # print(urlPattern)
        # exit()
        response = requests.get(urlPattern)
        resJson = response.json()
        if resJson['error']:
            break
        else:
            save_filename = saveFileNameFunc(workdir, page)
            with open(save_filename, 'w') as wf:
                json.dump(resJson, wf, ensure_ascii=True, indent=4)



def get_fofa_crawler_ip(patternName, save_dir=None, recordNum=10000):
    queryPattern = enginePattern['fofa'][patternName]
    workdir = set_work_dir(save_dir, patternName)
    endPages = recordNum//100
    for page in range(1, endPages+1):
        urlPattern = generate_fofa_pattern(
            queryPattern, patternName, page, page_size=100)
        response = requests.get(urlPattern)
        resJson = response.json()
        if resJson['error']:
            break
        else:
            save_filename = saveFileNameFunc(workdir, page)
            with open(save_filename, 'w') as wf:
                json.dump(resJson, wf, ensure_ascii=True, indent=4)


def get_one_record_from_fofa(queryPattern, option=None,urlQuery=None):
    if urlQuery is None:
        urlPattern = f'https://fofa.info/api/v1/search/all?email={fofa_token[0]}&key={fofa_token[1]}&qbase64={queryPattern}&fields=ip,host,port,banner,header,lastupdatetime'
    else:
        urlPattern=urlQuery
    response = requests.get(urlPattern)
    try:
        resJson = response.json()
    except Exception as e:
        print(e)
        print(response.text)
        exit()
    try:
        rawData = resJson
        rawData['fields']='ip,host,port,banner,header,lastupdatetime'
        # query = rawData ['qu']
        crawlTime = datetime.datetime.now()
        # query = rawData['query'] + f'fields=ip,host,port,banner,header,lastupdatetime'
        query = f'qbase64={queryPattern}&fields=ip,host,port,banner,header,lastupdatetime'
        assetMappingEngine = 'fofa'
        record_data={
            'rawData':rawData,
            'crawlTime':crawlTime,
            'query':query,
            'assetMappingEngine':assetMappingEngine
        }
        if option is None:
            pass
        else:
            record_data['option']=option
        record_db.insert_one(record_data)
    except Exception as e:
        import logging
        logging.exception(e)
        notice(f'error in get_one_record_from_fofa is {e}')
        
    return resJson






# ----------- fofa search ---------


# ----------- zoomeye search ------------

def get_zoomeye_key(keyNum: int):
    global key_valid_flag
    if sum(key_valid_flag) == 0:
        print('No available token!')
        return None
    length = len(zoomeye_tokens)
    resource_url = 'https://api.zoomeye.org/resources-info'
    # token=None
    while True:
        token = zoomeye_tokens[keyNum % length]
        headers = {'API-KEY':  token}
        resp = requests.get(url=resource_url, headers=headers)
        resource_info = resp.json()
        search = resource_info['resources']['search']
        if search == 0:
            print(f'The token {token} limit has been exhausted.')
            key_valid_flag[keyNum % length] = 0
            if sum(key_valid_flag) == 0:
                return None
        else:
            break
        keyNum += 1
    return keyNum

def get_one_record_from_zoomeye(queryPattern: str, keyNum=0, queryUrl=None):
    global key_count, key_valid_flag
    if queryUrl is None:
        urlPattern = f'https://api.zoomeye.org/host/search?query={queryPattern}'
    else:
        urlPattern = queryUrl
    # print(urlPattern)
    length = len(zoomeye_tokens)
    resource_url = 'https://api.zoomeye.org/resources-info'
    key_count = keyNum
    # notice(123)
    while True:
        token = zoomeye_tokens[key_count % length]
        if key_valid_flag[key_count % length]:
            break
        if sum(key_valid_flag) == 0:
            print('No available token!')
            return
        key_count += 1
    headers = {'API-KEY':  token}
    r = requests.get(url=f'{urlPattern}',
                     headers=headers)
    r_decoded = r.json()
    # print(r_decoded)
    if 'matches' not in r_decoded:
        print(r_decoded)
        return -3
    # print r_decoded
    # print r_decoded['total']
    # print(r_decoded)
    # print(r_decoded)
    # notice(456)
    matches = r_decoded['matches']
    # print(matches)
    if not matches or not len(matches):
        # print(r_decoded)
        resp = requests.get(url=resource_url, headers=headers)
        resource_info = resp.json()
        search = resource_info['resources']['search']
        if search == 0:
            print(f'The token {token}  limit has been exhausted.')
            # index=key_valid_flag.index(token)
            key_valid_flag[(key_count-1) % length] = 0
            avaliable_key = get_zoomeye_key(key_count)
            # print(avaliable_key)
            # notice(789)
            if avaliable_key is not None:
                key_count = avaliable_key
                token = zoomeye_tokens[key_count % length]
                headers = {'API-KEY':  token}
                r = requests.get(url=f'{urlPattern}',
                                 headers=headers)
                r_decoded = r.json()
                # print r_decoded
                # print r_decoded['total']
                # print(r_decoded)
                matches = r_decoded['matches']
                rawData = r_decoded
                crawlTime = datetime.datetime.now()
                query = queryPattern
                assetMappingEngine = 'zoomeye'
                record_data={
                    'rawData':rawData,
                    'crawlTime':crawlTime,
                    'query':query,
                    'assetMappingEngine':assetMappingEngine
                }
                record_db.insert_one(record_data)
                
                return r_decoded
                
            else:
                print('No avaliable key!')
                return -2
        else:
            return -1
    
    
    matches = r_decoded['matches']
    rawData = r_decoded
    crawlTime = datetime.datetime.now()
    query = queryPattern
    assetMappingEngine = 'zoomeye'
    record_data={
        'rawData':rawData,
        'crawlTime':crawlTime,
        'query':query,
        'assetMappingEngine':assetMappingEngine
    }
    try:
        record_db.insert_one(record_data)
    except Exception as e:
        print(e)
    return r_decoded




def get_zoomeye_crwaler_ip_improved(patternName,  save_dir=None, recordNum=10000, startPage=1):
    global key_count, key_valid_flag
    page = startPage
    length = len(zoomeye_tokens)
    resource_url = 'https://api.zoomeye.org/resources-info'
    url_pattern=patternDB[patternName]['urlPattern']['zoomeye']
    url_pattern=paddingPatternImproved('zoomeye',url_pattern)
    
    baseUrl='https://api.zoomeye.org/host/search?query='
    finalUrl=baseUrl + quote(url_pattern)+ '&t=v4'
    # print(finalUrl)
    # exit()
    
    # url_pattern = enginePattern['zoomeye'][patternName]

    # exit()
    # url_pattern = paddingPattern('zoomeye', url_pattern)
    # print(url_pattern)
    # exit()

    workdir = set_work_dir(save_dir, patternName)
    endPages = recordNum//20
    while (True):
        try:
            # token = get_zoomeye_key(key_count)
            while True:
                token = zoomeye_tokens[key_count % length]
                if key_valid_flag[key_count % length]:
                    break
                if sum(key_valid_flag) == 0:
                    print('No available token!')
                    return
                key_count += 1

            key_count += 1
            # if token is None:
            #     print('No available token!')
            #     break
            headers = {'API-KEY':  token}
            r = requests.get(url=f'{finalUrl}&page={page}&pageSize=50',
                             headers=headers)
            r_decoded = r.json()
            # print r_decoded
            # print r_decoded['total']
            # print(r_decoded)
            matches = r_decoded['matches']

            if not matches or not len(matches):
                # print(r_decoded)
                resp = requests.get(url=resource_url, headers=headers)
                resource_info = resp.json()
                search = resource_info['resources']['search']
                if search == 0:
                    print(f'The token {token}  limit has been exhausted.')
                    # index=key_valid_flag.index(token)
                    key_valid_flag[(key_count-1) % length] = 0
                    avaliable_key = get_zoomeye_key(key_count)
                    # print(avaliable_key)
                    if avaliable_key is not None:
                        key_count = avaliable_key
                        page -= 1
                    else:
                        print(r_decoded)
                        print('2: No available key!')
                        break
                else:
                    print(r_decoded)
                    # print(search)
                    print('1: No matched Result!')
                    break

            # if not os.path.exists(f'./{patternName}'):
            #     os.mkdir(f'./{patternName}')
            save_filename = saveFileNameFunc(workdir, page)
            with open(save_filename, 'w') as wf:
                json.dump(r_decoded, wf, ensure_ascii=True, indent=4)
            # exit(0)
                # print (x['ip'])
                # ip_list.append(x['ip'])

            # print(ip_list,init_res)
            # exit(0)
            # print('[-] info : count ' + str(page * 50))
            page += 1
            if page > endPages:
                break

        except Exception as e:
            print('[-] info : ' + str(e))
            # print(r_decoded)
            break




def get_zoomeye_crwaler_ip(patternName,  save_dir=None, recordNum=10000, startPage=1):
    global key_count, key_valid_flag
    page = startPage
    length = len(zoomeye_tokens)
    resource_url = 'https://api.zoomeye.org/resources-info'
    url_pattern = enginePattern['zoomeye'][patternName]

    # exit()
    url_pattern = paddingPattern('zoomeye', url_pattern)
    # print(url_pattern)
    # exit()

    workdir = set_work_dir(save_dir, patternName)
    endPages = recordNum//20
    while (True):
        try:
            # token = get_zoomeye_key(key_count)
            while True:
                token = zoomeye_tokens[key_count % length]
                if key_valid_flag[key_count % length]:
                    break
                if sum(key_valid_flag) == 0:
                    print('No available token!')
                    return
                key_count += 1

            key_count += 1
            # if token is None:
            #     print('No available token!')
            #     break
            headers = {'API-KEY':  token}
            r = requests.get(url=f'{url_pattern}&page={page}&pageSize=50',
                             headers=headers)
            r_decoded = r.json()
            # print r_decoded
            # print r_decoded['total']
            # print(r_decoded)
            matches = r_decoded['matches']

            if not matches or not len(matches):
                # print(r_decoded)
                resp = requests.get(url=resource_url, headers=headers)
                resource_info = resp.json()
                search = resource_info['resources']['search']
                if search == 0:
                    print(f'The token {token}  limit has been exhausted.')
                    # index=key_valid_flag.index(token)
                    key_valid_flag[(key_count-1) % length] = 0
                    avaliable_key = get_zoomeye_key(key_count)
                    # print(avaliable_key)
                    if avaliable_key is not None:
                        key_count = avaliable_key
                        page -= 1
                    else:
                        print(2)
                        break
                else:
                    print(1)
                    break

            # if not os.path.exists(f'./{patternName}'):
            #     os.mkdir(f'./{patternName}')
            save_filename = saveFileNameFunc(workdir, page)
            with open(save_filename, 'w') as wf:
                json.dump(r_decoded, wf, ensure_ascii=True, indent=4)
            # exit(0)
                # print (x['ip'])
                # ip_list.append(x['ip'])

            # print(ip_list,init_res)
            # exit(0)
            # print('[-] info : count ' + str(page * 50))
            page += 1
            if page > endPages:
                break

        except Exception as e:
            # 若搜索请求超过 API 允许的最大条目限制 或者 全部搜索结束，则终止请求
            print('[-] info : ' + str(e))
            # print(r_decoded)
            break
# ----------- zoomeye search ------------

def notice(info:str):
    import os,time
    headers={'Content-Type':'application/json'}
    url=''
    data={"msg_type":"text","content":{"text":info}}
    
    try:
        requests.post(url=url,headers=headers,json=data)
    except Exception as e:
        for _ in range(3):
            os.system('bash ~/conn.sh')
            time.sleep(5)
            try:
                data2={"msg_type":"text","content":{"text":'reconnect to network!'}}
                requests.post(url=url,headers=headers,json=data2)
                requests.post(url=url,headers=headers,json=data)
                break
            except:
                pass

def get_shodan_count_number(queryPattern):
    api = shodan.Shodan(SHODAN_API_KEY)
    result = api.count(queryPattern)
    return result['total']


import traceback
def print_error_log(exception):
    # 获取错误的堆栈信息
    traceback_info = traceback.format_exc()
    # 获取发生错误的函数名
    function_name = traceback.extract_tb(exception.__traceback__)[-1][2]
    # 获取发生错误的行数
    line_number = traceback.extract_tb(exception.__traceback__)[-1][1]
    # 打印错误日志
    error_log = f"Error in function '{function_name}', line {line_number}: {traceback_info}"
    print(error_log)

def merge_new_encoded_server(collection=None,typeName:str=None):
    # client_db = db.get_asset().assets_mapping['crawler_client']
    # record_db = db.get_asset().assets_mapping['all_records']

    server_db = ''
    server_stauts_db = ''
    # global server_db, client_db, server_stauts_db
    # with open('/home/song/workspace/ipleak/scripts/shodan_encode_server.json','r') as rf:
    #     shodan_encoded_server=json.load(rf)
    if collection is None:
        encoded_valid_servers =  mydb.DB().get_asset().assets_mapping['encoded_valid_servers']
    else:
        encoded_valid_servers =  collection
    
    
    for record in encoded_valid_servers.find({}):
        server_ip = record['server_ip']
        server_port = record['server_port']
        protocol = record['protocol']
        pattern = record['pattern']
        if typeName=='encoded':
            reverseFlag = 0
        else:
            reverseFlag = 0 if record['reverseFlag'] == 1 else 1
            # reverseFlag = 1
        # reverseFlag = 0
        queryData={
            'server_ip':server_ip,
            'server_port':server_port,
            'protocol':protocol,
            # 'pattern':pattern,
            # 'reverseFlag':reverseFlag
        }
        numCount = server_db.count_documents(queryData)
        if numCount == 0:
            server_db.insert_one({
                'server_ip':server_ip,
                'server_port':server_port,
                'protocol':protocol,
                'pattern':pattern,
                'reverseFlag': reverseFlag
            })
        numCount = server_stauts_db.count_documents({
            'server_ip':server_ip,
            'server_port':server_port,
        })
        if numCount == 0:
            server_stauts_db.insert_one({
                'server_ip':server_ip,
                'server_port':server_port,
                'type':typeName,
            })