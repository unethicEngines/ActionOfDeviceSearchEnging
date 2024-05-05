

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
