#!/usr/bin/python
# -*- coding: utf-8 -*-
# Usage: python c#wcss.py web.config
# Author: g4xyk00
# Reference: https://pumascan.com/rules.html

import sys
import re
import datetime

displayPositive = '\033[32m' + '[+] ' + '\033[0m'
displayNegative = '\033[31m' + '[!] ' + '\033[0m'

def displayMatch(item, regex, text, recommended):
    value = re.search(regex, text)
    if value is not None:
        match = value.group(1)

        if match.lower() == recommended:
            return displayPositive + item + ": " + match
        else:
            return displayNegative  + item + ": " + match 


filePath = sys.argv[1]
file = open(filePath)
tag = ['compilation', 'customErrors', 'forms', 'httpRuntime', 'pages', 'httpCookies', 'sessionState']
lineNum = 0;

print "---------------------------------------------------------------------"
print "              _                      __ _         __                 "
print "__      _____| |__   ___ ___  _ __  / _(_) __ _  / _\ ___ __ _ _ __  "
print "\ \ /\ / / _ \ '_ \ / __/ _ \| '_ \| |_| |/ _` | \ \ / __/ _` | '_ \ "
print " \ V  V /  __/ |_) | (_| (_) | | | |  _| | (_| | _\ \ (_| (_| | | | |"
print "  \_/\_/ \___|_.__(_)___\___/|_| |_|_| |_|\__, | \__/\___\__,_|_| |_|"
print "                                          |___/                      "
print ""
print "         Web.config security scanner by Axcel Security"
print "---------------------------------------------------------------------"

for line in file:
    lineNum += 1
    displayLineNum = "\nLine " + str(lineNum) + ": "

    for t in tag:
        if '<'+t in line: #if tag is listed
            instance = displayLineNum + line.strip()

            #Formatting for instance
            instance = '\033[46m' + instance + '\033[0m'

            #1. Compilation setting
            if t == tag[0]:
                print instance
                #1.1 Specifies whether to compile debug binaries rather than retail binaries
                #Recommended: debug="false", Default: debug="false"
                print displayMatch('Debug', 'debug="([a-zA-Z]*)"', line, "false")

            #2. Provides information about custom error messages
            elif t == tag[1]:
                print instance
                #Recommended: mode="RemoteOnly|On", Default: mode="RemoteOnly"
                value = re.search('mode="([a-zA-Z]*)"', line)
                if value is not None:
                    match = value.group(1)
                    if match.lower() == "off":
                        print displayNegative + "Custom Error: " + match 

            #3. Forms–based authentication
            elif t == tag[2]:
                print instance
                #3.1 SSL connection is required to transmit the authentication cookie
                if 'requireSSL' in line:
                    #Recommended: requireSSL="true", Default: requireSSL="false"
                    print displayMatch('Secure Cookie', 'requireSSL="([a-zA-Z]*)"', line, "true")
                else:
                    print displayNegative + "Secure Cookie : false"

                #3.2 Cookies behavior
                if 'cookieless' in line:
                    #Recommended: cookieless="UseCookies", Default: cookieless="UseDeviceProfile"
                    print displayMatch('Cookieless', 'cookieless="([a-zA-Z]*)"', line, "usecookies")
                else:
                    print displayNegative + "Cookieless: UseDeviceProfile"

                #3.3 Authenticated users are redirected to URLs in other Web applications
                if 'enableCrossAppRedirects' in line:
                    #Recommended: enableCrossAppRedirects="false", Default: enableCrossAppRedirects="false"
                    print displayMatch('Cross App Redirects', 'enableCrossAppRedirects="([a-zA-Z]*)"', line, "false")
                else:
                    print displayPositive + "Cross App Redirects: false"

                #3.4 Type of encryption to use for cookies.
                if 'protection' in line:
                    #Recommended: protection="All", Default: protection="All"
                    print displayMatch('Cookie Protection', 'protection="([a-zA-Z]*)"', line, "All")
                else:
                    print displayPositive + "Cookie Protection: All"

                #3.5 Minutes after which the cookie expires
                    if 'timeout' in line:
                        #Recommended: timeout="15", Default: timeout="30"
                        value = re.search('timeout="([0-9]*)"', line)
                        if value is not None:
                            match = value.group(1)
                            if match > 15:
                                print displayNegative + "Cookie Timeout (minutes): ",match
                    else:
                        print displayNegative + "Cookie Timeout (minutes): 30"

            #4. ASP.NET HTTP run-time settings
            elif t == tag[3]:
                print instance

                #4.1 Check the request header for potential injection attacks
                if 'enableHeaderChecking' in line:
                    #Recommended: enableHeaderChecking="true", Default: enableHeaderChecking="true"
                    print displayMatch('Header Checking', 'enableHeaderChecking="([a-zA-Z]*)"', line, "true")
                else:
                    print displayPositive + "Header Checking: true"

                #4.2 Output a version header
                if 'enableVersionHeader' in line: 
                    #Recommended: enableVersionHeader="true", Default: enableVersionHeader="true"
                    print displayMatch('Version Header', 'enableVersionHeader="([a-zA-Z]*)"', line, "false")
                else:
                    print displayNegative + "Version Header: true"

            #5. Page-specific configuration settings
            elif t == tag[4]:
                print instance

                #5.1 Specifies whether pages and controls validate postback and callback events
                if 'enableEventValidation' in line: 
                #Recommended: enableEventValidation="true", Default: enableEventValidation="true"
                    print displayMatch('Event Validation', 'enableEventValidation="([a-zA-Z]*)"', line, "true")
                else:
                    print displayPositive + "Event Validation: true" 

                #5.2 Encrypted view state is checked to verify that it has not been tampered with on the client
                if 'enableViewStateMac' in line: 
                #Recommended: enableViewStateMac="true", Default: enableViewStateMac="true"
                    print displayMatch('ViewStateMac protection', 'enableViewStateMac="([a-zA-Z]*)"', line, "true")
                else:
                    print displayPositive + "ViewStateMac protection: true" 

                #5.3 Request validation is performed by comparing all input data to a list of potentially dangerous values
                if 'validateRequest' in line: 
                #Recommended: validateRequest="true", Default: validateRequest="true"
                    print displayMatch('Request Validation', 'validateRequest="([a-zA-Z]*)"', line, "true")
                else:
                    print displayPositive + "Request Validation: true" 

                #5.4 Encryption mode of the view state
                if 'viewStateEncryptionMode' in line: 
                #Recommended: viewStateEncryptionMode="Always", Default: viewStateEncryptionMode="Auto"
                    print displayMatch('View State Encryption', 'viewStateEncryptionMode="([a-zA-Z]*)"', line, "Always")
                else:
                    print displayNegative + "View State Encryption: Auto" 

            #6. Properties for cookies        
            elif t == tag[5]: 
                print instance

                #6.1 Secure Sockets Layer (SSL) communication is required
                if 'requireSSL' in line: 
                 #Recommended: requireSSL="true",Default: requireSSL="false"
                    print displayMatch('View State Encryption', 'requireSSL="([a-zA-Z]*)"', line, "true")
                else:
                    print displayNegative + "SSL communication required: false" 

                #6.2 Enables output of the HttpOnlyCookies cookie 
                if 'httpOnlyCookies' in line: 
                #Recommended: httpOnlyCookies="true", Default: httpOnlyCookies="false"
                    print displayMatch('Enables output of HttpOnlyCookies cookie', 'httpOnlyCookies="([a-zA-Z]*)"', line, "true")
                else:
                    print displayNegative + "Enables output of HttpOnlyCookies cookie: false"

            #7. Session state settings
            else:
                if t == tag[6]: #Session state settings
                    print instance

                    #The number of minutes a session can be idle before it is abandoned
                    if 'timeout' in line: 
                    #Recommended: timeout="15", Default: timeout="20"
                        value = re.search('timeout="([0-9]*)"', line)
                        secLvl = 15 #High: 15, Med: 30, Low: 60
                        if value is not None:
                            match = value.group(1)
                            if match > secLvl:
                                print displayNegative + "Session Timeout (minutes): ",match
                            else:
                                print displayPositive + "Session Timeout (minutes): ",match
                    else:
                        print displayNegative + "Session Timeout: 20"

print "\n\n" + displayPositive + "Scan done at " + str(datetime.datetime.now())