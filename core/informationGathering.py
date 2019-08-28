# -*- coding: utf-8 -*-

from .common import alreadyInstalled, clear_scr, continuePrompt, fsociety_prompt, secure_input, toolDir
from fsociety import Fsociety
import os
import socket

from time import gmtime, strftime


"""
Information Gathering Tools Classes
"""


class InformationGatheringMenu:
    menuLogo = '''
    88 88b 88 888888  dP"Yb
    88 88Yb88 88__   dP   Yb
    88 88 Y88 88""   Yb   dP
    88 88  Y8 88      YbodP
    '''

    def __init__(self):
        clear_scr()
        print(self.menuLogo)

        print("  {1}--Nmap - Network Mapper")
        print("  {2}--Setoolkit")
        print("  {3}--Host To IP")
        print("  {4}--WPScan")
        print("  {5}--CMSmap")
        print("  {6}--XSStrike")
        print("  {7}--Doork")
        print("  {8}--Crips\n  ")
        print("  {99}-Back To Main Menu \n")
        choice2 = secure_input(fsociety_prompt)
        clear_scr()
        if choice2 == "1":
            nmap()
        elif choice2 == "2":
            setoolkit()
        elif choice2 == "3":
            host2ip()
        elif choice2 == "4":
            wpscan()
        elif choice2 == "5":
            CMSmap()
        elif choice2 == "6":
            XSStrike()
        elif choice2 == "7":
            doork()
        elif choice2 == "8":
            crips()
        elif choice2 == "99":
            Fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        secure_input("Completed, click return to go back")
        self.__init__()


class nmap:
    nmapLogo = '''
    88b 88 8b    d8    db    88""Yb
    88Yb88 88b  d88   dPYb   88__dP
    88 Y88 88YbdP88  dP__Yb  88"""
    88  Y8 88 YY 88 dP""""Yb 88
    '''

    def __init__(self):
        self.installDir = toolDir + "nmap"
        self.gitRepo = "https://github.com/nmap/nmap.git"

        self.targetPrompt = "   Enter Target IP/Subnet/Range/Host: "

        if not self.installed():
            self.install()
            self.run()
        else:
            self.run()

    @staticmethod
    def installed():
        return os.path.isfile("/usr/bin/nmap") or os.path.isfile("/usr/local/bin/nmap")

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("cd %s && ./configure && make && make install" %
                  self.installDir)

    def run(self):
        clear_scr()
        print(self.nmapLogo)
        target = secure_input(self.targetPrompt)
        self.menu(target)

    def menu(self, target):
        clear_scr()
        print(self.nmapLogo)
        print("   map scan for: %s\n" % target)
        print("   {1}--Simple Scan [-sV]")
        print("   {2}--Port Scan [-Pn]")
        print("   {3}--Operating System Detection [-A]\n")
        print("   {99}-Return to information gathering menu \n")
        response = secure_input("nmap ~# ")
        clear_scr()
        logPath = "logs/nmap-" + strftime("%Y-%m-%d_%H:%M:%S", gmtime())
        try:
            if response == "1":
                os.system("nmap -sV -oN %s %s" % (logPath, target))
                response = secure_input(continuePrompt)
            elif response == "2":
                os.system("nmap -Pn -oN %s %s" % (logPath, target))
                response = secure_input(continuePrompt)
            elif response == "3":
                os.system("nmap -A -oN %s %s" % (logPath, target))
                response = secure_input(continuePrompt)
            elif response == "99":
                pass
            else:
                self.menu(target)
        except KeyboardInterrupt:
            self.menu(target)


class setoolkit:
    def __init__(self):
        self.installDir = toolDir + "setoolkit"
        self.gitRepo = "https://github.com/trustedsec/social-engineer-toolkit.git"

        if not self.installed():
            self.install()
            self.run()
        else:
            print(alreadyInstalled)
            self.run()
        response = secure_input(continuePrompt)

    @staticmethod
    def installed():
        return os.path.isfile("/usr/bin/setoolkit")

    def install(self):
        os.system("apt-get --force-yes -y install git apache2 python-requests libapache2-mod-php \
            python-pymssql build-essential python-pexpect python-pefile python-crypto python-openssl")
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("cd %s && python setup.py install" % self.installDir)

    @staticmethod
    def run():
        os.system("setoolkit")


class host2ip:
    host2ipLogo = '''
    88  88  dP"Yb  .dP"Y8 888888 oP"Yb. 88 88""Yb
    88  88 dP   Yb `Ybo."   88   "' dP' 88 88__dP
    888888 Yb   dP o.`Y8b   88     dP'  88 88"""
    88  88  YbodP  8bodP'   88   .d8888 88 88
    '''

    def __init__(self):
        clear_scr()
        print(self.host2ipLogo)
        host = secure_input("   Enter a Host: ")
        ip = socket.gethostbyname(host)
        print("   %s has the IP of %s" % (host, ip))
        response = secure_input(continuePrompt)


class wpscan:
    wpscanLogo = '''
    Yb        dP 88""Yb .dP"Y8  dP""b8    db    88b 88
     Yb  db  dP  88__dP `Ybo." dP   `"   dPYb   88Yb88
      YbdPYbdP   88"""  o.`Y8b Yb       dP__Yb  88 Y88
       YP  YP    88     8bodP'  YboodP dP""""Yb 88  Y8
    '''

    def __init__(self):
        self.installDir = toolDir + "wpscan"
        self.gitRepo = "https://github.com/wpscanteam/wpscan.git"

        if not self.installed():
            self.install()
        clear_scr()
        print(self.wpscanLogo)
        target = secure_input("   Enter a Target: ")
        self.menu(target)

    def installed(self):
        return os.path.isdir(self.installDir)

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def menu(self, target):
        clear_scr()
        print(self.wpscanLogo)
        print("   WPScan for: %s\n" % target)
        print("   {1}--Username Enumeration [--enumerate u]")
        print("   {2}--Plugin Enumeration [--enumerate p]")
        print("   {3}--All Enumeration Tools [--enumerate]\n")
        print("   {99}-Return to information gathering menu \n")
        response = secure_input("wpscan ~# ")
        clear_scr()
        logPath = "../../logs/wpscan-" + \
                  strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        wpscanOptions = "--no-banner --random-agent --url %s" % target
        try:
            if response == "1":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate u --log %s" % (wpscanOptions, logPath))
                response = secure_input(continuePrompt)
            elif response == "2":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate p --log %s" % (wpscanOptions, logPath))
                response = secure_input(continuePrompt)
            elif response == "3":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate --log %s" % (wpscanOptions, logPath))
                response = secure_input(continuePrompt)
            elif response == "99":
                pass
            else:
                self.menu(target)
        except KeyboardInterrupt:
            self.menu(target)


class CMSmap:
    CMSmapLogo = '''
     dP""b8 8b    d8 .dP"Y8 8b    d8    db    88""Yb
    dP   `" 88b  d88 `Ybo." 88b  d88   dPYb   88__dP
    Yb      88YbdP88 o.`Y8b 88YbdP88  dP__Yb  88"""
     YboodP 88 YY 88 8bodP' 88 YY 88 dP""""Yb 88
    '''

    def __init__(self):
        self.installDir = toolDir + "CMSmap"
        self.gitRepo = "https://github.com/Dionach/CMSmap.git"

        if not self.installed():
            self.install()
        clear_scr()
        print(self.CMSmapLogo)
        target = secure_input("   Enter a Target: ")
        self.run(target)
        response = secure_input(continuePrompt)

    def installed(self):
        return os.path.isdir(self.installDir)

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def run(self, target):
        logPath = "logs/cmsmap-" + \
                  strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        try:
            os.system("python %s/cmsmap.py -t %s -o %s" %
                      (self.installDir, target, logPath))
        except:
            pass


class XSStrike:
    XSStrikeLogo = '''
    Yb  dP .dP"Y8 .dP"Y8 888888 88""Yb 88 88  dP 888888
     YbdP  `Ybo." `Ybo."   88   88__dP 88 88odP  88__
     dPYb  o.`Y8b o.`Y8b   88   88"Yb  88 88"Yb  88""
    dP  Yb 8bodP' 8bodP'   88   88  Yb 88 88  Yb 888888
    '''

    def __init__(self):
        self.installDir = toolDir + "XSStrike"
        self.gitRepo = "https://github.com/UltimateHackers/XSStrike.git"

        if not self.installed():
            self.install()
        clear_scr()
        print(self.XSStrikeLogo)
        self.run()
        response = secure_input(continuePrompt)

    def installed(self):
        return os.path.isdir(self.installDir)

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("pip install -r %s/requirements.txt" % self.installDir)

    def run(self):
        os.system("python %s/xsstrike" % self.installDir)


class doork:
    doorkLogo = '''
    8888b.   dP"Yb   dP"Yb  88""Yb 88  dP
     8I  Yb dP   Yb dP   Yb 88__dP 88odP
     8I  dY Yb   dP Yb   dP 88"Yb  88"Yb
    8888Y"   YbodP   YbodP  88  Yb 88  Yb
    '''

    def __init__(self):
        self.installDir = toolDir + "doork"
        self.gitRepo = "https://github.com/AeonDave/doork.git"

        if not self.installed():
            self.install()
        clear_scr()
        print(self.doorkLogo)
        target = secure_input("   Enter a Target: ")
        self.run(target)
        response = secure_input(continuePrompt)

    def installed(self):
        return os.path.isdir(self.installDir)

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("pip install beautifulsoup4 requests Django==1.11")

    def run(self, target):
        if not "http://" in target:
            target = "http://" + target
        logPath = "logs/doork-" + \
                  strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        try:
            os.system("python %s/doork.py -t %s -o %s" %
                      (self.installDir, target, logPath))
        except KeyboardInterrupt:
            pass


class crips:
    cripsLogo = '''
     dP""b8 88""Yb 88 88""Yb .dP"Y8
    dP   `" 88__dP 88 88__dP `Ybo."
    Yb      88"Yb  88 88"""  o.`Y8b
     YboodP 88  Yb 88 88     8bodP'
    '''

    def __init(self):
        self.installDir = toolDir + "Crips"
        self.gitRepo = "https://github.com/Manisso/Crips.git"

        if not self.installed():
            self.install()
        clear_scr()
        print(self.cripsLogo)
        self.run()

    def installed(self):
        return os.path.isdir(self.installDir) or os.path.isdir("/usr/share/doc/Crips")

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("bash %s/install.sh" % self.installDir)

    def run(self):
        try:
            os.system("crips")
        except:
            pass
