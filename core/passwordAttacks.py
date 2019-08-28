# -*- coding: utf-8 -*-

from .common import clear_scr, secure_input, toolDir
import fsociety
from .webHacking import brutex

import os

"""
Password Attack Tools Classes
"""


class passwordAttacksMenu:
    menuLogo = '''
    88""Yb    db    .dP"Y8 .dP"Y8 Yb        dP 8888b.
    88__dP   dPYb   `Ybo." `Ybo."  Yb  db  dP   8I  Yb
    88"""   dP__Yb  o.`Y8b o.`Y8b   YbdPYbdP    8I  dY
    88     dP""""Yb 8bodP' 8bodP'    YP  YP    8888Y"
    '''

    def __init__(self):
        clear_scr()
        print(self.menuLogo)
        print("   {1}--Cupp - Common User Passwords Profiler")
        print("   {2}--BruteX - Automatically bruteforces all services running on a target\n")
        print("   {99}-Back To Main Menu \n")
        choice3 = secure_input("passwd ~# ")

        clear_scr()
        if choice3 == "1":
            cupp()
        elif choice3 == "2":
            brutex()
        elif choice3 == "99":
            fsociety.fsociety.Fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        secure_input("Completed, click return to go back")
        self.__init__()


class cupp:
    cuppLogo = '''
     dP""b8 88   88 88""Yb 88""Yb
    dP   `" 88   88 88__dP 88__dP
    Yb      Y8   8P 88"""  88"""
     YboodP `YbodP' 88     88
     '''

    def __init__(self):
        self.installDir = toolDir + "cupp"
        self.gitRepo = "https://github.com/Mebus/cupp.git"

        if not self.installed():
            self.install()
        clear_scr()
        print(self.cuppLogo)
        self.run()

    def installed(self):
        return os.path.isdir(self.installDir)

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def run(self):
        os.system("python %s/cupp.py -i" % self.installDir)
