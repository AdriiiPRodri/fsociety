# -*- coding: utf-8 -*-

from .common import toolDir, clear_scr, secure_input
import os

class brutex:
    def __init__(self):
        self.installDir = toolDir + "brutex"
        self.gitRepo = "https://github.com/1N3/BruteX.git"

        if not self.installed():
            self.install()
        clear_scr()
        self.run()

    def installed(self):
        return os.path.isdir(self.installDir)

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        if not os.path.isdir("/usr/share/brutex"):
            os.makedirs("/usr/share/brutex")
        os.system("cd %s && chmods +x install.sh && ./install.sh" % self.installDir)

    @staticmethod
    def run():
        target = secure_input("Enter Target IP: ")
        os.system("brutex %s" % target)