# -*- coding: utf-8 -*-

import os
import urllib
import random

try:
    import ConfigParser
except:
    import configparser as ConfigParser

"""
Common Functions
"""


class Color:
    HEADER = '\033[95m'
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'
    LOGGING = '\33[34m'


def clear_scr():
    os.system('clear')


def yes_or_no():
    return secure_input("Continue Y / N: ") in yes

"""
Config
"""
installDir = '/'.join(os.path.dirname(os.path.abspath(__file__)).split('/')[0:-1]) + '/'
configFile = os.path.join(installDir, "fsociety.cfg")
config = ConfigParser.RawConfigParser()
config.read(configFile)

toolDir = installDir + config.get('fsociety', 'toolDir')
logDir = installDir + config.get('fsociety', 'logDir')
yes = config.get('fsociety', 'yes').split()
color_random = [Color.HEADER, Color.IMPORTANT, Color.NOTICE, Color.BLUE, Color.GREEN, Color.WARNING, Color.RED,
                Color.END, Color.UNDERLINE, Color.LOGGING]
random.shuffle(color_random)
fsocietylogo = color_random[0] + '''
        d88888b .d8888.  .d88b.   .o88b. d888888b d88888b d888888b db    db
        88'     88'  YP .8P  Y8. d8P  Y8   `88'   88         88    `8b  d8'
        88ooo   `8bo.   88    88 8P         88    88ooooo    88     `8bd8'
        88        `Y8b. 88    88 8b         88    88         88       88
        88      db   8D `8b  d8' Y8b  d8   .88.   88.        88       88
        YP      `8888Y'  `Y88P'   `Y88P' Y888888P Y88888P    YP       YP
        '''
fsociety_prompt = "fsociety ~# "
alreadyInstalled = "Already Installed"
continuePrompt = "\nClick [Return] to continue"

termsAndConditions = Color.NOTICE + '''
I shall not use fsociety to:
(i) upload or otherwise transmit, display or distribute any
content that infringes any trademark, trade secret, copyright
or other proprietary or intellectual property rights of any
person; (ii) upload or otherwise transmit any material that contains
software viruses or any other computer code, files or programs
designed to interrupt, destroy or limit the functionality of any
computer software or hardware or telecommunications equipment;
''' + Color.END

"""
Starts Menu Classes
"""


def secure_input(message):
    try:
        # Python2
        user_input = raw_input(message)
    except:
        # Python3
        user_input = input(message)

    return user_input


def agreement():
    while not config.getboolean("fsociety", "agreement"):
        clear_scr()
        print(termsAndConditions)
        agree = secure_input("You must agree to our terms and conditions first (Y/n) ")
        if agree.lower() in yes:
            config.set('fsociety', 'agreement', 'true')
            return True
        else:
            return False
    
    return True
