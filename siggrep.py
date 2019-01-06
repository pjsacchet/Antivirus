# @author - Patrick Sacchet
# @version - 1.0 - 01/04/2019
# Goal - Implement anitvirus usserface that will recursively go through user directories and use Yara signature files to identify malicious files
# How:
# Step 1: Implement proper directory searching functionality based on OS
# Step 2: Implement Yara recognition to correctly identify malicious files based on given signature files

import sys
import os
import time
import yara



def yara_sig_check(file):
    print("Will check file with rule file(s)")


# Function will search through user's entire computer, checking files appropiately
def dir_search(user_dir):
    timer_start = time.time()
    file_number = 0
    for root, dirs, files in os.walk(user_dir, topdown=True):
        for name in files:
            print("File found: " + name)
            # Call function to check Yara signature
            file_number += 1
    timer_end = time.time()
    total_time = timer_end - timer_start
    print("Time taken to scan whole system: " + str(total_time))
    print("Total files found: " + str(file_number))
    # Windows (Command: dir /s /a-d c:\) found 600836 files, this found 584755 files ---> Is this truly finding ALL files?


# Function will detect the system configuration of the user and return a string representing said os
# @return: OS type - Will identify User's OS type and return a string representation
def get_os_type():
    os = sys.platform
    if(os == "win32"):
        print("Platform detedted: Windows")
        print("Executing commands... ")
        time.sleep(3)
        return "windows"
    if(os == "linux"):
        print("Platform detected: Linux")
        print("Executing commands... ")
        time.sleep(3)
        return "linux"
    if(os == "darwin"):
        print("Platform detected: Mac")
        print("Executing commands... ")
        time.sleep(3)
        return "mac"
    if(os == "cygwin"):
        print("Platform detected: Windows/Cygwin")
        print("Executing commands... ")
        time.sleep(3)
        return "cygwin"
    else:
        print("Platform not detected, exiting...")
        sys.exit()

def main():
    #Will recursively go through user files initially
        # Grab user direcotry, call recursive directory search function, compare using yara rules file(s)
    #print ("Current working directory: " + os.getcwd())
    print("Attempting to detect your system configuration... ")
    os = get_os_type()
    if (os == "windows"):
        dir = "C:\\"
        dir_search(dir)



main()