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

# Function will open the filepath to the Yara rule files, compile them, adn check to see if they match any of the files
# @param:  file - file to check match for with Yara rules
# @return: None (printing result/writing to log)
def yara_sig_check(file):
    try:
        # MAC RULE PATH
        # rule_path = "/Users/patricksacchet/PycharmProjects/Antivrus/rule_files/rules"
        # WINDOWS RULE PATH (need to use raw string)
        # rule_path = r"C:\Users\Patrick\rule_files"
        # LINUX RULE PATH
        rule_path = "/home/pjsacchet/PycharmProjects/Antivrus/rule_files/rules"
        ### Need something for accessing files with restrictions on access ###
        ### Compile Yara rule files (if multiple files, I need to add to a dict) ###
        rules = yara.compile(filepath = rule_path)
        # Will scan the file for 60 seconds, any longer it will move on to the next file
        matches = rules.match(file, timeout = 60)
        if (len(matches) > 0):
            # Grab proper filename not directory 
            print("File was hit: " + file)
            time.sleep(5)
            sys.exit(1)
    except :
        print("Seems like there was an error with permissions")



# Function will search through user's entire computer, checking files appropriately
# @param: user_dir - Directory of the user's OS (should be base directory so we can search entire system)
# @return: None (printing information on files, time to search, and scanning each file with Yara signatures
def dir_search(user_dir):
    timer_start = time.time()
    file_number = 0
    for root, dirs, files in os.walk(user_dir, topdown=True):
        for name in files:
            print("Scanning file: " + name)
            # Call function to check file with Yara signatures
            file_path = os.path.realpath(os.path.join(root, name))
            yara_sig_check(file_path)
            file_number += 1
    timer_end = time.time()
    total_time = timer_end - timer_start
    print("Time taken to scan whole system: " + str(total_time))
    print("Total files found: " + str(file_number))
    # Windows (Command: dir /s /a-d c:\) found 600836 files, this found 584755 files ---> Is this truly finding ALL files?

# Function will grab proper directory depending on OS type
# @param: os_type - Type of OS which will tell us which directory location we should use for Yara rule files
# #return - Directory path for Yara rules
def get_rule_dir(os_type):
    # Check os type from os function
    # Return proper path for yara sig check function
    # MAC RULE PATH
    # rule_path = "/Users/patricksacchet/PycharmProjects/Antivrus/rule_files/rules"
    # WINDOWS RULE PATH (need to use raw string)
    # rule_path = r"C:\Users\Patrick\rule_files"
    # LINUX RULE PATH
    # rule_path = "/home/pjsacchet/PycharmProjects/Antivrus/rule_files/rules"
    return;

# Function will detect the system configuration of the user and return a string representing said os
# @return: OS type - Will identify User's OS type and return a string representation
def get_os_type():
    os = sys.platform
    if(os == "win32"):
        print("Platform detedted: Windows")
        print("Executing commands... ")
        time.sleep(3)
        return "windows"
    if(os.startswith("linux")):
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
    # Will find user's type of OS and search through entire system, recording number of files and time taken to scan
    # Should I compile rules as this runs? --> Check for updates on server then compile new rules
    print("Attempting to detect your system configuration... ")
    os = get_os_type()
    if (os == "windows"):
        dir = "C:\\"
        dir_search(dir)
    if (os == "mac"):
        dir = "/"
        dir_search(dir)
    # Only want to search my folder on school computers
    if (os == "linux"):
        dir = "/home/pjsacchet"
        dir_search(dir)


if __name__ == "__main__":
    main()