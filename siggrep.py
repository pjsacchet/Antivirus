# @author - Patrick Sacchet
# @version - 1.0 - 01/04/2019
# PLEASE NOTE:
    # In developing this program Python verison 23.5.1 and Yara 3.8.1 were used
# Goal - Implement anitvirus usserface that will recursively go through user directories and use Yara signature files to identify malicious files
# How:
# Step 1: Implement proper directory searching functionality based on OS
# Step 2: Implement Yara recognition to correctly identify malicious files based on given signature files

import sys
import os
import time
import yara
from pathlib import Path
from threading import Thread

# Function will write the file given to it, ensuring we open and immediately close for security measures
# @param: filename - Name of the file to write to
# @return: None
def write_file(filename, string):
    output_file = open(filename, "a+")
    output_file.write(string)
    output_file.close()
    return

# Purpose of this function will be to create a dictionary of Yara rule files to feed to the Yara compile funciton
# @param: rule_path - Path to the directory of all rule files
# @return: Dictionary containing all Yara rule files
def mk_dict(rule_path):
    # Will take the directory containing all signature files anc create a dictionary with the keys as the filenames, and values as their path values
    rule_dict = {}
    for file in os.listdir(rule_path):
        filepath = os.path.join(rule_path, file)
        rule_dict[file] = filepath
    return rule_dict

# Function will open the filepath to the Yara rule files, compile them, and check to see if they match any of the files
# @param:  file - file to check match for with Yara rules
# @param: rules - rules object compiled via Yara
# @return: file if hit
def yara_sig_check(file, rules):
    try:
        ### Need something for accessing files with restrictions on access ###
        # Will scan the file for 60 seconds, any longer it will move on to the next file
        matches = rules.match(file, timeout=60)
        if (len(matches) > 0):
            # Grab proper filename not directory
            filename = os.path.splitext(os.path.basename(file))[0]
            string = "File was hit: " + filename + " with rule: " + str(matches[0]) + "\n"
            write_file("siggrep_output.txt", string)
            print("File was hit: " + filename + " with rule: " + str(matches[0]))
            return file
    except:
        print("Seems like there was an error with permissions")

# Function will search through user's entire computer, checking files appropriately
# @param: user_dir - Directory of the user's OS (should be base directory so we can search entire system)
# @param: rule_dict - Dictionary containing all rule files for Yara to compile
# @return: None (printing information on files, time to search, and scanning each file with Yara signatures
def dir_search(user_dir, rule_dict):
    hit_files = []
    timer_start = time.time()
    file_number = 0
    # Compile Yara rules before starting scan
    rules = yara.compile(filepaths = rule_dict)
    for root, dirs, files in os.walk(user_dir, topdown=True):
        for name in files:
            print("Scanning file: " + name)
            # Call function to check file with Yara signatures
            file_path = os.path.realpath(os.path.join(root, name))
            scanned_file = (yara_sig_check(file_path, rules))
            # Don't add the file to the list if it wasn't flagged/was already added
            if(scanned_file != None and hit_files.__contains__(scanned_file) == False):
                scanned_file = os.path.splitext(os.path.basename(scanned_file))[0]
                hit_files.append(scanned_file)
            file_number += 1
    timer_end = time.time()
    total_time = timer_end - timer_start
    print("--------------------------------------------------------------------------------")
    print("This program discovered " + str(len(hit_files)) + " malicious files.")
    print("Please note: all malicious files that were identified can be found in 'siggrep_output.txt'")
    print("Time taken to scan whole system: " + str(total_time))
    print("Total files found: " + str(file_number))
    print("--------------------------------------------------------------------------------")
    # Windows (Command: dir /s /a-d c:\) found 600836 files, this found 584755 files ---> Is this truly finding ALL files?

# Function will grab proper directory depending on OS type
# @param: os_type - Type of OS which will tell us which directory location we should use for Yara rule files
# #return - Directory path for Yara rules
def get_rule_dir(os_type):
    # Check os type from os function and return the proper rule path dependent on the OS
    if(os_type == "windows"):
        rule_path = Path("C:/Users/Admin/Projects/Antivirus/rule_files")
        print(rule_path)
        return rule_path
    if (os_type == "mac"):
        rule_path = "/Users/patricksacchet/PycharmProjects/Antivirus/rule_files/"
        return rule_path
    if(os_type.startswith("linux")):
        rule_path = "/home/pjsacchet/PycharmProjects/Antivirus/rule_files/"
        return rule_path
    return

# Function will detect the system configuration of the user and return a string representing said os
# @param: None
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
    # Will find user's type of OS and search through entire system, recording number of files, time taken to scan and files that were hit
    # Should I compile rules as this runs? --> Check for updates on server then compile new rules
    print("Attempting to detect your system configuration... ")
    time.sleep(3)
    os = get_os_type()
    output_file = open("siggrep_output.txt", "w+")
    output_file.close()
    # For any OS, get the proper rule path, create a dictionary with the rule files, and search through the user's computer
    if (os == "windows"):
        dir = "C:\\"
        rule_path = get_rule_dir(os)
        rule_dict = mk_dict(rule_path)
        dir_search(dir, rule_dict)
    if (os == "mac"):
        dir = "/Users/"
        rule_path = get_rule_dir(os)
        rule_dict = mk_dict(rule_path)
        dir_search(dir, rule_dict)
    # Only want to search my folder on school computers
    if (os == "linux"):
        dir = "/home/pjsacchet"
        rule_path = get_rule_dir(os)
        rule_dict = mk_dict(rule_path)
        dir_search(dir, rule_dict)

if __name__ == "__main__":
    main()
