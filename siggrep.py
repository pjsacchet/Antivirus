# @author - Patrick Sacchet
# @version - 1.0 - 01/04/2019
# Goal - Implement anitvirus usserface that will recursively go through user directories and use Yara signature files to identify malicious files
# How:
# Step 1: Implement Yara recognition to correctly identify malicious files based on given signature files

import sys
import os
import yara

# Function wil;l recursively search through the files in the users directory
# @param: user_dir - Directory path of the user files
def dir_rec_search(user_dir):
    if(os.path.isdir(user_dir)):
        try:
            for file in os.listdir(user_dir):
                print ("Filename: " + file)
                new_dir = user_dir + "/" + file
                print("Attempting to access: " + new_dir)
                dir_rec_search(new_dir)
        except:
            print("Not allowed access apparently")
    else:
        for file in os.listdir(user_dir):
            print("File found: " + file)


# Function will detect the system configuration of the user and return a string representing said os
# @return: OS type - Will identify User's OS type and return a string representation
def get_os_type():
    os = sys.platform
    if(os == "win32"):
        print("Platform detedted: Windows")
        print("Executing commands... ")
        return "windows"
    if(os == "linux"):
        print("Platform detected: Linux")
        print("Executing commands... ")
        return "linux"
    if(os == "darwin"):
        print("Platform detected: Mac")
        print("Executing commands... ")
        return "mac"
    if(os == "cygwin"):
        print("Platform detected: Windows/Cygwin")
        print("Executing commands... ")
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
        print (dir)
        dir_rec_search(dir)



main()