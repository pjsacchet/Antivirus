# @author - Patrick Sacchet (pjsacchet)
# @version - 1.0 - 1/21/19
# PLEASE NOTE:
    # In developing this program Python verison 3.5.1 and Yara 3.8.1 were used
# Goal - Implement GUI that will import functionality from siggrep.py and provide an interface for the user
# How:
# Step 1: Create plain text box with scan button, if pressed will begin scan
# Step 2: Edit appearance of the box, make larger for user


import tkinter
from tkinter import *
from tkinter import ttk
import siggrep





# Adding top portion of window
root = Tk()
root.title("Antivirus")
root.geometry("500x300")

mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column = 0, row = 0, sticky = (N, W, E, S))
# Configure window properly if adjusted
root.columnconfigure(0, weight = 1)
root.rowconfigure(0, weight = 1)


# Adding button ---> drop down box
scanButton = ttk.Button(root, text = "Run Scan", width = 25,  command = lambda : siggrep.main()).grid(column = 0, row = 0)

progressBar = ttk.Progressbar(root, orient = "horizontal", length = 200,  mode = "indeterminate").grid(column = 0, row = 0, sticky = S)









root.mainloop()