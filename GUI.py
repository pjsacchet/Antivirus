# @author - Patrick Sacchet (pjsacchet)
# @version - 1.0 - 1/21/19
# PLEASE NOTE:
    # In developing this program Python verison 2.7.14 and Yara 3.8.1 were used
# Goal - Implement GUI that will import functionality from siggrep.py and provide an interface for the user
# How:
# Step 1: Create plain text box with scan button, if pressed will begin scan
# Step 2: Edit appearance of the box, make larger for user


import Tkinter
import subprocess
import siggrep
import textwrap
from threading import Thread
import sys
from Queue import Queue, Empty


def iter_except(function, exception):
    try:
        while True:
            yield function
    except exception:
        return

# Attempting to use multithreading to display the output from the command line in the window for the user
class DisplaySubproccessOutput:


    def __init__(self, root):
        self.root = root
        self.process = subprocess.Popen([sys.executable, "-u", "-c", textwrap.dedent("""
        import itertools, time
        
        for i in itertools.count():
            print("%d.%d" % divmod(i, 10))
            time.sleep(0.1)
            
        """)], stdout=subprocess.PIPE)

        q = Queue(maxsize = 1024)
        t = Thread(target = self.reader_thread, args = [q] )
        t.daemon = True
        t.start()
        self.label = Tkinter.Label(root, text = " ", font = (None, 200))
        self.label.pack(ipadx = 4, padx = 4, ipady = 4, pady = 4, fill = 'both')
        self.update(q)


    def reader_thread(self, q):
        try:
            with self.process.stdout as pipe:
                for line in iter(pipe.readline, b''):
                    q.put(line)
        finally:
            q.put(None)


    def update(self, q):
        for line in iter_except(q.get_nowait, Empty):
            if line is None:
                self.quit()
                return
            else:
                self.label['text'] = line
                break
        self.root.after(40, self.update, q)


    def quit(self):
        self.process.kill()
        self.root.destroy()






# Adding top portion of window
top = Tkinter.Tk()
top.title("Antivirus")
top.geometry("500x300")

app = DisplaySubproccessOutput(top)
top.protocol("WM_DELETE_WINDOW", app.quit)

top.eval('tk::PlaceWindow %s center' % top.winfo_pathname(top.winfo_id()))





# Adding button

#B1 = Tkinter.Button(top, text = "Run Scan", width = 25,  command = lambda : siggrep.main())

#B1.pack()

top.mainloop()