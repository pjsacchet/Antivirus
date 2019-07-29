# @author - Patrick Sacchet
# @version - 1.0 - 7/28/2019
# Implementing unit tests for all functions within siggrep.py
import coverage
import unittest
import siggrep
import os

class SiggrepTest(unittest.TestCase):

    def testwrite_file(self):
        siggrep.write_file("testfile", "this is a test")
        self.assertTrue(os.path.exists("testfile") == True)


if __name__ == '__main__':
    unittest.main()
