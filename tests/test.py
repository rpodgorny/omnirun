import unittest

import omnirun.main

class MyTestCase(unittest.TestCase):
	def test_test(self):
		omnirun.main.expand_host('192.168.100.[1-100]')
	#enddef
#endclass

