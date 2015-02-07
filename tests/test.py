import unittest

import omnirun

class MyTestCase(unittest.TestCase):
	def test_test(self):
		omnirun.expand_host('192.168.100.[1-100]')
	#enddef
#endclass

