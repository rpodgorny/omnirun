import unittest
import omnirun.main


class MyTestCase(unittest.TestCase):
	def test_expand_host(self):
		self.assertEqual(len(omnirun.main.expand_host('192.168.100.[1-100]')), 100)

	def test_hostspec_to_user_pass_host_port(self):
		self.assertEqual(omnirun.main.hostspec_to_user_pass_host_port('user:pass@host:4444'), ('user', 'pass', 'host', 4444))
		self.assertEqual(omnirun.main.hostspec_to_user_pass_host_port('user@host:4444'), ('user', None, 'host', 4444))
		self.assertEqual(omnirun.main.hostspec_to_user_pass_host_port('host:4444'), (None, None, 'host', 4444))
		self.assertEqual(omnirun.main.hostspec_to_user_pass_host_port('host'), (None, None, 'host', None))

