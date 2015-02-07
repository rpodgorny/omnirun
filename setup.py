from setuptools import setup, find_packages

from omnirun import __version__

setup(
	name = 'omnirun',
	version = __version__,
	description = 'run command on many hosts',
	url = 'https://github.com/rpodgorny/omnirun',
	author = 'Radek Podgorny',
	author_email = 'radek@podgorny.cz',
	license = 'GPL',
	packages = find_packages(),
	entry_points = {
		'console_scripts': ['omnirun=omnirun:main', ],
	},
	test_suite = 'tests',
)
