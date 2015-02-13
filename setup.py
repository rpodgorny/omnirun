from setuptools import setup, find_packages

from omnirun.version import __version__

setup(
	name = 'omnirun',
	version = __version__,
	description = 'run command on many hosts',
	url = 'https://github.com/rpodgorny/omnirun',
	author = 'Radek Podgorny',
	author_email = 'radek@podgorny.cz',
	license = 'GPL',
	#packages = find_packages(exclude=['contrib', 'docs', 'tests', 'tests*', ]),
	packages = ['omnirun', ],
	install_requires = ['docopt', ],
	extras_require = {
		'tests': ['coverage', ],
	},
	package_data = {
		'omnirun': ['version.py', ],
	},
	entry_points = {
		'console_scripts': ['omnirun=omnirun.main:main', ],
	},
	test_suite = 'tests',
)
