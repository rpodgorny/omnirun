#!/usr/bin/python3

'''
Omnirun. Run command on multiple hosts.

Usage:
  omnirun [options]
  omnirun [options] <command>
  omnirun [options] [--sudo] --script <script>
  omnirun [options] --copy-keys

Options:
  -H <host1,host2,...>           Comma sparated list of hosts to connect to.
  -T <tag>                       Only consider hosts with <tag>.
  --user=<user>                  Username to use for the remote host.
  --pass=<pass>                  Password to use for sshpass.
  --no-strict-host-key-checking  Disable ssh host key checking.
  --interactive                  Interactive mode. You have to disconnect manually.
  -p <num>                       Number of parallel processes to run.
  --single                       Run in single thread - skip tmux at all.
  --sudo                         Use sudo on remote system.
  --copy-keys                    Copy local ssh keys to remote servers.
  -t                             Force tty allocation on the remote host (add -t to ssh options).
  --keep-open=<0,1,2,...,unknown,nonzero>
                                 Keep the window open when exit status is among the enumerated.

Arguments:
  <command>  Command to run.
'''

from omnirun import __version__

import sys
import docopt
import os
import pwd
import socket
import time
import subprocess
import re


TMUX = '/usr/bin/tmux'
SSHPASS = '/usr/bin/sshpass'
#PUB_KEY_FN = os.path.expanduser('~/.ssh/id_ecdsa.pub')
MAX_FORKS = 10
DEBUG = 0


class color:
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'
#endclass


def get_hosts():
	lines = [
		'admiral.podgorny.cz arch linux podgorny',
		'berta.podgorny.cz arch arm linux podgorny',
		'chuck.podgorny.cz arch linux podgorny',
		'europa.podgorny.cz arch arm linux podgorny router',
		'hubert.asterix.cz arch asterix linux',
		'kulicka.podgorny.cz arch arm linux podgorny',
		'milan.podgorny.cz arch arm linux podgorny',
		'milhouse.podgorny.cz arch linux podgorny sureboot',
		'mj[1-200].asterix.cz asterix atx300 windows',
		'mj[1-2000]d.asterix.cz asterix windows',
		'mrtvola.asterix.cz arch asterix linux',
		'orion.asterix.cz arch asterix linux sureboot',
		'pimiento.podgorny.cz arch linux podgorny',
		'kapitan.podgorny.cz gentoo linux podgorny',
		'krutor.podgorny.cz arch linux',
		'pokuston.podgorny.cz arch arm linux podgorny',
		'rpodgorny.podgorny.cz arch linux podgorny',
		'simir.podgorny.cz arch linux podgorny',
		'taurus.asterix.cz arch asterix linux router',
		'ucho.podgorny.cz arch arm linux podgorny',
		'zombie.asterix.cz arch linux asterix',
	]

	lines_exp = []
	for line in lines:
		lines_exp.extend(expand_host(line))
	#endfor

	ret = {}
	for i in lines_exp:
		host, *tags = i.split()
		if not host in ret: ret[host] = set()
		ret[host] |= set(tags)
	#endfor

	return ret
#enddef


def expand_host(s):
	if not '[' in s or not '-' in s or not ']' in s: return [s, ]

	pre = s.split('[')[0]
	post = s.split(']')[1]

	from_ = s.split('[')[1].split('-')[0]
	to_ = s.split(']')[0].split('-')[1]
	from_ = int(from_)
	to_ = int(to_)

	ret = []
	for i in range(from_, to_ + 1):
		ret.append('%s%s%s' % (pre, i, post))
	#endfor

	return ret
#enddef


def check_pub_key(fn):
	with open(fn, 'r') as f:
		line = f.readline()
	#endwith

	user_and_host = line.split()[-1]
	user, host = user_and_host.split('@')

	if user != pwd.getpwuid(os.getuid())[0]: return False
	if host != socket.gethostname(): return False

	return True
#enddef


def tmux_window_statuses():
	ret = {}

	res = subprocess.check_output([TMUX, 'list-windows', '-F', '#{window_id} #{pane_dead} #{pane_dead_status}'], universal_newlines=True)

	for line in res.split('\n'):
		if not line: continue

		w_id, pane_dead, *rest = line.split()

		pane_dead = {'0': False, '1': True}[pane_dead]

		# no status is shown for live panes (or when using old version of tmux)
		if rest:
			pane_dead_status = int(rest[0])
		else:
			pane_dead_status = None
		#endif

		ret[w_id] = (pane_dead, pane_dead_status)
	#endfor

	return ret
#enddef


def tmux_new_window(name, cmd=None):
	lst = [TMUX, 'new-window', '-n', name, '-P', '-F', '#{window_id}', '-d']
	if cmd:
		lst.append(cmd)
	#endif
	res = subprocess.check_output(lst, universal_newlines=True)
	return res.split('\n')[0]
#enddef


def tmux_kill_window(w_id):
	res = subprocess.check_call([TMUX, 'kill-window', '-t', ':%s' % w_id], universal_newlines=True)
#enddef


def tmux_send_keys(w_id, cmd, enter=True):
	lst = [TMUX, 'send-keys', '-t', ':%s' % w_id, '-l', cmd]
	if enter:
		lst.extend([';', 'send-keys', '-t', ':%s' % w_id, 'Enter'])
	#endif
	res = subprocess.check_output(lst, universal_newlines=True)
#enddef


def tmux_respawn_pane(w_id, cmd):
	res = subprocess.check_output([TMUX, 'respawn-pane', '-t', ':%s' % w_id, '-k', cmd], universal_newlines=True)
#enddef


def tmux_capture_pane(w_id):
	res = subprocess.check_output([TMUX, 'capture-pane', '-t', ':%s' % w_id, '-p'], universal_newlines=True)
#enddef


def tmux_set_window_option(w_id, option, value):
	# TODO: why is the window_id format different here?
	res = subprocess.check_call([TMUX, 'set-window-option', '-t', '%s' % w_id, option, value], universal_newlines=True)
#enddef


def main():
	args = docopt.docopt(__doc__, version=__version__)

	#if args['--copy-keys'] and not check_pub_key(PUB_KEY_FN):
	#	raise Exception('i don\'t like the public key')
	#endif

	if args['-H']:
		hosts = set(args['-H'].split(','))

		expanded_hosts = set()
		for host in hosts:
			expanded_hosts |= set(expand_host(host))
		#endfor

		hosts = expanded_hosts
	else:
		tag = args['-T']

		hosts = set()
		for host, tags in get_hosts().items():
			if not tag or tag in tags:
				hosts.add(host)
			#endif
		#endfor
	#endif

	sshopts = ''
	#sshopts += ' -o ConnectTImeout=2'

	# TODO: the -t seems to be breaking logins to windows machines - figure shomething out
	if args['-t']:
		sshopts += ' -t'
	#endif

	if args['--no-strict-host-key-checking']:
		sshopts += ' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
	#endif

	cmds = {}
	for host in hosts:
		if args['--user']:
			host_full = '%s@%s' % (args['--user'], host)
		else:
			host_full = host
		#endif

		if args['--copy-keys']:
			#cmd = 'ssh-copy-id -i %s %s' % (PUB_KEY_FN, host_full)
			cmd = 'ssh-copy-id %s' % (host_full, )
		elif args['<script>']:
			if args['--sudo']:
				sudo = 'sudo'
			else:
				sudo = ''
			#endif

			tmp_fn = '/tmp/omnirun.%s' % int(time.time())

			if args['<script>'].startswith('http://') \
			or args['<script>'].startswith('https://'):
				cmd = 'ssh {sshopts} {host_full} "mkdir {tmp_fn} && cd {tmp_fn}; wget -O {tmp_fn}/script --no-check-certificate \"{script}\" && chmod a+x script && {sudo} ./script && cd - && rm -rf {tmp_fn}"'.format( \
				sshopts=sshopts, host_full=host_full, tmp_fn=tmp_fn, script=args['<script>'], sudo=sudo)
			else:
				cmd = 'ssh {sshopts} {host_full} "mkdir {tmp_fn} && cat >{tmp_fn}/script && chmod a+x ./script && {sudo} ./script && cd - && rm -rf {tmp_fn}" <{script}'.format( \
				sshopts=sshopts, host_full=host_full, tmp_fn=tmp_fn, sudo=sudo, script=args['<script>'])

				# these are some other tries - probably broken or half-working...
				#cmd = 'ssh %s %s \'sh -c "a=`mktemp`; cat >$a; chmod a+x $a; %s $a; rm $a"\' <%s' % (sshopts, host_full, sudo, args['<script>'])
				#cmd = 'ssh %s %s "cat >%s; chmod a+x %s; %s %s; rm %s"' % (sshopts, host_full, tmp_fn, tmp_fn, sudo, tmp_fn, tmp_fn)
				#cmd = 'ssh %s %s "cat | %s sh"' % (sshopts, host_full, sudo)
			#endif
		elif args['<command>']:
			cmd = 'ssh %s %s "%s"' % (sshopts, host_full, args['<command>'].replace('"', '\\"'))
		else:
			cmd = 'ssh %s %s' % (sshopts, host_full)
		#endif

		if args['--pass']:
			if not os.path.isfile(SSHPASS):
				raise Exception('%s does not exist' % SSHPASS)
			#endif

			cmd = '%s -p%s %s' % (SSHPASS, args['--pass'], cmd)
		#endif

		cmds[host] = cmd
	#endfor

	exits = {}

	if not os.path.isfile(TMUX):
		print('%s%s not found, implying --single%s' % (color.RED, TMUX, color.END))
		args['--single'] = True
	#endif

	if args['--single']:
		total = len(cmds)
		i = 0
		for host in sorted(list(cmds.keys())):
			cmd = cmds[host]
			i += 1
			print('%s(%d/%d) %s%s%s' % (color.YELLOW, i, total, color.BOLD, cmd, color.END))
			exit_status = subprocess.call(cmd, shell=True)

			if not exit_status in exits: exits[exit_status] = set()
			exits[exit_status].add(host)

			if exit_status == 0:
				col = color.GREEN
			else:
				col = color.RED
			#endif

			print('%s%s -> ret: %d%s' % (col, cmd, exit_status, color.END))
		#endfor
	else:
		try:
			nprocs = int(args['-p'])
		except:
			nprocs = 10
		#endtry

		keep_open = args['--keep-open']
		if not keep_open:
			keep_open = set()
		elif ',' in keep_open:
			rcs = keep_open.split(',')
			keep_open = set()
			for rc in rcs:
				try:
					keep_open.add(int(rc))
				except:
					keep_open.add(rc)
				#endtry
			#endfor
		else:
			rc = keep_open
			keep_open = set()
			try:
				keep_open.add(int(rc))
			except:
				keep_open.add(rc)
			#endtry
		#endif

		if 'unknown' in keep_open:
			keep_open.remove('unknown')
			keep_open.add(None)
		#endif

		if 'nonzero' in keep_open:
			keep_open.remove('nonzero')
			keep_open |= set(range(1, 256))
		#endif

		cmds_to_go = cmds.copy()
		running = {}
		total = len(cmds_to_go)
		i = 0
		while 1:
			while len(running) < nprocs and cmds_to_go:
				host = sorted(list(cmds_to_go.keys()))[0]
				cmd = cmds_to_go[host]
				del cmds_to_go[host]

				if args['--interactive']:
					w_id = tmux_new_window(host)
					tmux_send_keys(w_id, cmd)
				else:
					w_id = tmux_new_window(host, cmd)
				#endif

				assert w_id

				tmux_set_window_option(w_id, 'set-remain-on-exit', 'on')

				running[w_id] = (host, cmd)

				i += 1
				print('%s(%d/%d) (%s) %s%s' % (color.YELLOW, i, total, w_id, cmd, color.END))

				'''
				if args['--interactive']:
					tmux_send_keys(w_id, cmd)
				else:
					tmux_respawn_pane(w_id, cmd)

					###if args['<script>']:
						data = open(args['<script>'], 'r').read()
						w.list_panes()[0].send_keys(data, enter=False)
						#w.list_panes()[0].send_keys('$\'\\004\'', enter=False)
						#w.list_panes()[0].tmux('send-keys', 'C-d')
					#endif
				#endif
				'''
			#endwhile

			statuses = tmux_window_statuses()

			for w_id, (is_dead, exit_status) in statuses.items():
				if not w_id in running: continue
				if not is_dead: continue

				# TODO: don't kill the window if it's currently open?
				if exit_status not in keep_open:
					tmux_kill_window(w_id)
				#endif

				host, cmd = running[w_id]

				if not exit_status in exits: exits[exit_status] = set()
				exits[exit_status].add(host)

				if exit_status is None:
					col = color.YELLOW
					exit_status = 'unknown'  # TODO: not very nice
				elif exit_status == 0:
					col = color.GREEN
				else:
					col = color.RED
				#endif

				print('%s(%s) %s -> ret: %s%s' % (col, w_id, cmd, exit_status, color.END))

				del running[w_id]
			#endfor

			for w_id in running.copy():
				if w_id in statuses: continue

				print('%s not in statuses?!? wtf!!!' % w_id)
				exit_status = None

				# TODO: this is cut-n-pasted from above. unite!
				host, cmd = running[w_id]

				if not exit_status in exits: exits[exit_status] = set()
				exits[exit_status].add(host)

				if exit_status is None:
					col = color.YELLOW
					exit_status = 'unknown'  # TODO: not very nice
				elif exit_status == 0:
					col = color.GREEN
				else:
					col = color.RED
				#endif

				print('%s(%s) %s -> ret: %s%s' % (col, w_id, cmd, exit_status, color.END))

				del running[w_id]
			#endfor

			if not running and not cmds_to_go: break

			time.sleep(1)
		#endwhile
	#endif

	rets = []
	for ret in sorted(exits.keys(), key=lambda x:-1 if x is None else x):
		ret_str = str(ret)

		if ret is None:
			ret_str = 'unknown'
			col = color.YELLOW
		elif ret == 0:
			col = color.GREEN
		else:
			col = color.RED
		#endif

		rets.append(' %s%s: %d' % (col, ret_str, len(exits[ret])))
	#endfor

	print('rets: %s%s' % (', '.join(rets), color.END))
#enddef


if __name__ == '__main__':
	main()
#enddef
