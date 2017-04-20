#!/usr/bin/python3

'''
Omnirun. Run command on multiple hosts.

Usage:
  omnirun [options] <hosts>
  omnirun [options] <hosts> <command>
  omnirun [options] <hosts> [--sudo] --script <script>
  omnirun [options] <hosts> --copy-keys

Options:
  --no-strict-host-key-checking  Disable ssh host key checking.
  --interactive                  Interactive mode. You have to disconnect manually.
  -p <num>                       Number of parallel processes to run.
  -4                             Force connection over IPv4.
  -6                             Force connection over IPv6.
  --sudo                         Use sudo on remote system.
  --copy-keys                    Copy local ssh keys to remote servers.
  -t                             Force tty allocation on the remote host (add -t to ssh options).
  --keep-open=<0,1,2,...,unknown,nonzero>
                                 Keep the window open when exit status is among the enumerated.
  --retry-on=<0,1,2,...,unknown,nonzero>
                                 Keep running the command while the exit status is among the enumerated.
  --retry-limit=<n>              Maximum number of retries in retry mode.
  --terse                        Be terse when printing final result stats.

Arguments:
  <hosts>    Hosts to connect to.
  <command>  Command to run.

Host specification:
  [<username>[:<password>]@]<hostname>[:<port>] where <hostname> can be:
    * plain hostname (server34.company.com)
    * ip address (192.168.22.44)
    * ip address with range (192.168.22.[1-57)
    * tag - has to start with hash (#linux)
'''

from .version import __version__

import sys
import docopt
import os
import time
import subprocess
import signal
import omnirun.tmux as tmux


SSHPASS = '/usr/bin/sshpass'

# TODO: can you solve this without globals?
original_sigint_handler = None
exit_requested = False


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


def sigint_handler(signum, frame):
	print()
	print('%sinterrupt signal caught, exiting gracefully. interrupt once more for hard exit.%s' % (color.BOLD, color.END))
	print()

	signal.signal(signal.SIGINT, original_sigint_handler)

	global exit_requested
	exit_requested = True


def get_hosts(fn):
	with open(fn, 'r') as f:
		lines = f.readlines()
	lines_exp = []
	for line in lines:
		line = line.strip()
		if not line:
			continue
		if line.startswith('#'):
			continue
		lines_exp.extend(expand_host(line))
	ret = {}
	for i in lines_exp:
		host, *tags = i.split()
		if host not in ret:
			ret[host] = set()
		ret[host] |= set(tags)
	return ret


def expand_host(s):
	if '[' not in s or '-' not in s or ']' not in s:
		return [s, ]
	pre = s.split('[')[0]
	in_ = s.split('[')[1].split(']')[0]
	post = s.split(']')[1]
	ret = []
	for i in in_.split(','):
		i = i.strip()
		if not i:
			continue
		if '-' in i:
			from_, to_ = map(int, i.split('-', 1))
			for j in range(from_, to_ + 1):
				ret.append('%s%s%s' % (pre, j, post))
		else:
			ret.append('%s%s%s' % (pre, i, post))
	return ret


def hostspec_to_user_pass_host_port(s):
	user, pass_, host, port = None, None, None, None
	if '@' in s:
		user_pass, host = s.split('@')
		if ':' in user_pass:
			user, pass_ = user_pass.split(':')
		else:
			user = user_pass
	else:
		host = s
	if ':' in host:
		host, port = host.split(':')
		port = int(port)
	return (user, pass_, host, port)


def rc_parse(s):
	if s is None:
		return set()
	ret = set()
	rcs = set(s.split(','))
	if 'unknown' in rcs:
		rcs.remove('unknown')
		ret.add(None)
	if 'nonzero' in rcs:
		rcs.remove('nonzero')
		ret |= set(range(1, 256))
	for rc in rcs:
		rc = rc.strip()
		if not rc:
			continue
		ret.add(int(rc))
	return ret


def main():
	global original_sigint_handler
	original_sigint_handler = signal.getsignal(signal.SIGINT)
	signal.signal(signal.SIGINT, sigint_handler)

	args = docopt.docopt(__doc__, version=__version__)

	tag_to_hosts = {'all': set()}
	fn = os.path.expanduser('~/.omnirun.conf')
	if os.path.isfile(fn):
		for hostspec, tags in get_hosts(fn).items():
			for tag in tags:
				if tag not in tag_to_hosts:
					tag_to_hosts[tag] = set()
				tag_to_hosts[tag].add(hostspec_to_user_pass_host_port(hostspec))
				tag_to_hosts['all'].add(hostspec_to_user_pass_host_port(hostspec))

	hosts = set()
	for hostspec in args['<hosts>'].split(','):
		user, pass_, host_or_tag, port = hostspec_to_user_pass_host_port(hostspec)

		if host_or_tag.startswith('#'):
			for us_, pa_, ho_, po_ in tag_to_hosts.get(host_or_tag[1:], set()):
				if user:
					us_ = user
				if pass_:
					pa_ = pass_
				if port:
					po_ = port
				for eh in expand_host(ho_):
					hosts.add((us_, pa_, eh, po_))
		else:
			for h in expand_host(host_or_tag):
				hosts.add((user, pass_, h, port))

	if args['--copy-keys']:
		command_to_display = '<ssh-copy-id>'
	elif args['<script>']:
		command_to_display = '<script> %s' % args['<script>']
	elif args['<command>']:
		command_to_display = args['<command>']
	else:
		command_to_display = '<login>'

	cmds = {}
	for (user, pass_, host, port) in hosts:
		host_full = '%s@%s' % (user, host) if user else host

		sshopts = ''
		#sshopts += ' -o ConnectTImeout=2'
		sshopts += ' -t' if args['-t'] else ''  # TODO: the -t seems to be breaking logins to windows machines - figure shomething out
		sshopts += ' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' if args['--no-strict-host-key-checking'] else ''
		sshopts += ' -4' if args['-4'] else ''
		sshopts += ' -6' if args['-6'] else ''
		sshopts += ' -p %d' % port if port else ''

		if args['--copy-keys']:
			#cmd = 'ssh-copy-id -i %s %s' % (PUB_KEY_FN, host_full)
			cmd = 'ssh-copy-id %s' % host_full
			cmd += ' -p %d' % port if port else ''
		elif args['<script>']:
			sudo = 'sudo' if args.get('--sudo') else ''

			tmp_fn = '/tmp/omnirun.%s' % int(time.time())

			if args['<script>'].startswith(('http://', 'https://')):
				cmd = 'ssh {sshopts} {host_full} "sh -c \'rm -rf {tmp_fn} && mkdir {tmp_fn} && cd {tmp_fn}; wget -O {tmp_fn}/script --no-check-certificate \"{script}\" && chmod a+x script && {sudo} ./script && cd - && rm -rf {tmp_fn}\'"'.format( \
				sshopts=sshopts, host_full=host_full, tmp_fn=tmp_fn, script=args['<script>'], sudo=sudo)
			else:
				# TODO: do this check outside of the loop
				if not os.path.isfile(args['<script>']):
					print('script \'%s\' does not exist' % args['<script>'])
					return 1

				cmd = 'ssh {sshopts} {host_full} "sh -c \'rm -rf {tmp_fn} && mkdir {tmp_fn} && cat >{tmp_fn}/script && cd {tmp_fn} && chmod a+x ./script && {sudo} ./script && cd - && rm -rf {tmp_fn}\'" <{script}'.format( \
				sshopts=sshopts, host_full=host_full, tmp_fn=tmp_fn, sudo=sudo, script=args['<script>'])

				# these are some other tries - probably broken or half-working...
				#cmd = 'ssh %s %s \'sh -c "a=`mktemp`; cat >$a; chmod a+x $a; %s $a; rm $a"\' <%s' % (sshopts, host_full, sudo, args['<script>'])
				#cmd = 'ssh %s %s "cat >%s; chmod a+x %s; %s %s; rm %s"' % (sshopts, host_full, tmp_fn, tmp_fn, sudo, tmp_fn, tmp_fn)
				#cmd = 'ssh %s %s "cat | %s sh"' % (sshopts, host_full, sudo)
		elif args['<command>']:
			cmd = 'ssh %s %s "%s"' % (sshopts, host_full, args['<command>'].replace('"', '\\"'))
		else:
			cmd = 'ssh %s %s' % (sshopts, host_full)

		if pass_:
			if not os.path.isfile(SSHPASS):
				raise Exception('%s does not exist' % SSHPASS)
			cmd = '%s -p%s %s' % (SSHPASS, pass_, cmd)

		cmds[host_full] = cmd

	interactive = args['--interactive']
	keep_open = rc_parse(args['--keep-open'])
	retry_on = rc_parse(args['--retry-on'])
	retry_limit = int(args['--retry-limit']) if args['--retry-limit'] else None
	terse = args['--terse']

	try:
		nprocs = int(args['-p'])
	except:
		nprocs = 1

	if nprocs > 1 and not os.path.isfile(tmux.TMUX):
		print('%s%s not found, implying -p1%s' % (color.RED, tmux.TMUX, color.END))
		nprocs = 1

	if nprocs > 1 and len(cmds) == 1:
		print('only one host, implying -p1')
		nprocs = 1

	if nprocs > 1 and 'TMUX' not in os.environ:
		print('TMUX environment not set, implying -p1')
		nprocs = 1

	if not cmds:
		print('no hosts')
		return 1

	do_it(cmds, command_to_display, nprocs, interactive, keep_open, retry_on, retry_limit, terse)


def print_start(host, cmd, hosts_to_go, total, retries, retry_limit, window_id=None):
	window_id_s = ' (%s)' % window_id if window_id is not None else ''
	if retries.get(host):
		if retry_limit:
			retry_s = ' (retry %d/%d)' % (retries[host], retry_limit)
		else:
			retry_s = ' (retry %d)' % retries[host]
	else:
		retry_s = ''

	print('%s%s%s: %s%s%s%s (%d of %d to go)%s' % (color.CYAN, color.BOLD, host, cmd, window_id_s, color.END, retry_s, len(hosts_to_go), total, color.END))


def print_done(host, cmd, exit_status, exits, total, window_id=None):
	exit_status_str = exit_status
	if exit_status is None:
		col = color.YELLOW
		exit_status_str = 'unknown'  # TODO: not very nice
	elif exit_status == 0:
		col = color.GREEN
	else:
		col = color.RED
	if window_id is None:
		print('%s%s: %s -> %s%s (%d of %d done)%s' % (col, host, cmd, exit_status, color.END, len(exits), total, color.END))
	else:
		print('%s%s: %s (%s) -> %s%s (%d of %d done)%s' % (col, host, cmd, window_id, exit_status, color.END, len(exits), total, color.END))


def print_stats(exits, terse):
	# TODO: rename to something better
	stats = {}
	for host, exit_status in exits.items():
		if exit_status not in stats:
			stats[exit_status] = set()
		stats[exit_status].add(host)

	# TODO: rename to something better
	rets = []
	for ret in sorted(stats.keys(), key=lambda x: -1 if x is None else x):
		ret_str = str(ret)

		if ret is None:
			ret_str = 'unknown'
			col = color.YELLOW
		elif ret == 0:
			col = color.GREEN
		else:
			col = color.RED

		s = '%s%s: %d' % (col, ret_str, len(stats[ret]))
		if not terse and len(stats[ret]):
			s += ' (%s)' % ', '.join(sorted(list(stats[ret])))
		rets.append(s)

	if not terse:
		print('rets:\n%s%s' % ('\n'.join(rets), color.END))
	else:
		print('rets: %s%s' % (', '.join(rets), color.END))


# TODO: find a better name
def do_it(cmds, command_to_display, nprocs, interactive, keep_open, retry_on, retry_limit, terse):
	hosts_to_go = sorted(list(cmds.keys()))
	total = len(hosts_to_go)
	exits = {}
	retries = {k: -1 for k in hosts_to_go}  # TODO: i don't like this. fill the dict as we go...

	if nprocs == 1:
		while not exit_requested and hosts_to_go:
			host = hosts_to_go.pop(0)
			cmd = cmds[host]
			retries[host] += 1
			print_start(host, command_to_display, hosts_to_go, total, retries, retry_limit)
			exit_status = subprocess.call(cmd, shell=True)
			exits[host] = exit_status
			print_done(host, command_to_display, exit_status, exits, total)

			if exit_status in retry_on:
				if not retry_limit or retries[host] < retry_limit:
					hosts_to_go.append(host)  # return back to queue

			# we are only left with retries so let's just back off a little
			if set(hosts_to_go) <= set(exits.keys()):
				time.sleep(1)  # TODO: hard-coded shit
	else:
		running = {}
		while 1:
			while not exit_requested and len(running) < nprocs and hosts_to_go:
				host = hosts_to_go.pop(0)
				cmd = cmds[host]
				retries[host] += 1

				if interactive:
					w_id = tmux.tmux_new_window(host)
					tmux.tmux_send_keys(w_id, cmd)
				else:
					w_id = tmux.tmux_new_window(host, cmd)

				assert(w_id)

				tmux.tmux_set_window_option(w_id, 'set-remain-on-exit', 'on')
				running[w_id] = (host, cmd)
				print_start(host, command_to_display, hosts_to_go, total, retries, retry_limit, w_id)

			statuses = tmux.tmux_window_statuses()

			for w_id, (host, cmd) in running.copy().items():
				if w_id in statuses:
					is_dead, exit_status = statuses[w_id]

					# TODO: don't kill the window if it's currently open?
					if is_dead and exit_status not in keep_open:
						#tmux_set_window_option(w_id, 'set-remain-on-exit', 'off')
						tmux.tmux_kill_window(w_id)
				else:
					print('%s not in statuses?!? wtf!!!' % w_id)
					is_dead = True
					exit_status = None

				if not is_dead:
					continue

				exits[host] = exit_status
				print_done(host, command_to_display, exit_status, exits, total, w_id)
				del running[w_id]

				if exit_status in retry_on:
					if not retry_limit or retries[host] < retry_limit:
						hosts_to_go.append(host)  # return to queue

			if not running:
				break

			time.sleep(1)  # TODO: hard-coded shit

	print()
	print_stats(exits, terse)


if __name__ == '__main__':
	sys.exit(main())
