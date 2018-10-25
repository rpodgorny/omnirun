#!/usr/bin/python3

'''
Omnirun. Run command on multiple hosts.

Usage:
  omnirun [options] <hostspec>
  omnirun [options] <hostspec> <command>
  omnirun [options] <hostspec> [--sudo] --script <script> [<script_arg>...]
  omnirun [options] <hostspec> --copy-keys

Options:
  -i,--inventory=<fn>               Use <fn> as inventory file ("-" for stdin). Defaults to "~/.omnirun.conf".
  -X,--no-strict-host-key-checking  Disable ssh host key checking (you really shouldn't be using this!).
  -I,--interactive                  Interactive mode. You have to disconnect manually.
  -p <num>                          Number of parallel processes to run.
  --tmux                            Use tmux for parallelization.
  -4                                Force connection over IPv4.
  -6                                Force connection over IPv6.
  --sudo                            Use sudo on remote system.
  --copy-keys                       Copy local ssh keys to remote servers.
  -t                                Force tty allocation on the remote host (add -t to ssh options).
  --keep-open=<0,1,2,...,unknown,nonzero>
                                    Keep the window open when exit status is among the enumerated.
  --retry-on=<0,1,2,...,unknown,nonzero>
                                    Keep running the command while the exit status is among the enumerated (nonzero is default).
  -r,--retry-limit=<n>              Maximum number of retries in retry mode.
  --terse                           Be terse when printing final result stats.
  --capture=<path>                  Capture output to <path>.
  --json                            Save captured output in json format.

Arguments:
  <hostspec>  Host specification to connect to.
  <command>   Command to run.

Host specification (hostspec):
  [<username>[:<password>]@]<hostname>[:<port>] where <hostname> can be:
    * plain hostname (server34.company.com)
    * ip address (192.168.22.44)
    * hostname with range(s) (machine[1-57,66,77,88-90].company.com)
    * ip address with range(s) (192.168.22.[1-57,66,77,88-90])
    * tag - has to start with hash (#linux)
    * nothing - the implicit #all tag is used

Inventory file format:
  Newline seperated list of hostspecs and tags (space seperated). Such as:
    user:pass@host1.company.com tag1 tag2
    :pass2@host2.company.com tag2 tag3
  Hostspec can be specified multiple times - tags are merged in such case.
'''

from omnirun.version import __version__

import sys
import docopt
import os
import time
import subprocess
import signal
import omnirun.tmux as tmux
import json


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


def parse_hosts(lines):
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


def save_capture(res, fn, json_):
	if json_:
		with open(fn, 'a') as f:
			f.write(json.dumps(res) + '\n')
	else:
		os.makedirs('%s/%s' % (fn, res['host']), exist_ok=True)
		for k, v in res.items():
			with open('%s/%s/%s' % (fn, res['host'], k), 'w') as f:
				f.write(str(v))


def main():
	global original_sigint_handler
	original_sigint_handler = signal.getsignal(signal.SIGINT)
	signal.signal(signal.SIGINT, sigint_handler)

	args = docopt.docopt(__doc__, version=__version__)

	tag_to_hosts = {'all': set()}
	if args['--inventory']:
		fn = args['--inventory']
	else:
		fn = os.path.expanduser('~/.omnirun.conf')
	if fn == '-':
		lines = sys.stdin.readlines()
	elif os.path.isfile(fn):
		with open(fn, 'r') as f:
			lines = f.readlines()
	else:
		lines = []
	for hostspec, tags in parse_hosts(lines).items():
		for tag in tags:
			if tag not in tag_to_hosts:
				tag_to_hosts[tag] = set()
			tag_to_hosts[tag].add(hostspec_to_user_pass_host_port(hostspec))
		tag_to_hosts['all'].add(hostspec_to_user_pass_host_port(hostspec))

	hostspecs_ = args['<hostspec>']
	if ',' in hostspecs_ and '[' not in hostspecs_:
		hostspecs_ = hostspecs_.split(',')
	else:
		hostspecs_ = [hostspecs_, ]
	hosts = set()
	for hostspec in hostspecs_:
		user, pass_, host_or_tag, port = hostspec_to_user_pass_host_port(hostspec)
		if not host_or_tag:
			host_or_tag = '#all'
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
	if not hosts:
		print('no hosts')
		return 1

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
			script_args = args['<script_arg>']
			sudo = 'sudo' if args['--sudo'] else ''
			tmp_fn = '/tmp/omnirun.%s' % int(time.time())
			if args['<script>'].startswith(('http://', 'https://')):
				cmd = 'ssh {sshopts} {host_full} "sh -c \'rm -rf {tmp_fn} && mkdir {tmp_fn} && cd {tmp_fn}; wget -O {tmp_fn}/script --no-check-certificate \"{script}\" && chmod a+x script && {sudo} ./script {script_args} && cd - && rm -rf {tmp_fn}\'"'.format(sshopts=sshopts, host_full=host_full, tmp_fn=tmp_fn, script=args['<script>'], script_args=' '.join(script_args), sudo=sudo)
			else:
				# TODO: do this check outside of the loop
				if not os.path.isfile(args['<script>']):
					print('script \'%s\' does not exist' % args['<script>'])
					return 1
				cmd = 'ssh {sshopts} {host_full} "sh -c \'rm -rf {tmp_fn} && mkdir {tmp_fn} && cat >{tmp_fn}/script && cd {tmp_fn} && chmod a+x ./script && {sudo} ./script {script_args} && cd - && rm -rf {tmp_fn}\'" <{script}'.format(sshopts=sshopts, host_full=host_full, tmp_fn=tmp_fn, sudo=sudo, script=args['<script>'], script_args=' '.join(script_args))
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
	if retry_limit and not retry_on:
		print('--retry-limit specified but --retry-on not, implying --retry-on=nonzero')
		retry_on = rc_parse('nonzero')
	terse = args['--terse']
	capture = args['--capture']
	json_ = args['--json']
	if capture and json_:
		capture_fn = '%s.json' % capture
	else:
		capture_fn = capture
	if capture_fn and os.path.exists(capture_fn):
		print('%s exists!' % capture_fn)
		return 1
	try:
		nprocs = int(args['-p'])
	except:
		nprocs = 1
	tmux_ = args['--tmux']
	if nprocs > 1 and len(cmds) == 1:
		print('only one host, implying -p1')
		nprocs = 1
	if tmux_ and nprocs > 1 and not os.path.isfile(tmux.TMUX):
		print('%s%s not found, implying -p1%s' % (color.RED, tmux.TMUX, color.END))
		nprocs = 1
	if tmux_ and nprocs > 1 and 'TMUX' not in os.environ:
		print('TMUX environment not set, implying -p1')
		nprocs = 1
	results_by_host = do_it(cmds, command_to_display, nprocs, interactive, tmux_, keep_open, retry_on, retry_limit, capture_fn, json_)
	print()
	print_stats(results_by_host, terse)


def print_start(host, cmd, hosts_to_go, total, retries, retry_limit, _id=None):
	window_id_s = ' (%s)' % _id if _id is not None else ''
	if retries.get(host):
		if retry_limit:
			retry_s = ' (retry %d/%d)' % (retries[host], retry_limit)
		else:
			retry_s = ' (retry %d)' % retries[host]
	else:
		retry_s = ''

	print('%s%s%s: %s%s%s%s (%d of %d to go)%s' % (color.CYAN, color.BOLD, host, cmd, window_id_s, color.END, retry_s, len(hosts_to_go), total, color.END))


def print_done(host, cmd, exit_status, results_by_host, total, _id=None):
	exit_status_str = exit_status
	if exit_status is None:
		col = color.YELLOW
		exit_status_str = 'unknown'  # TODO: not very nice
	elif exit_status == 0:
		col = color.GREEN
	else:
		col = color.RED
	if _id is None:
		print('%s%s: %s -> rc: %s%s (%d of %d done)%s' % (col, host, cmd, exit_status_str, color.END, len(results_by_host), total, color.END))
	else:
		print('%s%s: %s (%s) -> rc: %s%s (%d of %d done)%s' % (col, host, cmd, _id, exit_status_str, color.END, len(results_by_host), total, color.END))


def print_out_err(host, cmd, out, err, _id=None):
	if out:
		if _id is None:
			print('%s%s: %s -> out:%s' % (color.YELLOW, host, cmd, color.END))
		else:
			print('%s%s: %s (%s) -> out:%s' % (color.YELLOW, host, cmd, _id, color.END))
		print(out)
	if err:
		if _id is None:
			print('%s%s: %s -> err:%s' % (color.YELLOW, host, cmd, color.END))
		else:
			print('%s%s: %s (%s) -> err:%s' % (color.YELLOW, host, cmd, _id, color.END))
		print(err)


def print_stats(results_by_host, terse):
	stats = {}  # TODO: rename to something better
	for host, res in results_by_host.items():
		exit_status = res['rc']
		if exit_status not in stats:
			stats[exit_status] = set()
		stats[exit_status].add(host)
	rets = []  # TODO: rename to something better
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
def do_it_single(cmds, command_to_display, retry_on, retry_limit, capture_fn, json_):
	hosts_to_go = sorted(list(cmds.keys()))
	total = len(hosts_to_go)
	results_by_host = {}
	#retries = {k: -1 for k in hosts_to_go}  # TODO: i don't like this. fill the dict as we go...
	retries = {}
	while not exit_requested and hosts_to_go:
		host = hosts_to_go.pop(0)
		cmd = cmds[host]
		retries[host] = retries.get(host, -1) + 1
		print_start(host, command_to_display, hosts_to_go, total, retries, retry_limit)
		if capture_fn:
			p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
			out_, err_ = p.stdout, p.stderr
			print_out_err(host, command_to_display, out_, err_)
			_res = {
				'host': host,
				'cmd': command_to_display,
				'out': out_,
				'err': err_,
				'rc': p.returncode,
			}
			save_capture(_res, capture_fn, json_)
		else:
			p = subprocess.run(cmd, shell=True)
			_res = {
				'host': host,
				'cmd': cmd,
				'rc': p.returncode,
			}
		results_by_host[host] = _res
		print_done(host, command_to_display, _res['rc'], results_by_host, total)
		if _res['rc'] in retry_on:
			if not retry_limit or retries[host] < retry_limit:
				hosts_to_go.append(host)  # return back to queue
		# we are only left with retries so let's just back off a little
		if set(hosts_to_go) <= set(results_by_host.keys()):
			time.sleep(1)  # TODO: hard-coded shit
	return results_by_host


def do_it_multi(cmds, command_to_display, nprocs, retry_on, retry_limit, capture_fn, json_):
	hosts_to_go = sorted(list(cmds.keys()))
	total = len(hosts_to_go)
	results_by_host = {}
	#retries = {k: -1 for k in hosts_to_go}  # TODO: i don't like this. fill the dict as we go...
	retries = {}
	procs = {}
	while 1:
		while not exit_requested and len(procs) < nprocs and hosts_to_go:
			host = hosts_to_go.pop(0)
			cmd = cmds[host]
			retries[host] = retries.get(host, -1) + 1
			p = subprocess.Popen(cmd, shell=True, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			procs[host] = (p, cmd)
			print_start(host, command_to_display, hosts_to_go, total, retries, retry_limit, p.pid)
		for host, (p, cmd) in procs.copy().items():
			exit_status = p.poll()
			is_dead = exit_status is not None
			if not is_dead:
				continue
			if capture_fn:
				out_, err_ = p.communicate()
				print_out_err(host, command_to_display, out_, err_, p.pid)
				_res = {
					'host': host,
					'cmd': command_to_display,
					'out': out_,
					'err': err_,
					'rc': exit_status,
				}
				save_capture(_res, capture_fn, json_)
			else:
				_res = {
					'host': host,
					'cmd': cmd,
					'rc': exit_status,
				}
			results_by_host[host] = _res
			print_done(host, command_to_display, _res['rc'], results_by_host, total, p.pid)
			del procs[host]
			if _res['rc'] in retry_on:
				if not retry_limit or retries[host] < retry_limit:
					hosts_to_go.append(host)  # return to queue
		if exit_requested and not procs:
			break
		if not procs and not hosts_to_go:
			break
		time.sleep(1)  # TODO: hard-coded shit
	return results_by_host


def do_it_multi_tmux(cmds, command_to_display, nprocs, interactive, keep_open, retry_on, retry_limit):
	hosts_to_go = sorted(list(cmds.keys()))
	total = len(hosts_to_go)
	results_by_host = {}
	#retries = {k: -1 for k in hosts_to_go}  # TODO: i don't like this. fill the dict as we go...
	retries = {}
	running = {}
	while 1:
		while not exit_requested and len(running) < nprocs and hosts_to_go:
			host = hosts_to_go.pop(0)
			cmd = cmds[host]
			retries[host] = retries.get(host, -1) + 1
			if interactive:
				w_id = tmux.tmux_new_window(host)
				tmux.tmux_send_keys(w_id, cmd)
			else:
				w_id = tmux.tmux_new_window(host, cmd)
			assert(w_id)
			tmux.tmux_set_window_option(w_id, 'remain-on-exit', 'on')
			running[w_id] = (host, cmd)
			print_start(host, command_to_display, hosts_to_go, total, retries, retry_limit, w_id)
		statuses = tmux.tmux_window_statuses()
		for w_id, (host, cmd) in running.copy().items():
			if w_id in statuses:
				is_dead, exit_status = statuses[w_id]
				# TODO: don't kill the window if it's currently open?
				if is_dead and exit_status not in keep_open:
					#_out = tmux.tmux_capture_pane(w_id)  # not really working
					#tmux_set_window_option(w_id, 'remain-on-exit', 'off')
					tmux.tmux_kill_window(w_id)
			else:
				print('%s not in statuses?!? wtf!!!' % w_id)
				is_dead = True
				exit_status = None
			if not is_dead:
				continue
			_res = {
				'host': host,
				'cmd': command_to_display,
				'rc': exit_status,
			}
			results_by_host[host] = _res
			print_done(host, command_to_display, _res['rc'], results_by_host, total, w_id)
			del running[w_id]
			if _res['rc'] in retry_on:
				if not retry_limit or retries[host] < retry_limit:
					hosts_to_go.append(host)  # return to queue
		if not running and not hosts_to_go:
			break
		time.sleep(1)  # TODO: hard-coded shit
	return results_by_host


# TODO: find a better name
def do_it(cmds, command_to_display, nprocs, interactive, tmux_, keep_open, retry_on, retry_limit, capture_fn, json_):
	if nprocs == 1:
		return do_it_single(cmds, command_to_display, retry_on, retry_limit, capture_fn, json_)
	if tmux_:
		return do_it_multi_tmux(cmds, command_to_display, nprocs, interactive, keep_open, retry_on, retry_limit)
	return do_it_multi(cmds, command_to_display, nprocs, retry_on, retry_limit, capture_fn, json_)


if __name__ == '__main__':
	sys.exit(main())
