import subprocess


TMUX = '/usr/bin/tmux'


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

		ret[w_id] = (pane_dead, pane_dead_status)

	return ret


def tmux_new_window(name, cmd=None):
	lst = [TMUX, 'new-window', '-n', name, '-P', '-F', '#{window_id}', '-d']
	if cmd:
		lst.append(cmd)
	res = subprocess.check_output(lst, universal_newlines=True)
	return res.split('\n')[0]


def tmux_kill_window(w_id):
	res = subprocess.check_call([TMUX, 'kill-window', '-t', ':%s' % w_id], universal_newlines=True)


def tmux_send_keys(w_id, cmd, enter=True):
	lst = [TMUX, 'send-keys', '-t', ':%s' % w_id, '-l', cmd]
	if enter:
		lst.extend([';', 'send-keys', '-t', ':%s' % w_id, 'Enter'])
	res = subprocess.check_output(lst, universal_newlines=True)


def tmux_respawn_pane(w_id, cmd):
	res = subprocess.check_output([TMUX, 'respawn-pane', '-t', ':%s' % w_id, '-k', cmd], universal_newlines=True)


def tmux_capture_pane(w_id):
	res = subprocess.check_output([TMUX, 'capture-pane', '-t', ':%s' % w_id, '-p'], universal_newlines=True)


def tmux_set_window_option(w_id, option, value):
	# TODO: why is the window_id format different here?
	res = subprocess.check_call([TMUX, 'set-window-option', '-t', '%s' % w_id, option, value], universal_newlines=True)
