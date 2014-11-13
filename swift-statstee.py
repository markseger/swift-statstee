#!/usr/bin/python -u

#https://sourceforge.net/p/forge/site-support/8418/#!/usr/bin/python -u

# Copyright 2014 Hewlett-Packard Development Company, L.P.
# Use of this script is subject to HP Terms of Use at
# http://www8.hp.com/us/en/privacy/terms-of-use.html.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#  debug flag
#   1 - show config data
#   2 - show socket info
#   4 - trace all messages, VERY verbose!

# to enable statsd, just add 'log_statsd_host = localhost' to conf files
# under [DEFAULT]

import errno
import os
import re
import select
import signal
import socket
import sys
import syslog
import time
from optparse import OptionParser, OptionGroup


def logmsg(severity, text):

    # when running as a second instance we don't care about logging because:
    # - we're running interactively and will see any errors
    # - this may not even be a machine with /var/log/swift on it
    if options.port:
        print text
        return

    timestamp = time.strftime("%Y%m", time.gmtime())
    logfile = '%s/%s-%s-statstee.log' % \
        (logdir, time.strftime("%Y%m", time.gmtime()),
         socket.gethostname().split('.')[0])
    msg = '%s %s %s' % \
        (time.strftime("%Y%m%d-%H:%M:%S", time.gmtime()), severity, text)
    if debug or re.match('[EF]', severity) and not options.daemon:
        print text

    try:
        log = open(logfile, 'a+')
        log.write('%s\n' % msg)
        log.close()
    except:
        print "Couldn't open", logfile
        syslog.syslog("couldn't open %s for appending" % logfile)
        sys.exit()

    if re.match('E|F', severity):
        syslog.syslog(text)
        if severity == 'F':
            sys.exit()


def error(text):
    """
    Report error and exit
    """
    print text
    sys.exit()


def load_conf():
    """
    Loads config either from local conf file if it exists, or /etc,
    only enabling collection flags for services which enable statsd
    sending to localhost
    """

    global port_in, port_out, addr_out, logdir, logname, frequency

    # defaults for config file
    port_in = 8125
    port_out = 0
    addr_out = localhost
    logdir = '/var/log/swift'
    logname = 'swift-stats'
    frequency = 0.1

    # if not specified, flags default to 'yes'
    flags = {}
    for flag in ('account', 'container', 'object', 'proxy'):
        flags[flag] = True

    exists = False
    for dir in ('.', '/etc/'):
        confname = dir + '/swift-statstee.conf'
        if os.path.exists(confname):
            exists = True
            if debug & 1:
                print "reading config data from:", confname
            c = open(confname, 'r')
            for line in c:
                line = line[0:-1]
                if line == '' or re.match('#', line):
                    continue

                # allow extra whitespace
                line = re.sub(' ', '', line)
                name, value = re.split('\s*=\s*', line)

                if name == 'port_in':
                    port_in = int(value)
                elif name == 'port_out':
                    port_out = int(value)
                elif name == 'addr_out':
                    addr_out = value
                elif name == 'logdir':
                    logdir = value
                elif name == 'logname':
                    logname = value
                elif name == 'frequency':
                    frequency = float(value)
                else:
                    if name not in flags:
                        logmsg('W', 'ignoring unknown config options: %s'
                               % name)
                    bool = True if value == 'yes' else False
                    flags[name] = bool
            if exists:
                break

    if not exists:
        error("cannot find swift-statstee.conf in /etc or local directory")

    # if statsd NOT enabled in the corresponding swift server.conf files
    # disable reporting of those server's stats.
    for server in ('account', 'container', 'object', 'proxy'):
        conf_file = '/etc/swift/%s-server.conf' % server
        if os.path.exists(conf_file):
            try:
                f = open(conf_file, 'r')
                for line in f:
                    if re.match('log_statsd_host', line) and \
                            re.search('localhost', line):
                        continue
            except:
                flags[server] = False
                logmsg('W', 'Disabling statsd logging because not ' +
                       'enabled in %s-server.conf' % server)

    total = 0
    for flag in flags:
        if flags[flag] == True:
            total += 1
    if not total:
        error("no output flags defined")

    return(flags)


def init_opers(statsfile):
    """
    In order to always print all counters in the output
    file, we need to initialize the known universe.  If
    additional data is ever added to statsd, this WILL
    have to change to recognize them.  Also note that
    status codes ARE dynamic and so their positions
    cannot be counted on
    """

    global statslog

    #  load values from log if there, noting proxies are special
    logvals = {}
    if os.path.exists(statsfile):
        logvals['prxsrvr'] = {}
        statslog = open(statsfile, 'r+')
        for line in statslog:
            line = line[:-1]
            if line == '' or re.match('#', line):
                continue
            name, vals = line.split(' ', 1)
            if name != 'prxsrvr':
                logvals[name] = []
                logvals[name] = vals.split()
            else:
                type, vals = vals.split(' ', 1)
                logvals['prxsrvr'][type] = vals.split()
    elif not options.port:    # only if primary instance
        statslog = open(statsfile, 'w')

    opers = {}

    #    A c c o u n t

    opers['account'] = {}
    opers['account']['auditor'] = {}
    opers['account']['reaper'] = {}
    opers['account']['replicator'] = {}
    opers['account']['server'] = {}

    index = 0
    for metric in ('errors', 'passes', 'failures'):
        value = logvals['accaudt'][index] if 'accaudt' in logvals else 0
        opers['account']['auditor'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('errors', 'containers_failures', 'containers_deleted',
                   'containers_remaining', 'containers_possibly_remaining',
                   'objects_failures', 'objects_deleted', 'objects_remaining',
                       'objects_possibly_remaining'):
        value = logvals['accreap'][index] if 'accreap' in logvals else 0
        opers['account']['reaper'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('diffs', 'diff_caps',  'no_changes', 'hasmmatches',
                   'rsyncs', 'remote_merges', 'attempts', 'failures',
                   'removes', 'successes'):
        value = logvals['accrepl'][index] if 'accrepl' in logvals else 0
        opers['account']['replicator'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('PUT', 'GET', 'POST', 'DELETE', 'HEAD', 'REPLICATE',
                   'errors'):
        value = logvals['accsrvr'][index] if 'accsrvr' in logvals else 0
        opers['account']['server'][metric] = int(value)
        index += 1

    #    C o n t a i n e r s

    opers['container'] = {}
    opers['container']['auditor'] = {}
    opers['container']['replicator'] = {}
    opers['container']['server'] = {}
    opers['container']['sync'] = {}
    opers['container']['updater'] = {}

    index = 0
    for metric in ('errors', 'passes', 'failures'):
        value = logvals['conaudt'][index] if 'conaudt' in logvals else 0
        opers['container']['auditor'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('diffs', 'diff_caps', 'no_changes', 'hashmatches', 'rsyncs',
                   'remote_merges', 'attempts', 'failures', 'removes',
                   'successes'):
        value = logvals['conrepl'][index] if 'conrepl' in logvals else 0
        opers['container']['replicator'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('PUT', 'GET', 'POST', 'DELETE', 'HEAD', 'REPLICATE',
                   'errors'):
        value = logvals['consrvr'][index] if 'consrvr' in logvals else 0
        opers['container']['server'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('skips', 'failures', 'syncs', 'deletes', 'puts'):
        value = logvals['consync'][index] if 'consync' in logvals else 0
        opers['container']['sync'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('successes', 'failures', 'no_changes'):
        value = logvals['conupdt'][index] if 'conupdt' in logvals else 0
        opers['container']['updater'][metric] = int(value)
        index += 1

    #    O b j e c t s

    opers['object'] = {}
    opers['object']['auditor'] = {}
    opers['object']['expirer'] = {}
    opers['object']['replicator'] = {}
    opers['object']['server'] = {}
    opers['object']['updater'] = {}

    index = 0
    for metric in ('quarantines', 'errors'):
        value = logvals['objaudt'][index] if 'objaudt' in logvals else 0
        opers['object']['auditor'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('objects', 'errors'):
        value = logvals['objexpr'][index] if 'objexpr' in logvals else 0
        opers['object']['expirer'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('part_delete', 'part_update', 'suffix_hashes',
                   'suffix_syncs'):
        value = logvals['objrepl'][index] if 'objrepl' in logvals else 0
        opers['object']['replicator'][metric] = int(value)
        index += 1

    index = 0
    for metric in ('PUT', 'GET', 'POST', 'DELETE', 'HEAD', 'REPLICATE',
                   'errors', 'quarantines', 'async_pendings', 'putcount'):
        value = logvals['objsrvr'][index] if 'objsrvr' in logvals else 0
        opers['object']['server'][metric] = int(value)
        index += 1

        # this is the ONLY float
        value = logvals['objsrvr'][index] if 'objsrvr' in logvals else 0
        opers['object']['server']['puttime'] = float(value)

    index = 0
    for metric in ('errors', 'quarantines', 'successes', 'failures',
                   'unlinks'):
        value = logvals['objupdt'][index] if 'objupdt' in logvals else 0
        opers['object']['updater'][metric] = int(value)
        index += 1

    #    P r o x y

    # note that we're NOT using type 'server' for the 2nd proxy dict entry
    opers['proxy'] = {}
    opers['proxy']['account'] = {}
    opers['proxy']['container'] = {}
    opers['proxy']['object'] = {}

    # skipping GET.status and bytes xfer for now...
    for type in ('account', 'container', 'object'):

        opers['proxy'][type]['status'] = {}

        index = 0
        logtype = 'prxy%s' % type[0:3]    # different format name for proxies
        for verb in ('PUT', 'GET', 'POST', 'DELETE', 'HEAD', 'COPY', 'OPTIONS',
                     'BAD_METHOD'):
            value = logvals[logtype][index] if logtype in logvals else 0
            opers['proxy'][type][verb] = int(value)
            index += 1

        for metric in ('errors', 'handoff_count', 'handoff_all_count',
                       'timeouts', 'disconnects'):
            value = logvals[logtype][index] if logtype in logvals else 0
            opers['proxy'][type][metric] = int(value)
            index += 1

        if logtype in logvals:
            for index in range(index, len(logvals[logtype])):
                status, count = logvals[logtype][index].split(':')
                opers['proxy'][type]['status'][int(status)] = int(count)

    return(opers)


def logger(line):
    """
    Writes one ling to stats file and optionally to the
    terminal if --term, which is mainly there for debugging
    """

    if options.term == True or options.top:
        print line
    
    statslog.write('%s\n' % line)


def report():
    """
    This is the workhorse for output, building up and writing
    one line at a time via called to logger()
    """

    # gotta do with a write because print generates trailing space
    if options.top:
        top = '%c[H%c[J' % (27, 27)
        sys.stdout.write(top)

    # note this is version 1.0 of stats and NOT this program
    statslog.seek(0)
    logger("V1.0 %f" % time.time())

    #    A c c o u n t

    if flags['account']:
        line = "#       errs pass fail\n"
        line += 'accaudt %d %d %d' % ( \
            opers['account']['auditor']['errors'],
            opers['account']['auditor']['passes'],
            opers['account']['auditor']['failures'])
        logger(line)

        line = "#       errs cfail cdel cremain cposs_remain " + \
            "ofail odel oremain oposs_remain\n"
        line += 'accreap %d %d %d %d %d %d %d %d %d' % (
            opers['account']['reaper']['errors'],
            opers['account']['reaper']['containers_failures'],
            opers['account']['reaper']['containers_deleted'],
            opers['account']['reaper']['containers_remaining'],
            opers['account']['reaper']['containers_possibly_remaining'],
            opers['account']['reaper']['objects_failures'],
            opers['account']['reaper']['objects_deleted'],
            opers['account']['reaper']['objects_remaining'],
            opers['account']['reaper']['objects_possibly_remaining'])
        logger(line)

        line = "#       diff diff_cap nochg hasmat rsync rem_merge " + \
            "attmpt fail remov succ\n"
        line += 'accrepl %d %d %d %d %d %d %d %d %d %d' % (
            opers['account']['replicator']['diffs'],
            opers['account']['replicator']['diff_caps'],
            opers['account']['replicator']['no_changes'],
            opers['account']['replicator']['hasmmatches'],
            opers['account']['replicator']['rsyncs'],
            opers['account']['replicator']['remote_merges'],
            opers['account']['replicator']['attempts'],
            opers['account']['replicator']['failures'],
            opers['account']['replicator']['removes'],
            opers['account']['replicator']['successes'])
        logger(line)

        line = "#       put get post del head repl errs\n"
        line += 'accsrvr %d %d %d %d %d %d %d' % (
            opers['account']['server']['PUT'],
            opers['account']['server']['GET'],
            opers['account']['server']['POST'],
            opers['account']['server']['DELETE'],
            opers['account']['server']['HEAD'],
            opers['account']['server']['REPLICATE'],
            opers['account']['server']['errors'])
        logger(line)

    #    C o n t a i n e r

    if flags['container']:
        line = "#       errs pass fail\n"
        line += 'conaudt %d %d %d' % (
            opers['container']['auditor']['errors'],
            opers['container']['auditor']['passes'],
            opers['container']['auditor']['failures'])
        logger(line)

        line = "#       diff diff_cap nochg hasmat rsync rem_merge " + \
            "attmpt fail remov succ\n"
        line += 'conrepl %d %d %d %d %d %d %d %d %d %d' % (
            opers['container']['replicator']['diffs'],
            opers['container']['replicator']['diff_caps'],
            opers['container']['replicator']['no_changes'],
            opers['container']['replicator']['hashmatches'],
            opers['container']['replicator']['rsyncs'],
            opers['container']['replicator']['remote_merges'],
            opers['container']['replicator']['attempts'],
            opers['container']['replicator']['failures'],
            opers['container']['replicator']['removes'],
            opers['container']['replicator']['successes'])
        logger(line)

        line = "#       put get post del head repl errs\n"
        line += 'consrvr %d %d %d %d %d %d %d' % (
            opers['container']['server']['PUT'],
            opers['container']['server']['GET'],
            opers['container']['server']['POST'],
            opers['container']['server']['DELETE'],
            opers['container']['server']['HEAD'],
            opers['container']['server']['REPLICATE'],
            opers['container']['server']['errors'])
        logger(line)

        line = "#       skip fail sync del put\n"
        line += 'consync %d %d %d %d %d' % (
            opers['container']['sync']['skips'],
            opers['container']['sync']['failures'],
            opers['container']['sync']['syncs'],
            opers['container']['sync']['deletes'],
            opers['container']['sync']['puts'])
        logger(line)

        line = "#       succ fail no_chg\n"
        line += 'conupdt %d %d %d' % (
            opers['container']['updater']['successes'],
            opers['container']['updater']['failures'],
            opers['container']['updater']['no_changes'])
        logger(line)

    #    O b j e c t

    if flags['object']:
        line = "#       quar errs\n"
        line += 'objaudt %d %d' % (
            opers['object']['auditor']['quarantines'],
            opers['object']['auditor']['errors'])
        logger(line)

        line = "#       obj errs\n"
        line += 'objexpr %d %d' % (
            opers['object']['expirer']['objects'],
            opers['object']['expirer']['errors'])
        logger(line)

        line = "#       part_del part_upd suff_hashes suff_sync\n"
        line += 'objrepl %d %d %d %d' % (
            opers['object']['replicator']['part_delete'],
            opers['object']['replicator']['part_update'],
            opers['object']['replicator']['suffix_hashes'],
            opers['object']['replicator']['suffix_syncs'])
        logger(line)

        line = "#       put get post del head repl errs quar async_pend "
        line += "putcount puttime\n"
        line += 'objsrvr %d %d %d %d %d %d %d %d %d %d %f' % (
            opers['object']['server']['PUT'],
            opers['object']['server']['GET'],
            opers['object']['server']['POST'],
            opers['object']['server']['DELETE'],
            opers['object']['server']['HEAD'],
            opers['object']['server']['REPLICATE'],
            opers['object']['server']['errors'],
            opers['object']['server']['quarantines'],
            opers['object']['server']['async_pendings'],
            opers['object']['server']['putcount'],
            opers['object']['server']['puttime'])
        logger(line)

        line = "#       errs quar succ fail unlk\n"
        line += 'objupdt %d %d %d %d %d' % (
            opers['object']['updater']['errors'],
            opers['object']['updater']['quarantines'],
            opers['object']['updater']['successes'],
            opers['object']['updater']['failures'],
            opers['object']['updater']['unlinks'])
        logger(line)

    #    P r o x y

    if flags['proxy']:

        # only need 1 header since all lines the same
        logger("#       put get post del head copy opt bad_meth errs " + \
                   "handoff handoff_all timout discon status")
        for type in ('account', 'container', 'object'):
            line = ''

            line += 'prxy%s %d %d %d %d %d %d %d %d' % (
                type[0:3],
                opers['proxy'][type]['PUT'],
                opers['proxy'][type]['GET'],
                opers['proxy'][type]['POST'],
                opers['proxy'][type]['DELETE'],
                opers['proxy'][type]['HEAD'],
                opers['proxy'][type]['COPY'],
                opers['proxy'][type]['OPTIONS'],
                opers['proxy'][type]['BAD_METHOD'])
            line += ' %d %d %d %d %d' % (
                opers['proxy'][type]['errors'],
                opers['proxy'][type]['handoff_count'],
                opers['proxy'][type]['handoff_all_count'],
                opers['proxy'][type]['timeouts'],
                opers['proxy'][type]['disconnects'])

            for status in sorted(opers['proxy'][type]['status']):
                line += " %d:%d" % (status,
                                    opers['proxy'][type]['status'][status])
            logger(line)


def control_c_handler(signal, frame):
    '''
    control-c handler
    '''

    logmsg('W', 'sigint received, shutting down')
    sys.exit(0)


def getval(metric, value):
    '''
    return both a count and a timing when present
    expected formats for value:
      integer|c
      float|ms
      float|ms|@float, in this case we multiple by @float
    '''

    # all metrics of the form: value|modifier
    match = re.match('(.*)\|(.*)', value)
    real_val = match.group(1)
    modifier = match.group(2)
    if modifier == 'c':
        count = int(real_val)
        timing = 0
    elif modifier == 'ms':
        count = 1
        timing = float(real_val)

    elif modifier[0] == '@':
        match = re.match('@(.*)', modifier)
        if match:
            real_val = re.sub('\|ms', '', real_val)
            count = 1 / float(match.group(1))
            timing = count * float(real_val)
    else:
        logmsg('E', 'Unexpected metric value format: %s' % value)

    return(count, timing)


def main():
    """
    As the name says...
    """

    global program, version, copyright
    global debug, flags, opers, options, localhost, port_out

    program = 'swift-statstee'
    version = '1.0'
    copyright = 'Copyright 2014 Hewlett-Packard Development Company, L.P.'

    signal.signal(signal.SIGINT, control_c_handler)

    parser = OptionParser(add_help_option=False)
    parser.add_option('-d', dest='debug', help='debugging mask', default='0')
    parser.add_option('-D', dest='daemon', help='run as a daemon',
                      action='store_true')
    parser.add_option('-p', dest='port', help='listen port, see manpage',
                      default='')
    parser.add_option('-v', dest='version', help='show version and exit',
                      action='store_true')
    parser.add_option('--ignore', dest='ignore', help='exclude matching events',
                      default='')
    parser.add_option('--filter', dest='filter', help='include matching events',
                      default='')
    parser.add_option('--top', dest='top', help='top format',
                      action='store_true', default=False)
    parser.add_option('--term', dest='term', help='output on terminal',
                      action='store_true', default=False)
    (options, args) = parser.parse_args()

    if options.version:
        print '%s V%s\n%s' % (program, version, copyright)
        sys.exit()

    if os.geteuid() != 0:
        error('you must be root to run this')

    if options.port and not options.top and \
       not options.term and not options.filter and \
       not options.ignore:
        error('-p require --filter, --ignore, --term or --top')

    # just because it gets used everywhere
    debug = int(options.debug)

    # if daemon, make sure one isn't already running and if not
    # create a file in /var/run with our pid in it
    if options.daemon:
        if debug != 0:
            error('no debugging in daemon mode, sorry')

        myname = os.path.basename(__file__)
        runlog = '/var/run/swift-statstee.pid'

        if os.path.exists(runlog):
            f = open(runlog, 'r')
            pid = f.read()[:-1]
            f.close()

            proc_path = '/proc/%s/comm' % pid
            if os.path.exists(proc_path):
                f = open('/proc/%s/comm' % pid)
                pname = f.read()[:-1]
                f.close()
                if pname == myname:
                    error("a daemonized %s already running" % myname)

    # logdir/statsname can get overridden by config file
    localhost = '127.0.0.1'
    flags = load_conf()
    statsfile = '%s/%s' % (logdir, logname)

    if debug & 1:
        print "Flags:", flags

    opers = init_opers(statsfile)
    if options.port == '':
        listen_port = port_in
        listen_addr = localhost
        msg = "listening on port %s,  logging to %s every %0.1f seconds" % \
                (listen_port, statsfile, frequency)
    else:
        if re.search(':', options.port):
            listen_addr, listen_port = options.port.split(':')
        else:
            listen_addr = localhost
            listen_port = options.port
        listen_port = int(listen_port)
        msg = "listening on port %s, logging disabled!" % listen_port
    if debug & 2:
        print msg

    # listen for statsd packets
    sockets = []
    sockets_none = []
    sockin = socket.socket(socket.AF_INET,     # Internet
                           socket.SOCK_DGRAM)  # UDP
    try:
        sockin.bind((listen_addr, listen_port))
    except socket.error, err:
            print "%s:%s in use, is another copy running?" % \
                (listen_addr, listen_port)
            sys.exit()

    sockets.append(sockin)

    # echo statsd packets if 'tee' port defined noting we're
    # NOT adding to list of sockets to 'select()' on
    if port_out and options.port == '':
        if debug & 2:
            print "echoing to %s:%s" % (addr_out, port_out)
        sockout = socket.socket(socket.AF_INET,     # Internet
                                socket.SOCK_DGRAM)  # UDP

    message = '%s %s beginning execution, listening on port %d' % \
              (program, version, listen_port)
    if port_out:
        if options.port == '':
            message += ', echoing to %s:%d' % (addr_out, port_out)
            message += ', logging every %0.1f secs' % frequency
        else:
            port_out = 0
            message += ', forwarding and updating stats disabled'
    logmsg('I', message)

    if options.daemon:

        # there seems to be some differing opinions of whether or
        # not to disable I/O right before we fork/exit, but it
        # certainly can't hurt.  I also discovered I need to use
        # dup2() as 3 opens cause hangs over ssh?!?  no explantion
        # was ever found
        sys.stdin = open('/dev/null', 'r+')
        os.dup2(0, 1)    # standard output (1)
        os.dup2(0, 2)    # standard error (2)

        # for a new copy and exit the parent
        pid = os.fork()
        if pid > 0:
            sys.exit()

        # decouple from parent environent
        os.chdir('/')
        os.setsid()
        os.umask(0)

        # and disable all I/O
        sys.stdin = open('/dev/null', 'r+')
        os.dup2(0, 1)    # standard output (1)
        os.dup2(0, 2)    # standard error (2)

        # finally write our new PID to the run file
        f = open(runlog, 'w')
        f.write('%s\n' % os.getpid())
        f.close()

    ################################################
    #
    #    M a i n    P r o c e s s i n g   L o o p
    #
    ################################################

    #timeout = 1
    time_last = change_flag = 0
    while (True):

        rready = select.select(sockets, sockets_none, sockets_none,
                               frequency)[0]
        now = time.time()
        if len(rready):
            time_now = time.time()
            data, address = sockin.recvfrom(1024)
            if port_out and options.port == '':
                sockout.sendto(data, (addr_out, port_out))

            # if filtering and/or ignoring, do it here
            if (options.filter or options.ignore):
                if (options.filter and not re.search(options.filter, data)) or \
                   (options.ignore and re.search(options.ignore, data)):
                    continue
                print '%f %s' % (time_now, data)
                continue

            # get data name, value and service type noting in the case of
            # 'removes', there is an additional metric qualifier which we
            # choose to ignore and strip off.  Also note tempauth has no type
            # from here on, service and metric WILL be defined even if bad!
            try:
                key, val = data.split(':')
                service, metric = key.split('.', 1)
                metric = re.sub('^removes\..*', 'removes', metric)
            except ValueError:
                logmsg('E', "Error splitting datagram: %s" % data)
                continue

            # and now service_type is always defined
            if not re.search('tempauth', service):
                try:
                    service, service_type = service.split('-')
                except ValueError:
                    logmsg('E', "Error in service split: %s" % data)
                    continue
            else:
                service_type = ''

            # get count and timing.  should this be inline rather than fct?
            count, timing = getval(metric, val)
            if debug & 4:
                print "Service: %s Type: %s Metric: %s Count: %d %f" % \
                    (service, service_type, metric, count, timing)

            # there's a lot of common code below but moving it all to one
            # place can cause longer term problem if I just want to change
            # one metric for one service

            #    A c c o u n t

            if service == 'account':

                # at least for now, we don't care about timing data and only
                # want counts, noting some metrics don't star with '.'
                metric = re.sub('\.*timing$', '', metric)
                if metric == '':
                    continue

                # when there are errors, they're reported by service type
                # but I want to lump them all into one counter like this
                if re.search('errors$', metric):
                    opers[service][service_type]['errors'] += 1
                    change_flag = 1
                    continue

                try:
                    opers['account'][service_type][metric] += count
                    change_flag = 1
                except KeyError:
                    logmsg('E', "KeyError - opers[%s][%s][%s]" %
                           (service, service_type, metric) +
                           "from datagram: %s" % data)
                    continue

            #    C o n t a i n e r

            elif service == 'container':

                # at least for now, we don't care about timing data and only
                # want counts, noting some metrics don't star with '.'
                metric = re.sub('\.*timing$', '', metric)
                if metric == '':
                    continue

                # when there are errors, they're reported by service type
                # but I want to lump them all into one counter like this
                if re.search('errors$', metric):
                    opers[service][service_type]['errors'] += 1
                    change_flag = 1
                    continue

                try:
                    opers['container'][service_type][metric] += count
                    change_flag = 1
                except KeyError:
                    logmsg('E', "KeyError - opers[%s][%s][%s]" %
                           (service, service_type, metric) +
                           "from datagram: %s" % data)
                    continue

            #    O b j e c t

            elif service == 'object':

                # server data kinds special
                if service_type == 'server':
                    if metric == 'quarantine' or metric == 'async_pendings':
                        opers[service][service_type][metric] += count
                        change_flag = 1
                    else:
                        type, subtype = metric.split('.')[0:2]
                        if subtype == 'timing':
                            opers[service][service_type][type] += 1
                            change_flag = 1
                        elif type == 'PUT' and re.match('.*timing$', metric):
                            #print "DEV TIMING", data, type, timing
                            #print "Time: %f" % timing
                            opers[service][service_type]['putcount'] += count
                            opers[service][service_type]['puttime'] += timing
                        elif subtype == 'errors':
                            opers[service][service_type]['errors'] += 1
                            change_flag = 1
                    continue

                # replicator reports partition device numbers and an extra
                # suffix level I don't want to deal with, so rename them
                # so the update below works for everything non-server
                elif service_type == 'replicator':
                    if re.match('partition.delete.count', metric):
                        metric = 'part_delete'
                    elif re.match('partition.update.count', metric):
                        metric = 'part_update'
                    elif re.match('suffix', metric):
                        metric = re.sub('\.', '_', metric)

                # all object server data already counted above and we don't
                # care about timing data, at least not yet
                if not re.match('.*timing$', metric):
                    try:
                        opers['object'][service_type][metric] += count
                        change_flag = 1
                    except KeyError:
                        logmsg('E', "KeyError - opers[%s][%s][%s]" %
                               (service, service_type, metric) +
                               "from datagram: %s" % data)

            elif service == 'proxy':

                # proxy only has one service type of server, so reset type to
                # account, container or object and set the metric to the rest
                try:
                    service_type, metric = metric.split('.', 1)
                except ValueError:
                    logmsg('E', "metric split, datagram: %s" % (metric, data))
                    continue

                # ignore these at least for now
                if re.search('xfer$', metric) or \
                        re.search('byte\.timing$', metric):
                    continue

                # verb type metrics need to have value of 'metric' chopped out,
                # but only after saving status
                status = 0
                match = re.match('(\w+)\.(\d+)', metric)
                if match:
                    metric = match.group(1)
                    status = int(match.group(2))

                try:
                    opers['proxy'][service_type][metric] += count
                    change_flag = 1
                except KeyError:
                    logmsg('E', "KeyError - opers[%s][%s][%s]" %
                           (service, service_type, metric) +
                           "from datagram: %s" % data)
                    continue

                # need to do more for verbs
                if status:
                    # if failure, we're already counted as success
                    if status < 200 and status > 299:
                        try:
                            opers['proxy'][service_type][metric] -= count
                            change_flag = 1
                        except KeyError:
                            logmsg('E', "KeyError - opers[%s][%s][%s]" %
                                   (service, service_type, metric) +
                                   "from datagram: %s" % data)
                            continue

                    # count ALL status types as well
                    if status not in opers['proxy'][service_type]['status']:
                        opers['proxy'][service_type]['status'][status] = 0
                    try:
                        opers['proxy'][service_type]['status'][status] += \
                            count
                        change_flag = 1
                    except KeyError:
                        logmsg('E', "KeyError - opers[%s][%s][%s]" %
                               (service, service_type, metric) +
                               "from datagram: %s" % data)
                        continue

            elif service == 'tempauth':
                continue

        time_now = time.time()
        time_diff = time_now - time_last
        #print "Bottom %f %d Diff: %f" % (time_now, change_flag, time_diff)
        if time_diff >= frequency and change_flag == 1:
            #print "  >> PUT %f" % (time.time())
            report()
            time_last = time_now
            change_flag = 0


if __name__ == '__main__':

    try:
        main()
    except Exception as err:
        import traceback
        logmsg('F', 'Unexpected error: %s' % traceback.format_exc())
