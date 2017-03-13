from contextlib import closing
from datetime import datetime, timedelta
import json
import pcapy
import sqlite3
import struct
import sys
import traceback
import urllib2
import pprint

# import wuds modules
sys.dont_write_bytecode = True
from config import *
from alerts import *

# define constants
MAC_LIST = [x.lower() for x in MAC_LIST]
NOTIFY = {}
for k, v in NOTIFY_DICT.iteritems():
    NOTIFY [k.lower()] = v

DASH = {}
for k, v in DASH_DICT.iteritems():
    DASH [k.lower()] = v

LOG_TYPES = {
    0: 'messages',
    1: 'probes',
}
MESSAGE_LEVELS = {
    0: 'INFO',
    1: 'ERROR',
    2: 'ALERT',
    }

dashcount=False

def to_unicode(obj, encoding='utf-8'):
    # checks if obj is a unicode string and converts if not
    if isinstance(obj, basestring):
        if not isinstance(obj, unicode):
            obj = unicode(obj, encoding)
    return obj

def log(log_type, values):
    # add a timestamp to the values
    values = (str(datetime.now()),) + values
    # sanitize values for storage
    values = tuple([to_unicode(x) for x in values])
    # insert values into the database
    values_str = ','.join('?'*len(values))
    query = 'INSERT INTO %s VALUES (%s)' % (LOG_TYPES[log_type], values_str)
    cur.execute(query, values)
    conn.commit()

def log_message(level, message):
    log(0, (MESSAGE_LEVELS[level], message))

def log_probe(bssid, rssi, essid):
    oui = resolve_oui(bssid)
    log(1, (bssid, rssi, essid, oui))

def is_admin_oui(mac):
    return int(mac.split(':')[0], 16) & 2

def resolve_oui(mac):
    # check if mac vendor has already been resolved
    if mac not in ouis:
        # check if mac has a local admin oui
        if is_admin_oui(mac):
            ouis[mac] = ADMIN_OUI
        # retrieve mac vendor from oui lookup api
        else:
            try:
                resp = urllib2.urlopen('https://www.macvendorlookup.com/api/v2/%s' % mac,timeout=5)
                if resp.code == 204:
                    ouis[mac] = 'Unknown'
                elif resp.code == 200:
                    jsonobj = json.load(resp)
                    ouis[mac] = jsonobj[0]['company']
                else:
                    raise Exception('Invalid response code: %d' % (resp.code))
                log_message(0, 'OUI resolved. [%s => %s]' % (mac, ouis[mac]))
            except Exception as e:
                log_message(1, 'OUI resolution failed. [%s => %s]' % (mac, str(e)))
                # return, but don't store the value
                return 'Error'
    return ouis[mac]

def call_alerts(**kwargs):
    for var in globals():
        # find config variables for alert modules
        if var.startswith('ALERT_') and globals()[var] == True:
            # dynamically call enabled alert modules
            if var.lower() in globals():
                func = globals()[var.lower()]
                try:
                    func(**kwargs)
                    log_message(2, '%s alert triggered. [%s]' % (var[6:], kwargs['bssid']))
                except:
                    if DEBUG: print traceback.format_exc()
                    log_message(1, '%s alert failed. [%s]' % (var[6:], kwargs['bssid']))

def packet_handler(pkt):
    rtlen = struct.unpack('h', pkt[2:4])[0]
    ftype = (ord(pkt[rtlen]) >> 2) & 3
    stype = ord(pkt[rtlen]) >> 4
    # check if probe request
    if ftype == 0 and stype == 4:
        rtap = pkt[:rtlen]
        frame = pkt[rtlen:]
	notify = False
	dashnotify = False
        # parse bssid
        bssid = frame[10:16].encode('hex')
        bssid = ':'.join([bssid[x:x+2] for x in xrange(0, len(bssid), 2)])
        # parse rssi
        rssi = struct.unpack("b",rtap[-4:-3])[0]
        # parse essid
        essid = frame[26:26+ord(frame[25])] if ord(frame[25]) > 0 else '<None>'
        # build data tuple
	print "bssid: %s" % bssid
        # check whitelist for probing mac address
        foreign = False
        if bssid not in MAC_LIST:
            foreign = True
        # handle local admin mac addresses
        if is_admin_oui(bssid) and ADMIN_IGNORE:
            foreign = False
        # check proximity
        on_premises = False
	if bssid in NOTIFY and not (NOTIFY[bssid] is None):
	    notify = True
	    bssid_name = NOTIFY[bssid]
	    print "NOTIFY bssid: %s" % bssid
	    print "NOTIFY bssid_name: %s" % bssid_name
        if rssi > RSSI_THRESHOLD:
            on_premises = True
        data = (bssid, rssi, essid)
	if bssid in DASH and not (DASH[bssid] is None) and bssid not in counts:
		dashnotify = True
		notify = False
		foreign = False
		counts[bssid] = datetime.now()-timedelta(seconds=2)
		print "DATE: %s" % counts[bssid]
		bssid_name = DASH[bssid]
		print "DASH event: %s" % bssid
		print "DASH name: %s" % bssid_name
	if bssid in DASH and not (DASH[bssid] is None) and (datetime.now() - counts[bssid].seconds > 1):
		print "FOUND A DUPE"
        # log according to configured level
        if LOG_LEVEL == 0: log_probe(*data)
        if foreign and LOG_LEVEL == 1: log_probe(*data)
        if on_premises and LOG_LEVEL == 2: log_probe(*data)
	if (dashnotify):
            call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=resolve_oui(bssid), bssid_name=bssid_name, dash=True)
        if ((foreign and on_premises) or (on_premises and notify)):
	    THRESHOLD = ALERT_THRESHOLD
	    if (notify):
		THRESHOLD = NOTIFY_THRESHOLD
	    print "bssid: %s" % bssid
	    print "foreign?: %s" % foreign
	    print "on premises: %s" % on_premises
	    print "foced notify?: %s" % notify
            if LOG_LEVEL == 3: log_probe(*data)
            # send alerts periodically
	    print ', '.join(alerts)
            if bssid not in alerts:
		print "adding to alert for %s" % bssid
                alerts[bssid] = datetime.now() - timedelta(minutes=5)
		if (notify):
                	call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=resolve_oui(bssid), bssid_name=bssid_name, dash=False)
		else:
                	call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=resolve_oui(bssid), bssid_name=None, dash=False)
            if (datetime.now() - alerts[bssid]).seconds > THRESHOLD:
                if LOG_LEVEL == 4: log_probe(*data)
                alerts[bssid] = datetime.now()
		print "calling alerts for %s" % bssid
		if (notify):
                	call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=resolve_oui(bssid), bssid_name=bssid_name, dash=False)
		else:
                	call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=resolve_oui(bssid), bssid_name=None, dash=False)

# connect to the wuds database
# wuds runs as root and should be able to write anywhere
with sqlite3.connect(LOG_FILE) as conn:
    with closing(conn.cursor()) as cur:
        # build the database schema if necessary
        cur.execute('CREATE TABLE IF NOT EXISTS probes (dtg TEXT, mac TEXT, rssi INT, ssid TEXT, oui TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS messages (dtg TEXT, lvl TEXT, msg TEXT)')
        conn.commit()
        log_message(0, 'WUDS started.')
        # set up the sniffer
        cap = pcapy.open_live(IFACE, 1514, 1, 0)
        alerts = {}
        ouis = {}
	counts = {}
        # start the sniffer
        while True:
            try:
                (header, pkt) = cap.next()
                if cap.datalink() == 0x7F:
                    packet_handler(pkt)
            except KeyboardInterrupt:
                break
            except:
                #if DEBUG: print traceback.format_exec()
                continue
        log_message(0, 'WUDS stopped.')
