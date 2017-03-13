
#=========
# CONTROL
#=========

# (STR) WLAN interface in monitor mode
IFACE = 'mon0'

# (LIST) List of MAC addresses expected within the premises
MAC_LIST = [ 
    '2c:1f:23:42:d2:b5',
    '6c:40:08:7b:cd:fb',
    ]

# list of Mac Addrs to always notify when they come/go
NOTIFY_DICT = {
	"88:32:9b:9a:a1:e7":"Weird Walking Dude",
	}

# was working on capturing and running scripts based on dash buttons from
# Amazon, but this isn't working. 
DASH_DICT = {
	#"10:AE:60:60:06:72":"Cottonelle"
}

# (STR) Vendor name to report for probes from Local Admin MAC addresses
ADMIN_OUI = 'Masked'

# (BOOL) Automatically white list Local Admin MAC addresses
# WARNING...
# iOS MAC randomization uses Local Admin MAC addresses. Ignoring Local
# Admin MAC addresses will cause false negatives. However, NOT ignoring
# Local Admin MAC addresses will cause false positives.
ADMIN_IGNORE = True

# (INT) RSSI threshold for triggering alerts
RSSI_THRESHOLD = -80

# (INT) Number of seconds between alerts for persistent foreign probes
ALERT_THRESHOLD = 1200
NOTIFY_THRESHOLD = 7200

# (STR) Path to the database file
LOG_FILE = 'log.db'

# (INT) Determines which probes are stored in the database
# 0 = all probes
# 1 = all foreign probes
# 2 = all probes on the premises
# 3 = all foreign probes on the premises
# 4 = only probes that generate alerts
LOG_LEVEL = 3

# (BOOL) Enable/Disable stdout debugging messages
DEBUG = True

#========
# ALERTS
#========

# (BOOL) Enable/Disable alert modules
ALERT_SMS = False
ALERT_PUSHOVER = True
ALERT_PUSHOVER2 = False

#==================
# ALERT_SMS CONFIG
#==================

# (STR) SMTP server hostname and port (TLS required) for sending alerts
SMTP_SERVER = 'smtp.gmail.com:587'

# (STR) Mail server credentials for sending alerts
SMTP_USERNAME = ''
SMTP_PASSWORD = ''

# (STR) SMS email address (through cellular service provider) for receiving alerts
SMS_EMAIL = ''

#=======================
# ALERT_PUSHOVER CONFIG
#=======================

# (STR) API and User keys from pushover.net
PUSHOVER_API_KEY= 'aSogPxBA5BHCdWBQxY6RfzuseYourRealKey'
PUSHOVER_API_KEY2= 'aSogPxBA5BHCdWBQxY6RfzuseYourRealKey'
PUSHOVER_USER_KEY = 'uszZUqnxg3E2bqLbm5J8w5UuseYourRealUserKey'
PUSHOVER_USER_KEY2 = 'uK7h4VGESzchaP24Aci4QdUuseYourRealUserKey'
