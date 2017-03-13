from config import *
import requests

'''
Each module must receive **kwargs as a parameter. The kwargs variable is a dictionary
consisting of all the data extracted from the probe request. Each module name must
start with 'alert_' and have a matching variable in config.py for enabling/disabling.
Configurable module options may be defined in config.py.
'''

from email.mime.text import MIMEText
import smtplib

def alert_sms(**kwargs):
    msg = MIMEText('WUDS proximity alert! A foreign device (%s - %s) has been detected on the premises.' % (kwargs['bssid'], kwargs['oui']))
    server = smtplib.SMTP(SMTP_SERVER)
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    server.sendmail(SMTP_USERNAME, SMS_EMAIL, msg.as_string())
    server.quit()

import urllib
import urllib2

def alert_pushover(**kwargs):
    if not (kwargs['dash']):
    	if not (kwargs['bssid_name'] is None): 
    		msg = 'Proximity alert! (%s - %s) has been detected on the premises.' % (kwargs['bssid_name'], kwargs['oui'])
    	else:
    		msg = 'Proximity alert! A foreign device (%s - %s) has been detected on the premises.' % (kwargs['bssid'], kwargs['oui'])
    	url = 'https://api.pushover.net/1/messages.json'
    	payload = {'token': PUSHOVER_API_KEY, 'user': PUSHOVER_USER_KEY, 'message': msg}
    	payload = urllib.urlencode(payload)
    	resp = urllib2.urlopen(url, data=payload)

def alert_pushover2(**kwargs):
    if not (kwargs['dash']):
    	if not (kwargs['bssid_name'] is None): 
    		msg = 'Proximity alert! (%s - %s) has been detected on the premises.' % (kwargs['bssid_name'], kwargs['oui'])
    	else:
    		msg = 'Proximity alert! A foreign device (%s - %s) has been detected on the premises.' % (kwargs['bssid'], kwargs['oui'])
    	url = 'https://api.pushover.net/1/messages.json'
    	payload = {'token': PUSHOVER_API_KEY2, 'user': PUSHOVER_USER_KEY2, 'message': msg}
    	payload = urllib.urlencode(payload)
    	resp = urllib2.urlopen(url, data=payload)

def alert_smartthings(**kwargs):
    if (kwargs['dash']):
    	headers = {"Authorization": "Bearer SMARTTHINGS_APIKEY"}
    	data = '{"command":"toggle"}'
    	resp = requests.put(SMARTTHINGS_URL, data=data, headers=headers)
