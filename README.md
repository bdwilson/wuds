# WUDS: Wireless User Detection System

WUDS is a proximity detection system that uses Wi-Fi probe requests, signal
strength, and a white list of MAC addresses to create a detection barrier and
identify the presence of foreign devices within a protected zone. Designed with
the Raspberry Pi in mind, WUDS can be installed and configured on any system
with Python 2.x and a wireless card capable of Monitor mode. Credit goes to 
[http://www.lanmaster53.com/2014/10/wifi-user-detection-system/](http://www.lanmaster53.com/2014/10/wifi-user-detection-system/)
for the initial code. This version adds Pushover alerts, "always notify" for
certain MAC addrs. 

You will also need a wireless device that supports
[http://raspberrypi.stackexchange.com/questions/36747/enable-monitoring-mode-for-rtl8188cus-via-usb-on-raspbian#37970](monitor
mode).

## Setup

```bash
# install prerequisites
# iw      - control the wi-fi interface
# pycapy  - access full 802.11 frames
# sqlite3 - interact with the database
# screen  - (optional) daemonize WUDS
sudo apt-get install iw python-pcapy sqlite3 screen
# lauch a screen session
screen
# install WUDS
git clone https://github.com/bdwilson/wuds
cd wuds
# edit the config file
vim config.py
# execute the included run script
./run.sh
# Ctrl+A, D detaches from the screen session
```

Make sure you adjust your wireless device in run.sh as well.

## File Summary

* alerts.py - custom alert modules
* config.py - configuration file
* core.py - core library
* run.sh - startup script
* README.py - this file
