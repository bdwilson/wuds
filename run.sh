iface=`grep IFACE config.py | cut -d'=' -f 2 | sed "s/['\" ]//g"`
sudo iw dev wlan0 interface add $iface type monitor
sudo ifconfig $iface up
sudo python ./core.py
sudo ifconfig $iface down
sudo iw dev $iface del
