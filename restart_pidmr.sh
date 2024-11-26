#!/bin/bash
# This assumes the configuration directory is set to /hs/svr_1
# and the Handle Software is installed in /opt/hsj

if [ -f /hs/svr_1/delete_this_to_stop_server ]; then 
sudo rm /hs/svr_1/delete_this_to_stop_server
fi 

if [ -f /Path_to_the_jar_file/PIDMRHDLProxy-0.0.1-SNAPSHOT.jar ]; then
sudo mv /Path_to_the_jar_file/PIDMRHDLProxy-0.0.1-SNAPSHOT.jar /opt/hsj/handle-9.3.1/lib/
else
echo "The PIDMRHDLProxy-0.0.1-SNAPSHOT.jar file not found."
fi

if [ -f /Path_to_the_jar_file/influxdb-2.24.jar ]; then
sudo mv /Path_to_the_jar_file/influxdb-2.24.jar /opt/hsj/handle-9.3.1/lib/
else
echo "The influxdb-2.24 file not found."
fi

sudo /opt/hsj/handle-9.3.1/bin/hdl-server /hs/svr_1 >/dev/null 2>&1 &