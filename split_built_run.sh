#!/bin/bash


#AND DONT FORGET
#fred@cs438host:~/salmon/monitorbw$ sudo ./monitorbw
#fred@cs438host:~/salmon/justHTTP$ ./salmonhttp

echo "***********START**********" >>emailstdout
echo "***********START**********" >>erremail
echo "***********START**********" >>tcpstdout
echo "***********START**********" >>errtcp
echo "***********START**********" >>udpstdout
echo "***********START**********" >>errudp
echo "***********START**********" >>eRESTstdout
echo "***********START**********" >>errerest


nohup ./email_server >>emailstdout 2>>erremail &
nohup ./tcp_server >>tcpstdout 2>>errtcp &
nohup ./udp_server >>udpstdout 2>>errudp &

sleep 3

/home/fred/salmon/vmime_rest/wrapper_emailREST.sh >>eRESTstdout 2>>errerest &

#PSOUTPUT=`ps aux | grep 'directory_server' | sed '/sed/d' | sed 's/^.*\.\/directory_server.*$/\.\/directory_server/' | sed '/grep directory_server/d'`
#if [ "$PSOUTPUT" = "./directory_server" ] ; then
#	echo "The first directory_server instance is up and running, so everything should be fine!"
#else
#	echo "directory_server not found in process list; check for compilation errors"
#fi
