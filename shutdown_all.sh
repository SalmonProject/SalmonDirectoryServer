#!/bin/sh

killall -9 directory_server
killall -9 email_server
killall -9 tcp_server
#killall -9 send_mail
killall -9 udp_server
killall -9 wrapper_emailREST.sh
killall -9 email_to_REST
