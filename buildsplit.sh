#!/bin/bash

make -C /home/fred/salmon/vmime_rest &

sed --in-place 's/const bool HACKHACK_TCP_PROCESS = true;/const bool HACKHACK_TCP_PROCESS = false;/' source/app.d

./dub build --force
mv directory_server email_server

sed --in-place 's/const bool HACKHACK_TCP_PROCESS = false;/const bool HACKHACK_TCP_PROCESS = true;/' source/app.d

./dub build --force
mv directory_server tcp_server
