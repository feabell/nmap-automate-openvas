#!/bin/bash

CHUNKED=false

echo "[*] Running discovery scan....."

if [ ! -s 'targets.txt' ]
then
  echo "[!] Quitting: No targets in targets.txt."
  exit 
fi

sudo nmap -sn -PS22,445,3389,21,443 -PU161,53,67 -oA host_discovery -vv -iL ./targets.txt

echo "[*] Discovery scan complete."
grep Up host_discovery.gnmap | cut -d" " -f 2 >hosts.txt

discowc=`wc -l hosts.txt | cut -d" " -f 1`

echo  "[*] "$discowc" hosts found"

if [ ! -s 'hosts.txt' ]
then
  echo "[!] Quitting: no hosts to scan."
  exit
fi

if [[ $(wc -l <hosts.txt) -ge 64 ]]
then
  echo "[!] Large number of hosts found, chunking...."
  split -l64 -d hosts.txt hosts_chunked_
  CHUNKED=true
fi


if [ "$CHUNKED" = "true" ]; then
  for file in hosts_chunked_*
  do
  echo "[*] Running chunked top1k tcp port scan $file....."
    sudo nmap -sS -Pn -n --top-ports=1000 -oA $file.disco_tcp_top1000 -A -iL ./$file --stats-every 600s
  done
else
  echo "[*] Running top1k tcp port scan....."
  sudo nmap -sS -Pn -n --top-ports=1000 -oA disco_tcp_top1000 -A -iL ./hosts.txt --stats-every 600s
fi

