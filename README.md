# go_port_scanner

This is a simple TCP port scanner written in Go. 

```console
hightemp@computer-01:~/Projects/go_port_scanner$ ./go_port_scanner -host 192.168.31.142 -workers 10000 
TCP: 22
TCP: 5000
TCP: 9090
hightemp@computer-01:~/Projects/go_port_scanner$ ./go_port_scanner -host proxyapi.ru -workers 10 -start 1 -end 80
TCP: 80
hightemp@computer-01:~/Projects/go_port_scanner$ ./go_port_scanner -host proxyapi.ru -workers 10 -start 1 -end 443
TCP: 80
TCP: 443
```