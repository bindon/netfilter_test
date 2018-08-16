# [Net Filter Test](https://github.com/bindon/netfilter_test)

## Usage

> How to add rules for iptables
- sudo iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 32768
- sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 32768


> How to execute netfilter
1. make (in project home directory)
2. cd bin
3. sudo ./netfilter_test
