# tds-sniffer

`tds-sniffer` is forked from [Snapper](https://github.com/vr000m/Snapper), it can sniffer freetds protocol(current now only support sybase sql server >= 10 which use tds 5.0 version), So far only [sql query](http://www.freetds.org/tds.html#t33) and [procedure](http://www.freetds.org/tds.html#t230) can be parsed.

**note:** we only test `Sybase-ASE 12.5` in the Centos 5.5 and 6.4 os system, and does not parse the params value in both `sql query` and `procedure`.

## How to compile?

#### DEPENDENCIES

```
libpcap-devel
```

#### compile

```
gcc -g -Wall -o tds-sniffer -lpcap tds-sniffer.c
```

## How to use?

```
./tds-sniffer eth0 "tcp dst port 5000"    
NET: 10.0.21.0 a03fe00 CMASK: 255.255.255.0 ffffff00
Device: eth0
Filter expression: tcp dst port 5000
2018-03-01T19:48:08 10.0.21.2:52313 -> 10.0.21.5:5000  sql_len: 9  query: select 1
2018-03-01T19:48:08 10.0.21.2:52307 -> 10.0.21.5:5000  sql_len: 9  query: select 1
2018-03-01T19:48:09 10.0.21.2:52307 -> 10.0.21.5:5000  sql_len: 61  query: SELECT t.username AS username FROM account t WHERE t.id = @p0
```

## References

* [1] https://github.com/vr000m/Snapper
* [2] http://www.freetds.org/tds.html
* [3] http://www.tcpdump.org/pcap.html
