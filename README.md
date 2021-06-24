<<<<<<< HEAD
gosnmp for TWSNMP
===

**18 Aug 2020**

I start the fork for TWSNMP Manager(**twsnmp/twsnmp**). 

**18 Aug 2020**

I added snmp agent functions.


Original note
======

**11 July 2020** - I'm planning on archiving **gosnmp**, as maintaining it is
having too much of an effect on my work and personal life. I started the fork
in March 2013 and I've been working on it ever since.

At the moment I'm keeping it open so it can act as a central clearing house for
issues and discussions around who is going to fork and maintain gosnmp - maybe one
person, maybe a team. Here are some suggestions around short term goals:

- more tests, both unit and integration
- Docker infrastructure, so developers can locally troubleshoot their changes
  before submitting (broken) PRs
- fix snmpv3, INFORM responses, traps

Thanks to Tim Rots for reaching out to me, to the many people who have submitted
PRs, and of course Andreas Louca, who started the project in 2012.

Tim has raised issue [Searching for collaboration to fork gosnmp](https://github.com/soniah/gosnmp/issues/247)
to help coordinate replacement maintainers.

Sonia Hamilton, sonia@snowfrog.net, Australia.

=======
>>>>>>> upstream/master
gosnmp
======

[![GoDoc](https://godoc.org/github.com/twsnmp/gosnmp?status.png)](http://godoc.org/github.com/twsnmp/gosnmp)
https://github.com/twsnmp/gosnmp

GoSNMP is an SNMP client library fully written in Go. It provides Get,
GetNext, GetBulk, Walk, BulkWalk, Set and Traps. It supports IPv4 and
IPv6, using __SNMPv1__, __SNMPv2c__ or __SNMPv3__. Builds are tested against
linux/amd64 and linux/386.

# About

**gosnmp** was started by [Andreas Louca](https://github.com/alouca), then
completely rewritten by [Sonia Hamilton](https://github.com/soniah)
(2012-2020), and now ownership has been transferred to the community at
[gosnmp/gosnmp](https://github.com/gosnmp/gosnmp).

For support and help, join us in the #snmp channel of
[Gophers Slack](https://invite.slack.golangbridge.org/).

# Overview

GoSNMP has the following SNMP functions:

* **Get** (single or multiple OIDs)
* **GetNext**
* **GetBulk** (SNMPv2c and SNMPv3 only)
* **Walk** - retrieves a subtree of values using GETNEXT.
* **BulkWalk** - retrieves a subtree of values using GETBULK (SNMPv2c and
  SNMPv3 only).
* **BulkWalkAll** - similar to BulkWalk but returns a filled array of all values rather than using a callback function to stream results.
* **Set** - supports Integers and OctetStrings.
* **SendTrap** - send SNMP TRAPs.
* **Listen** - act as an NMS for receiving TRAPs.
* **SNMP Agent** - act as SNMP agent.

GoSNMP has the following **helper** functions:

* **ToBigInt** - treat returned values as `*big.Int`
* **Partition** - facilitates dividing up large slices of OIDs

<<<<<<< HEAD
**twsnmp/gosnmp** has completely diverged from **soniah/gosnmp**, your code
=======
**gosnmp/gosnmp** has completely diverged from **alouca/gosnmp**, your code
>>>>>>> upstream/master
will require modification in these (and other) locations:

* the **Get** function has a different method signature
* the **NewGoSNMP** function has been removed, use **Connect** instead
  (see Usage below). `Connect` uses the `GoSNMP` struct;
  `gosnmp.Default` is provided for you to build on.
* GoSNMP no longer relies on **alouca/gologger** - you can use your
  logger if it conforms to the `gosnmp.LoggerInterface` interface; otherwise
  debugging will disabled.

```go
type LoggerInterface interface {
    Print(v ...interface{})
    Printf(format string, v ...interface{})
}
```
To enable logging, you must call gosnmp.NewLogger() function, and pass a pointer to your logging interface, for example with standard *log.Logger:

```go
gosnmp.Default.Logger = gosnmp.NewLogger(log.New(os.Stdout, "", 0))
```
or
```go
g := &gosnmp.GoSNMP{
    ...
    Logger:    gosnmp.NewLogger(log.New(os.Stdout, "", 0)),
}

```
You can completely remove the logging code from your application using the golang build tag "gosnmp_nodebug", for example:
```
go build -tags gosnmp_nodebug
```
This will completely disable the logging of the gosnmp library, even if the logger interface is specified in the code. This provides a small performance improvement.

# Installation

```shell
<<<<<<< HEAD
go get github.com/twsnmp/gosnmp
=======
go get github.com/gosnmp/gosnmp
>>>>>>> upstream/master
```

# Documentation

<<<<<<< HEAD
http://godoc.org/github.com/twsnmp/gosnmp
=======
https://pkg.go.dev/github.com/gosnmp/gosnmp
>>>>>>> upstream/master

# Usage

Here is `examples/example/main.go`, demonstrating how to use GoSNMP:

```go
// Default is a pointer to a GoSNMP struct that contains sensible defaults
// eg port 161, community public, etc
g.Default.Target = "192.168.1.10"
err := g.Default.Connect()
if err != nil {
    log.Fatalf("Connect() err: %v", err)
}
defer g.Default.Conn.Close()

oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
result, err2 := g.Default.Get(oids) // Get() accepts up to g.MAX_OIDS
if err2 != nil {
    log.Fatalf("Get() err: %v", err2)
}

for i, variable := range result.Variables {
    fmt.Printf("%d: oid: %s ", i, variable.Name)

    // the Value of each variable returned by Get() implements
    // interface{}. You could do a type switch...
    switch variable.Type {
    case g.OctetString:
        bytes := variable.Value.([]byte)
        fmt.Printf("string: %s\n", string(bytes))
    default:
        // ... or often you're just interested in numeric values.
        // ToBigInt() will return the Value as a BigInt, for plugging
        // into your calculations.
        fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
    }
}
```

Running this example gives the following output (from my printer):

```shell
% go run example.go
0: oid: 1.3.6.1.2.1.1.4.0 string: Administrator
1: oid: 1.3.6.1.2.1.1.7.0 number: 104
```

* `examples/example2.go` is similar to `example.go`, however it uses a
  custom `&GoSNMP` rather than `g.Default`
* `examples/walkexample.go` demonstrates using `BulkWalk`
* `examples/example3.go` demonstrates `SNMPv3`
* `examples/trapserver.go` demonstrates writing an SNMP v2c trap server

<<<<<<< HEAD
SNMP Agent
----------

1. Make SNMP agent struct

```go
	g := &gosnmp.GoSNMP{}
	g.Port = 161
	g.Community = "public"
	g.Version = gosnmp.Version2c
	a := &gosnmp.GoSNMPAgent{
		Port:   161,
		IPAddr: "0.0.0.0",
		Logger: log.New(os.Stdout, "", 0),
		Snmp:   g,
  }
```

2. Make MIB get function

```go
func getSysDescr(oid string) interface{} {
	return "test"
}
```

3. Add MIB to MIB Database

```go
	a.AddMibList(".1.3.6.1.2.1.1.1.0", gosnmp.OctetString, getSysDescr)
```

4. Start SNMP agent

```go
	if err := a.Start(); err != nil {
		log.Fatal(err)
	}
```

MIB Parser
----------
=======
# MIB Parser
>>>>>>> upstream/master

I don't have any plans to write a mib parser. Others have suggested
https://github.com/sleepinggenius2/gosmi

# Contributions

Contributions are welcome, especially ones that have packet captures (see
below).

If you've never contributed to a Go project before, here is an example workflow.

<<<<<<< HEAD
1. [fork this repo on the GitHub webpage](https://github.com/twsnmp/gosnmp/fork)
1. `go get github.com/twsnmp/gosnmp`
1. `cd $GOPATH/src/github.com/twsnmp/gosnmp`
=======
1. [fork this repo on the GitHub webpage](https://github.com/gosnmp/gosnmp/fork)
1. `go get github.com/gosnmp/gosnmp`
1. `cd $GOPATH/src/github.com/gosnmp/gosnmp`
>>>>>>> upstream/master
1. `git remote rename origin upstream`
1. `git remote add origin git@github.com:<your-github-username>/gosnmp.git`
1. `git checkout -b development`
1. `git push -u origin development` (setup where you push to, check it works)

# Packet Captures

Create your packet captures in the following way:

Expected output, obtained via an **snmp** command. For example:

```shell
% snmpget -On -v2c -c public 203.50.251.17 1.3.6.1.2.1.1.7.0 \
  1.3.6.1.2.1.2.2.1.2.6 1.3.6.1.2.1.2.2.1.5.3
.1.3.6.1.2.1.1.7.0 = INTEGER: 78
.1.3.6.1.2.1.2.2.1.2.6 = STRING: GigabitEthernet0
.1.3.6.1.2.1.2.2.1.5.3 = Gauge32: 4294967295
```

A packet capture, obtained while running the snmpget. For example:

```shell
sudo tcpdump -s 0 -i eth0 -w foo.pcap host 203.50.251.17 and port 161
```

# Bugs

Rane's document [SNMP: Simple? Network Management
Protocol](https://www.ranecommercial.com/legacy/note161.html) was useful when learning the SNMP
protocol.

Please create an [issue](https://github.com/gosnmp/gosnmp/issues) on
Github with packet captures (upload capture to Google Drive, Dropbox, or
similar) containing samples of missing BER types, or of any other bugs
you find. If possible, please include 2 or 3 examples of the
missing/faulty BER type.

The following BER types have been implemented:

* 0x00 UnknownType
* 0x01 Boolean
* 0x02 Integer
* 0x03 BitString
* 0x04 OctetString
* 0x05 Null
* 0x06 ObjectIdentifier
* 0x07 ObjectDescription
* 0x40 IPAddress (IPv4 & IPv6)
* 0x41 Counter32
* 0x42 Gauge32
* 0x43 TimeTicks
* 0x44 Opaque (Float & Double)
* 0x45 NsapAddress
* 0x46 Counter64
* 0x47 Uinteger32
* 0x78 OpaqueFloat
* 0x79 OpaqueDouble
* 0x80 NoSuchObject
* 0x81 NoSuchInstance
* 0x82 EndOfMibView

# Running the Tests

Local testing in Docker
```shell
<<<<<<< HEAD
docker build -t twsnmp/gosnmp:latest .
docker run -it twsnmp/gosnmp:latest
=======
docker build -t gosnmp/gosnmp:latest .
docker run -it gosnmp/gosnmp:latest
>>>>>>> upstream/master
```

or

```shell
export GOSNMP_TARGET=1.2.3.4
export GOSNMP_PORT=161
export GOSNMP_TARGET_IPV4=1.2.3.4
export GOSNMP_PORT_IPV4=161
export GOSNMP_TARGET_IPV6='0:0:0:0:0:ffff:102:304'
export GOSNMP_PORT_IPV6=161
go test -v -tags all        # for example
go test -v -tags helper     # for example
```

Tests are grouped as follows:

* Unit tests (validating data packing and marshalling):
   * `marshal_test.go`
   * `misc_test.go`
* Public API consistency tests:
   * `gosnmp_api_test.go`
* End-to-end integration tests:
   * `generic_e2e_test.go`

The generic end-to-end integration test `generic_e2e_test.go` should
work against any SNMP MIB-2 compliant host (e.g. a router, NAS box, printer).

Mocks were generated using:

`mockgen -source=interface.go -destination=mocks/gosnmp_mock.go -package=mocks`

However they're currently removed, as they were breaking linting.

To profile cpu usage:

```shell
go test -cpuprofile cpu.out
go test -c
go tool pprof gosnmp.test cpu.out
```

To profile memory usage:

```shell
go test -memprofile mem.out
go test -c
go tool pprof gosnmp.test mem.out
```

To check test coverage:

```shell
go get github.com/axw/gocov/gocov
go get github.com/matm/gocov-html
<<<<<<< HEAD
gocov test github.com/twsnmp/gosnmp | gocov-html > gosnmp.html && firefox gosnmp.html &
=======
gocov test github.com/gosnmp/gosnmp | gocov-html > gosnmp.html && firefox gosnmp.html &
>>>>>>> upstream/master
```


# License

Parts of the code are taken from the Golang project (specifically some
functions for unmarshaling BER responses), which are under the same terms
and conditions as the Go language. The rest of the code is under a BSD
license.

See the LICENSE file for more details.

The remaining code is Copyright 2012 the GoSNMP Authors - see
AUTHORS.md for a list of authors.
