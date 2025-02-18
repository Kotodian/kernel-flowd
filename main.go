package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type Proto uint8

const (
	ProtoTCP Proto = 6
	ProtoUDP Proto = 17
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return "unknown"
}

type Role uint8

func (r Role) String() string {
	switch r {
	case RoleTCPClient:
		return "tcp client"
	case RoleTCPServer:
		return "tcp server"
	case RoleUDPClient:
		return "udp client"
	case RoleUDPServer:
		return "udp server"
	}
	return "none"
}

const (
	RoleNone Role = iota
	RoleTCPClient
	RoleTCPServer
	RoleUDPClient
	RoleUDPServer
)

type TcpState uint8

const (
	TcpStateNone TcpState = iota
	TcpStateEstablished
	TcpStateSynSent
	TcpStateSynRecv
	TcpStateFinWait1
	TcpStateFinWait2
	TcpStateTimeWait
	TcpStateClose
	TcpStateCloseWait
	TcpStateLastAck
	TcpStateListening
	TcpStateClosing
	TcpStateNewSynRecv
)

func (s TcpState) String() string {
	switch s {
	case TcpStateNone:
		return "none"
	case TcpStateEstablished:
		return "established"
	case TcpStateSynSent:
		return "syn sent"
	case TcpStateSynRecv:
		return "syn recv"
	case TcpStateFinWait1:
		return "fin wait 1"
	case TcpStateFinWait2:
		return "fin wait 2"
	case TcpStateTimeWait:
		return "time wait"
	case TcpStateClose:
		return "close"
	case TcpStateCloseWait:
		return "close wait"
	case TcpStateLastAck:
		return "last ack"
	case TcpStateListening:
		return "listening"
	case TcpStateClosing:
		return "closing"
	case TcpStateNewSynRecv:
		return "new syn recv"
	}
	return "unknown"
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 -type record_sock bpf tcp_udp.bpf.c
func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("loading objects: %+v", verr)
		}
	}

	defer objs.Close()
	err := objs.bpfVariables.SelfPid.Set(uint32(os.Getpid()))
	if err != nil {
		log.Fatalf("setting self pid: %s", err)
	} else {
		fmt.Printf("self pid set to %d\n", os.Getpid())
	}

	sendSkb, err := link.Kprobe("udp_send_skb", objs.UdpSendSkb, nil)
	if err != nil {
		log.Fatalf("creating kprobe udp_send_skb: %s", err)
	}
	defer sendSkb.Close()

	sendV6Skb, err := link.Kprobe("udp_v6_send_skb", objs.UdpV6SendSkb, nil)
	if err != nil {
		log.Fatalf("creating kprobe udp_v6_send_skb: %s", err)
	}
	defer sendV6Skb.Close()

	consumeUdp, err := link.Kprobe("skb_consume_udp", objs.SkbConsumeUdp, nil)
	if err != nil {
		log.Fatalf("creating kprobe skb_consume_udp: %s", err)
	}
	defer consumeUdp.Close()

	inetCskAccept, err := link.Kretprobe("inet_csk_accept", objs.InetCskAccept, nil)
	if err != nil {
		log.Fatalf("creating kretprobe inet_csk_accept: %s", err)
	}
	defer inetCskAccept.Close()

	// trace point
	inetSockSetState, err := link.Tracepoint("sock", "inet_sock_set_state", objs.InetSockSetState, nil)
	if err != nil {
		log.Fatalf("creating tracepoint inet_sock_set_state: %s", err)
	}
	defer inetSockSetState.Close()

	tcpV4DoRcv, err := link.Kprobe("tcp_v4_do_rcv", objs.TcpV4DoRcv, nil)
	if err != nil {
		log.Fatalf("creating kprobe tcp_v4_do_rcv: %s", err)
	}
	defer tcpV4DoRcv.Close()

	tcpV6DoRcv, err := link.Kprobe("tcp_v6_do_rcv", objs.TcpV6DoRcv, nil)
	if err != nil {
		log.Fatalf("creating kprobe tcp_v6_do_rcv: %s", err)
	}
	defer tcpV6DoRcv.Close()

	ipLocalOut, err := link.Kprobe("ip_local_out", objs.IpLocalOut, nil)
	if err != nil {
		log.Fatalf("creating kprobe ip_local_out: %s", err)
	}
	defer ipLocalOut.Close()
	ip6Xmit, err := link.Kprobe("ip6_xmit", objs.Ip6Xmit, nil)
	if err != nil {
		log.Fatalf("creating kprobe ip6_xmit: %s", err)
	}
	defer ip6Xmit.Close()

	// raw socket
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("creating raw socket: %s", err)
	}
	defer syscall.Close(sock)
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  4,
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		log.Fatalf("binding raw socket: %s", err)
	}
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.HandleSkb.FD()); err != nil {
		log.Fatalf("attaching raw socket: %s", err)
	}

	rd, err := ringbuf.NewReader(objs.RingbufRecords)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %s", err)
	}
	defer rd.Close()
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	go func() {
		f, _ := os.OpenFile("/sys/kernel/debug/tracing/trace_pipe", os.O_RDONLY, os.ModePerm)
		defer f.Close()
		reader := bufio.NewReader(f)
		for {
			line, _, err := reader.ReadLine()
			if err == io.EOF {
				break
			}
			fmt.Println(string(line))
		}
	}()

	log.Println("Listening for records ...")

	var event bpfRecordSock

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		localIPBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			localIPBytes[i] = byte(event.Laddr[i])
		}
		remoteIPBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			remoteIPBytes[i] = byte(event.Raddr[i])
		}

		var localIP, remoteIP net.IP
		if event.Family == 2 {
			localIP = net.IPv4(localIPBytes[0], localIPBytes[1], localIPBytes[2], localIPBytes[3])
			remoteIP = net.IPv4(remoteIPBytes[0], remoteIPBytes[1], remoteIPBytes[2], remoteIPBytes[3])
		} else if event.Family == 10 {
			// may be 4 to 6
			localIP = net.IP(localIPBytes)
			remoteIP = net.IP(remoteIPBytes)
		}

		fmt.Printf("Received event: process: %d, local ip: %s, remote ip: %s, local port: %d, remote port: %d, proto: %s, role: %s, rx_bytes: %d, tx_bytes: %d, state: %d\n",
			event.Rec.Pid, localIP, remoteIP, event.Lport, event.Rport, Proto(event.Proto), Role(event.Role), event.RxBytes, event.TxBytes, event.State)
	}
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
