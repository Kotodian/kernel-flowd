package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	dns "golang.org/x/net/dns/dnsmessage"
)

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
		log.Fatalf("loading objects: %s", err)
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
		if event.Family == 2 {
			localIP := fmt.Sprintf("%d.%d.%d.%d", localIPBytes[0], localIPBytes[1], localIPBytes[2], localIPBytes[3])
			remoteIP := fmt.Sprintf("%d.%d.%d.%d", remoteIPBytes[0], remoteIPBytes[1], remoteIPBytes[2], remoteIPBytes[3])
			if remoteIP == "223.5.5.5" && event.Rport == 53 {
				fmt.Printf("Received event: process: %d, local ip: %s, remote ip: %s, local port: %d, remote port: %d, role: %s, rx_bytes: %d, tx_bytes: %d, state: %d\n",
					event.Rec.Pid, localIP, remoteIP, event.Lport, event.Rport, Role(event.Role).String(), event.RxBytes, event.TxBytes, event.State)
				for i := 0; i < int(event.AppMsg.Cnt); i++ {
					if event.AppMsg.Len[i] > 0 {
						data := make([]byte, event.AppMsg.Len[i])
						for j := 0; j < int(event.AppMsg.Len[i]); j++ {
							data[j] = byte(event.AppMsg.Data[i][j])
						}
						message := dns.Message{}
						err := message.Unpack(data)
						if err != nil {
							fmt.Println(err)
							continue
						}
						for _, answer := range message.Answers {
							fmt.Println(answer.GoString())
						}
					}
				}
			}
		}
	}
}
