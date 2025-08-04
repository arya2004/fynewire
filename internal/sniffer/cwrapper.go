package sniffer

/*
#cgo CFLAGS:  -I${SRCDIR}/../../C
#cgo LDFLAGS: -L${SRCDIR}/../../C -lsniffer -lpcap
#include "sniffer.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/arya2004/fynewire/internal/model"
)


type Sniffer interface {
	Start() error          
	Stop()                  
	Packets() <-chan model.Packet
}

var _ Sniffer = (*cSniffer)(nil)


func Interfaces() ([]string, error) {
	var all *C.pcap_if_t
	var e [C.PCAP_ERRBUF_SIZE]C.char
	if C.pcap_findalldevs(&all, &e[0]) != 0 {
		return nil, errors.New("pcap_findalldevs failed")
	}
	defer C.pcap_freealldevs(all)

	var out []string
	for d := all; d != nil; d = d.next {
		out = append(out, C.GoString(d.name))
	}
	return out, nil
}

func New(dev string) Sniffer { return &cSniffer{dev: dev} }

type cSniffer struct {
	dev   string
	pktCh chan model.Packet
	stop  chan struct{}
	once  sync.Once
}

func (s *cSniffer) Start() error {
	if s.pktCh != nil {
		return nil // already running
	}
	cdev := C.CString(s.dev)
	defer C.free(unsafe.Pointer(cdev))

	if C.snf_open(cdev, 1600, 1, 100) != 0 {
		return errors.New("snf_open failed")
	}

	s.pktCh = make(chan model.Packet, 128)
	s.stop = make(chan struct{})
	go s.loop()
	return nil
}

func (s *cSniffer) loop() {
	for {
		select {
		case <-s.stop:
			C.snf_close()
			close(s.pktCh)
			return
		default:
		}
		var cs, cd *C.char
		if C.snf_next_pkt(&cs, &cd) != 1 {
			continue
		}
		p := model.Packet{C.GoString(cs), C.GoString(cd)}
		C.free(unsafe.Pointer(cs))
		C.free(unsafe.Pointer(cd))
		s.pktCh <- p
	}
}

func (s *cSniffer) Stop() {
	s.once.Do(func() { close(s.stop) })
}

func (s *cSniffer) Packets() <-chan model.Packet { return s.pktCh }