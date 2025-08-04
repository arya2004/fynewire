package capture

/*
#cgo CFLAGS:  -I${SRCDIR}/../../C
#cgo LDFLAGS: -L${SRCDIR}/../../C -lsniffer -lpcap
#include "sniffer.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)


func Interfaces() ([]string, error) {

	var cList **C.char
	var cCnt C.int
	if C.snf_list_devs(&cList, &cCnt) != 0 {
		return nil, errPcap("list devs faille")
	}

	defer C.snf_free_devs(cList, cCnt)

	// converts **C.char to Go []string

	n := int(cCnt)
	tmp := (*[1 << 28] * C.char) (unsafe.Pointer(cList))[:n:n]

	out := make([]string, 0, n)

	for _, s := range tmp {
		out = append(out, C.GoString(s))
	}

	return out, nil


}




func open(dev string) error {
	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	if C.snf_open(cdev, 1600, 1, 100) != 0 {
		return errPcap("open failed")
	}
	
	return  nil

}




func closeCap() {
	C.snf_close()
}



func next() (summary, detail string, ok bool) {

	var s, d *C.char
	if C.snf_next_pkt(&s, &d) != 1 {
		return "", "", false
	}

	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	
	return C.GoString(s), C.GoString(d), true

}


func errPcap(msg string) error {
	return fmt.Errorf("pcap: %s", msg)
}