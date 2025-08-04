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