package main

// #cgo LDFLAGS: -framework CoreFoundation -framework Security
// #include <CoreFoundation/CoreFoundation.h>
// #include <Security/Security.h>
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func secret(service, account string) (string, error) {
	cService := C.CString(service)
	cAccount := C.CString(account)

	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))

	cSize := C.UInt32(0)
	cPass := unsafe.Pointer(nil)

	if ret := C.SecKeychainFindGenericPassword(
		0, // default keychain
		C.UInt32(len(service)),
		cService,
		C.UInt32(len(account)),
		cAccount,
		&cSize,
		&cPass,
		nil,
	); ret != C.errSecSuccess {
		cMsg := C.SecCopyErrorMessageString(ret, nil)
		defer C.CFRelease(C.CFTypeRef(cMsg))
		cStr := C.CFStringGetCStringPtr(cMsg, C.kCFStringEncodingUTF8)
		if cStr != nil {
			return "", errors.New(C.GoString(cStr))
		}
		return "", fmt.Errorf("unknown error: %d", ret)
	}

	return C.GoStringN((*C.char)(cPass), C.int(cSize)), nil
}
