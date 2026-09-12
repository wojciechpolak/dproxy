// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build windows

package privatepath

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func TestWindowsPrivateACLAllowsOnlyTheCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(path, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(path, info); err != nil {
		t.Fatal(err)
	}

	everyone, err := syscall.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceACLForTest(path, everyone); err != nil {
		t.Fatal(err)
	}
	if err := Validate(path, info); err == nil {
		t.Fatal("an ACL granting access to Everyone was accepted as private")
	}
}

func replaceACLForTest(path string, sid *syscall.SID) error {
	entry := windowsExplicitAccess{
		permissions: windowsGenericAll,
		accessMode:  windowsSetAccess,
		trustee: windowsTrustee{
			trusteeForm: windowsTrusteeIsSID,
			trusteeType: windowsTrusteeIsUser,
			value:       uintptr(unsafe.Pointer(sid)),
		},
	}
	var pinner runtime.Pinner
	pinner.Pin(sid)
	defer pinner.Unpin()
	var acl *windowsACL
	result, _, _ := windowsSetEntriesInACL.Call(
		1,
		uintptr(unsafe.Pointer(&entry)),
		0,
		uintptr(unsafe.Pointer(&acl)),
	)
	if result != 0 {
		return syscall.Errno(result)
	}
	defer func() { _, _ = syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(acl)))) }()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	result, _, _ = windowsSetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(name)),
		windowsFileObject,
		windowsDACLInformation|windowsProtectedDACLInformation,
		0,
		0,
		uintptr(unsafe.Pointer(acl)),
		0,
	)
	runtime.KeepAlive(entry)
	runtime.KeepAlive(name)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}
