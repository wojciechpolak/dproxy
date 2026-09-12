// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build windows

// Package privatepath applies and validates access controls for files that
// contain dproxy credentials.
package privatepath

import (
	"fmt"
	"io/fs"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	windowsGenericAll                     = 0x10000000
	windowsSetAccess                      = 2
	windowsNoInheritance                  = 0
	windowsSubcontainersAndObjectsInherit = 3
	windowsTrusteeIsSID                   = 0
	windowsTrusteeIsUser                  = 1
	windowsFileObject                     = 1
	windowsDACLInformation                = 0x00000004
	windowsProtectedDACLInformation       = 0x80000000
	windowsDACLProtected                  = 0x1000
	windowsAccessAllowedACE               = 0
)

type windowsACL struct {
	revision byte
	padding1 byte
	size     uint16
	aceCount uint16
	padding2 uint16
}

type windowsTrustee struct {
	multipleTrustee          *windowsTrustee
	multipleTrusteeOperation uint32
	trusteeForm              uint32
	trusteeType              uint32
	value                    uintptr
}

type windowsExplicitAccess struct {
	permissions uint32
	accessMode  uint32
	inheritance uint32
	trustee     windowsTrustee
}

type windowsACEHeader struct {
	aceType  byte
	aceFlags byte
	aceSize  uint16
}

type windowsAccessAllowedACERecord struct {
	header   windowsACEHeader
	mask     uint32
	sidStart uint32
}

type windowsSecurityDescriptor struct{}

var (
	windowsSecurity                     = syscall.NewLazyDLL("advapi32.dll")
	windowsSetEntriesInACL              = windowsSecurity.NewProc("SetEntriesInAclW")
	windowsSetNamedSecurityInfo         = windowsSecurity.NewProc("SetNamedSecurityInfoW")
	windowsGetNamedSecurityInfo         = windowsSecurity.NewProc("GetNamedSecurityInfoW")
	windowsGetSecurityDescriptorControl = windowsSecurity.NewProc("GetSecurityDescriptorControl")
	windowsGetACE                       = windowsSecurity.NewProc("GetAce")
	windowsEqualSID                     = windowsSecurity.NewProc("EqualSid")
)

// Restrict installs a protected DACL with one entry for the current user.
// Directory entries inherit the same restriction to new children.
func Restrict(path string, directory bool) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("get current Windows user: %w", err)
	}
	inheritance := uint32(windowsNoInheritance)
	if directory {
		inheritance = windowsSubcontainersAndObjectsInherit
	}
	entry := windowsExplicitAccess{
		permissions: windowsGenericAll,
		accessMode:  windowsSetAccess,
		inheritance: inheritance,
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
		return fmt.Errorf("build private Windows access-control list: %w", syscall.Errno(result))
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
		return fmt.Errorf("set private Windows access-control list on %s: %w", path, syscall.Errno(result))
	}
	return nil
}

// Validate rejects inherited ACLs and ACLs that grant access to any principal
// other than the current user.
func Validate(path string, _ fs.FileInfo) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("get current Windows user: %w", err)
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var acl *windowsACL
	var descriptor *windowsSecurityDescriptor
	result, _, _ := windowsGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(name)),
		windowsFileObject,
		windowsDACLInformation,
		0,
		0,
		uintptr(unsafe.Pointer(&acl)),
		0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	runtime.KeepAlive(name)
	if result != 0 {
		return fmt.Errorf("read Windows permissions for %s: %w", path, syscall.Errno(result))
	}
	if descriptor == nil {
		return fmt.Errorf("%s permissions have no Windows security descriptor", path)
	}
	defer func() { _, _ = syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(descriptor)))) }()
	if acl == nil {
		return fmt.Errorf("%s permissions have no private Windows access-control list", path)
	}

	var control uint16
	var revision uint32
	success, _, callErr := windowsGetSecurityDescriptorControl.Call(
		uintptr(unsafe.Pointer(descriptor)),
		uintptr(unsafe.Pointer(&control)),
		uintptr(unsafe.Pointer(&revision)),
	)
	if success == 0 {
		return windowsCallError("read Windows access-control flags", callErr)
	}
	if control&windowsDACLProtected == 0 || acl.aceCount != 1 {
		return fmt.Errorf("%s permissions do not have an isolated Windows access-control list", path)
	}

	var ace *windowsAccessAllowedACERecord
	success, _, callErr = windowsGetACE.Call(
		uintptr(unsafe.Pointer(acl)),
		0,
		uintptr(unsafe.Pointer(&ace)),
	)
	if success == 0 {
		return windowsCallError("read Windows access-control entry", callErr)
	}
	if ace.header.aceType != windowsAccessAllowedACE {
		return fmt.Errorf("%s permissions contain a non-user Windows access-control entry", path)
	}
	aceSID := (*syscall.SID)(unsafe.Pointer(&ace.sidStart))
	equal, _, _ := windowsEqualSID.Call(
		uintptr(unsafe.Pointer(aceSID)),
		uintptr(unsafe.Pointer(sid)),
	)
	runtime.KeepAlive(sid)
	if equal == 0 {
		return fmt.Errorf("%s permissions grant access to another Windows principal", path)
	}
	return nil
}

func currentUserSID() (*syscall.SID, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid.Copy()
}

func windowsCallError(action string, err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return fmt.Errorf("%s failed", action)
	}
	return fmt.Errorf("%s: %w", action, err)
}
