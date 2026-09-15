//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	engineDLL        *windows.LazyDLL
	procSetProtect   *windows.LazyProc
	procStart        *windows.LazyProc
	procWaitReady    *windows.LazyProc
	procPacketPort   *windows.LazyProc
	procTunIP        *windows.LazyProc
	procTunDNS       *windows.LazyProc
	procStop         *windows.LazyProc
	protectImpl      func(int64) bool
	protectCallback  uintptr
)

func engineLibName() string { return "csqtt_engine.dll" }

func engineLoad(searchDirs ...string) error {
	path, err := findEngineLib(engineLibName(), searchDirs...)
	if err != nil {
		return err
	}
	engineDLL = windows.NewLazyDLL(path)
	if err := engineDLL.Load(); err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	procSetProtect = engineDLL.NewProc("csqtt_engine_set_protect")
	procStart = engineDLL.NewProc("csqtt_engine_start")
	procWaitReady = engineDLL.NewProc("csqtt_engine_wait_ready")
	procPacketPort = engineDLL.NewProc("csqtt_engine_packet_port")
	procTunIP = engineDLL.NewProc("csqtt_engine_tun_ip")
	procTunDNS = engineDLL.NewProc("csqtt_engine_tun_dns")
	procStop = engineDLL.NewProc("csqtt_engine_stop")
	return nil
}

func engineSetProtect(fn func(int64) bool) {
	protectImpl = fn
	protectCallback = syscall.NewCallback(func(fd uintptr) uintptr {
		if protectImpl == nil {
			return 1
		}
		if protectImpl(int64(fd)) {
			return 1
		}
		return 0
	})
	_, _, _ = procSetProtect.Call(protectCallback)
}

func engineStart(configJSON string) error {
	p, err := windows.BytePtrFromString(configJSON)
	if err != nil {
		return err
	}
	r, _, _ := procStart.Call(uintptr(unsafe.Pointer(p)))
	if r != 0 {
		return fmt.Errorf("csqtt_engine_start: %d", int32(r))
	}
	return nil
}

func engineWaitReady(timeoutMs int) error {
	r, _, _ := procWaitReady.Call(uintptr(timeoutMs))
	if r != 0 {
		return fmt.Errorf("engine not ready")
	}
	return nil
}

func enginePacketPort() int {
	r, _, _ := procPacketPort.Call()
	return int(int32(r))
}

func engineTunIP() string  { return engineCString(procTunIP) }
func engineTunDNS() string { return engineCString(procTunDNS) }

func engineCString(p *windows.LazyProc) string {
	buf := make([]byte, 128)
	r, _, _ := p.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r != 0 {
		return ""
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

func engineStop() {
	if procStop != nil {
		_, _, _ = procStop.Call()
	}
}

func findEngineLib(name string, extra ...string) (string, error) {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	dirs = append(dirs, extra...)
	for _, d := range dirs {
		if d == "" {
			continue
		}
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	if env := os.Getenv("CSQTT_ENGINE_LIB"); env != "" {
		return env, nil
	}
	return "", fmt.Errorf("%s not found next to helper (searched %v)", name, dirs)
}
