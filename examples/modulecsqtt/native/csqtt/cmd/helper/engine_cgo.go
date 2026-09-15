//go:build cgo && !windows

package main

/*
#cgo linux LDFLAGS: -ldl
#cgo android LDFLAGS: -ldl
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int32_t (*csqtt_protect_cb)(int64_t);

static void *eng;
static void (*fn_set_protect)(csqtt_protect_cb);
static int32_t (*fn_start)(const char *);
static int32_t (*fn_wait_ready)(int32_t);
static int32_t (*fn_packet_port)(void);
static int32_t (*fn_tun_ip)(char *, int32_t);
static int32_t (*fn_tun_dns)(char *, int32_t);
static void (*fn_stop)(void);

extern int32_t goProtectFd(int64_t fd);

static int csqtt_load(const char *path) {
	eng = dlopen(path, RTLD_NOW);
	if (!eng) {
		return -1;
	}
	fn_set_protect = (void (*)(csqtt_protect_cb))dlsym(eng, "csqtt_engine_set_protect");
	fn_start = (int32_t (*)(const char *))dlsym(eng, "csqtt_engine_start");
	fn_wait_ready = (int32_t (*)(int32_t))dlsym(eng, "csqtt_engine_wait_ready");
	fn_packet_port = (int32_t (*)(void))dlsym(eng, "csqtt_engine_packet_port");
	fn_tun_ip = (int32_t (*)(char *, int32_t))dlsym(eng, "csqtt_engine_tun_ip");
	fn_tun_dns = (int32_t (*)(char *, int32_t))dlsym(eng, "csqtt_engine_tun_dns");
	fn_stop = (void (*)(void))dlsym(eng, "csqtt_engine_stop");
	if (!fn_start || !fn_wait_ready || !fn_packet_port || !fn_tun_ip || !fn_stop) {
		return -2;
	}
	return 0;
}

static const char *csqtt_dlerror(void) { return dlerror(); }

static void csqtt_bind_protect(void) {
	if (fn_set_protect) {
		fn_set_protect(goProtectFd);
	}
}

static int32_t csqtt_start(const char *j) { return fn_start ? fn_start(j) : -1; }
static int32_t csqtt_wait_ready(int32_t ms) { return fn_wait_ready ? fn_wait_ready(ms) : -1; }
static int32_t csqtt_packet_port(void) { return fn_packet_port ? fn_packet_port() : 0; }
static int32_t csqtt_tun_ip(char *b, int32_t n) { return fn_tun_ip ? fn_tun_ip(b, n) : -1; }
static int32_t csqtt_tun_dns(char *b, int32_t n) { return fn_tun_dns ? fn_tun_dns(b, n) : -1; }
static void csqtt_stop(void) { if (fn_stop) fn_stop(); }
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"
)

var protectImpl func(int64) bool

//export goProtectFd
func goProtectFd(fd C.int64_t) C.int32_t {
	if protectImpl == nil {
		return 1
	}
	if protectImpl(int64(fd)) {
		return 1
	}
	return 0
}

func engineLibName() string {
	if runtime.GOOS == "darwin" {
		return "libcsqtt_engine.dylib"
	}
	return "libcsqtt_engine.so"
}

func engineLoad(searchDirs ...string) error {
	path, err := findEngineLib(engineLibName(), searchDirs...)
	if err != nil {
		return err
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	if rc := C.csqtt_load(cpath); rc != 0 {
		errStr := C.GoString(C.csqtt_dlerror())
		return fmt.Errorf("dlopen %s: %s (code %d)", path, errStr, int(rc))
	}
	return nil
}

func engineSetProtect(fn func(int64) bool) {
	protectImpl = fn
	C.csqtt_bind_protect()
}

func engineStart(configJSON string) error {
	cj := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cj))
	if rc := C.csqtt_start(cj); rc != 0 {
		return fmt.Errorf("csqtt_engine_start: %d", int32(rc))
	}
	return nil
}

func engineWaitReady(timeoutMs int) error {
	if C.csqtt_wait_ready(C.int32_t(timeoutMs)) != 0 {
		return fmt.Errorf("engine not ready")
	}
	return nil
}

func enginePacketPort() int { return int(C.csqtt_packet_port()) }

func engineTunIP() string {
	buf := make([]byte, 128)
	if C.csqtt_tun_ip((*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(len(buf))) != 0 {
		return ""
	}
	return cstrFrom(buf)
}

func engineTunDNS() string {
	buf := make([]byte, 128)
	if C.csqtt_tun_dns((*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(len(buf))) != 0 {
		return ""
	}
	return cstrFrom(buf)
}

func cstrFrom(buf []byte) string {
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

func engineStop() { C.csqtt_stop() }

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
