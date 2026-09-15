package tunnel

import (
	"log"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type LinkEndpoint struct {
	dispatcherMu     sync.RWMutex
	dispatcher       stack.NetworkDispatcher
	onOutgoingPacket func([]byte)
	packetIn         atomic.Uint64
	packetOut        atomic.Uint64
}

func NewLinkEndpoint() *LinkEndpoint {
	return &LinkEndpoint{}
}

func (e *LinkEndpoint) SetOutgoingPacketHandler(fn func([]byte)) {
	e.onOutgoingPacket = fn
}

func (e *LinkEndpoint) InjectInbound(data []byte) {
	e.packetIn.Add(1)
	e.dispatcherMu.RLock()
	dispatcher := e.dispatcher
	e.dispatcherMu.RUnlock()
	if dispatcher == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUNNEL] recovered from inbound panic (%d bytes): %v", len(data), r)
		}
	}()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte{}, data...)),
	})
	dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
}

func (e *LinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		data := pkt.ToView().ToSlice()
		e.packetOut.Add(1)
		if e.onOutgoingPacket != nil {
			e.onOutgoingPacket(data)
		}
		n++
	}
	return n, nil
}

func (e *LinkEndpoint) MTU() uint32 { return 1300 }
func (e *LinkEndpoint) MaxHeaderLength() uint16         { return 0 }
func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress  { return "\x02\x00\x00\x00\x00\x01" }
func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcherMu.Lock()
	e.dispatcher = dispatcher
	e.dispatcherMu.Unlock()
}
func (e *LinkEndpoint) IsAttached() bool {
	e.dispatcherMu.RLock()
	defer e.dispatcherMu.RUnlock()
	return e.dispatcher != nil
}
func (e *LinkEndpoint) Wait()                                   {}
func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *LinkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *LinkEndpoint) Close()                                  {}
func (e *LinkEndpoint) SetMTU(uint32)                           {}
func (e *LinkEndpoint) SetLinkAddress(tcpip.LinkAddress)        {}
func (e *LinkEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (e *LinkEndpoint) SetOnCloseAction(func())                 {}
