//go:build windows

// Implementación Windows de GetNics mediante la API nativa de Windows.
package scanner

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetNics devuelve las tarjetas de red activas con IP habilitada.
// GetAdaptersAddresses evita lanzar wmic.exe al iniciar la aplicación;
// además de ser más fiable en Windows actuales, no abre una consola fugaz.
func GetNics() ([]Nic, error) {
	const flags = windows.GAA_FLAG_INCLUDE_PREFIX |
		windows.GAA_FLAG_INCLUDE_GATEWAYS |
		windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER

	var size uint32 = 15 * 1024
	var first *windows.IpAdapterAddresses
	var buffer []byte
	loaded := false
	for attempts := 0; attempts < 3; attempts++ {
		buffer = make([]byte, size)
		first = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("no se pudo leer la configuración de red: %w", err)
		}
		loaded = true
		break
	}
	if !loaded {
		return nil, fmt.Errorf("no se pudo reservar memoria para leer la configuración de red")
	}

	hostname, _ := os.Hostname()
	nics := make([]Nic, 0, 4)
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}
		nic := Nic{
			Hostname: hostname,
			Name:     windows.UTF16PtrToString(adapter.FriendlyName),
			Hardware: windows.UTF16PtrToString(adapter.Description),
		}

		macLength := int(adapter.PhysicalAddressLength)
		if macLength > len(adapter.PhysicalAddress) {
			macLength = len(adapter.PhysicalAddress)
		}
		if macLength > 0 {
			nic.MAC = strings.ToUpper(net.HardwareAddr(adapter.PhysicalAddress[:macLength]).String())
		}

		for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			nic.IP = append(nic.IP, ip.String())
			nic.Subnet = append(nic.Subnet, fmt.Sprintf("/%d", address.OnLinkPrefixLength))
		}
		for gateway := adapter.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
			ip := gateway.Address.IP()
			if ip != nil && !ip.IsUnspecified() {
				nic.Gateway = append(nic.Gateway, ip.String())
			}
		}
		if len(nic.IP) > 0 {
			nics = append(nics, nic)
		}
	}

	// Las conexiones con gateway suelen ser las más útiles para elegir el CIDR.
	sort.SliceStable(nics, func(i, j int) bool {
		return len(nics[i].Gateway) > len(nics[j].Gateway)
	})
	runtime.KeepAlive(buffer)
	return nics, nil
}
