// Package scanner implementa la lógica de detección de servidores
// Proxmox, Synology y QNAP en una red local, así como la enumeración
// de las tarjetas de red del host.
//
// La API está diseñada para soportar escaneo en vivo: el llamador
// proporciona callbacks que se invocan a medida que se descubren
// resultados o se avanza en el barrido.
package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ServerType identifica el tipo de servidor detectado.
type ServerType string

const (
	TypeProxmox  ServerType = "Proxmox"
	TypeSynology ServerType = "Synology"
	TypeQNAP     ServerType = "QNAP"
)

// ServerResult representa un servidor detectado en la red.
type ServerResult struct {
	IP    string     `json:"ip"`
	Title string     `json:"title"`
	Type  ServerType `json:"type"`
}

// Callbacks agrupa los hooks opcionales que el llamador puede
// proporcionar para recibir actualizaciones durante el escaneo.
// Cualquier campo puede ser nil.
type Callbacks struct {
	// OnResult se invoca una vez por cada servidor detectado.
	OnResult func(ServerResult)
	// OnProgress se invoca de forma periódica con el número de
	// IPs escaneadas hasta el momento y el total. Se llama al menos
	// una vez al finalizar el escaneo.
	OnProgress func(scanned, total int)
	// OnError se invoca si el parseo del rango CIDR falla.
	OnError func(err error)
}

// Options controla el comportamiento de un escaneo.
type Options struct {
	// CIDR es el rango a escanear, p.ej. "192.168.1.0/24".
	CIDR string
	// Timeout por petición HTTP (por defecto 5s).
	Timeout time.Duration
}

// defaults aplica valores por defecto a las opciones vacías.
func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
}

// GetAllIPs devuelve todas las direcciones IP del rango CIDR
// proporcionado, incluyendo la dirección de red y la de broadcast.
func GetAllIPs(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("rango CIDR inválido %q: %w", cidr, err)
	}
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// incIP incrementa una IP en 1, manejando el overflow entre octetos.
// Es una variante IP-safe del operador++ sobre []byte.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// scanKind agrupa los parámetros comunes a los tres tipos de escaneo.
type scanKind struct {
	port    int
	scheme  string
	timeout time.Duration
	match   func(title string) bool
	label   ServerType
	finder  func(ctx context.Context, ip string, timeout time.Duration) (string, bool)
}

// runKind ejecuta un tipo de escaneo sobre el slice de IPs.
// Devuelve los resultados encontrados. Si ctx se cancela, retorna
// inmediatamente con los resultados parciales.
func runKind(ctx context.Context, ips []string, kind scanKind, cb Callbacks) []ServerResult {
	var (
		mu      sync.Mutex
		results = make([]ServerResult, 0, 8)
		wg      sync.WaitGroup
		done    atomic.Int64
	)
	total := len(ips)
	launching := true
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			launching = false
		default:
		}
		if !launching {
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer func() {
				completed := int(done.Add(1))
				if cb.OnProgress != nil && (completed == total || completed%4 == 0) {
					cb.OnProgress(completed, total)
				}
				wg.Done()
			}()
			title, ok := kind.finder(ctx, ip, kind.timeout)
			if !ok {
				return
			}
			res := ServerResult{IP: ip, Title: title, Type: kind.label}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
			if cb.OnResult != nil {
				cb.OnResult(res)
			}
		}(ip)
	}
	wg.Wait()
	completed := int(done.Load())
	if cb.OnProgress != nil && completed%4 != 0 {
		cb.OnProgress(completed, total)
	}
	return results
}

// ScanAll ejecuta los tres escaneos (Proxmox, Synology, QNAP) sobre
// el rango CIDR de las opciones, en serie, y emite resultados por el
// canal de callbacks según se van descubriendo.
//
// Devuelve el conjunto completo de resultados al finalizar, o un error
// si el CIDR es inválido.
func ScanAll(ctx context.Context, opts Options, cb Callbacks) ([]ServerResult, error) {
	opts.defaults()
	ips, err := GetAllIPs(opts.CIDR)
	if err != nil {
		if cb.OnError != nil {
			cb.OnError(err)
		}
		return nil, err
	}

	proxmox := scanKind{
		port:    8006,
		scheme:  "https",
		timeout: opts.Timeout,
		match:   func(t string) bool { return containsFold(t, "Proxmox") },
		label:   TypeProxmox,
		finder:  probeProxmox,
	}
	synology := scanKind{
		port:    5000,
		scheme:  "http",
		timeout: opts.Timeout,
		match:   func(t string) bool { return containsFold(t, "synology") },
		label:   TypeSynology,
		finder:  probeSynology,
	}
	qnap := scanKind{
		port:    8080,
		scheme:  "http",
		timeout: opts.Timeout,
		match:   func(t string) bool { return containsFold(t, "qnap") },
		label:   TypeQNAP,
		finder:  probeQNAP,
	}

	all := make([]ServerResult, 0, 16)
	kinds := []scanKind{proxmox, synology, qnap}
	for index, kind := range kinds {
		if ctx.Err() != nil {
			break
		}
		stageCallbacks := cb
		stageCallbacks.OnProgress = func(scanned, total int) {
			if cb.OnProgress != nil {
				cb.OnProgress(index*len(ips)+scanned, len(kinds)*total)
			}
		}
		all = append(all, runKind(ctx, ips, kind, stageCallbacks)...)
	}
	return all, nil
}
