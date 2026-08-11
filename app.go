// Package main contiene la App de Wails y sus métodos bound
// (los que se exponen al frontend JS).
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"proxmox-findergo/scanner"
)

// App es la estructura que Wails expone al frontend. Mantiene el
// estado del escaneo en curso y la lista de resultados acumulados.
type App struct {
	ctx context.Context

	mu       sync.Mutex
	cidr     string
	results  []scanner.ServerResult
	scanning bool
	cancel   context.CancelFunc
}

// NewApp construye una App vacía. El contexto se asigna desde
// startup.go cuando Wails inicia el runtime.
func NewApp() *App {
	return &App{
		cidr:    "192.168.10.0/24",
		results: []scanner.ServerResult{},
	}
}

// startup es un hook del ciclo de vida de Wails: se ejecuta cuando
// la ventana está lista para recibir llamadas. Aquí guardamos el
// contexto para emitir eventos al frontend.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// ----- Métodos expuestos al frontend JS -----

// PresetCIDRs devuelve los rangos CIDR predefinidos que se
// muestran en el selector del UI.
func (a *App) PresetCIDRs() []string {
	return []string{
		"192.168.0.0/24",
		"192.168.1.0/24",
		"192.168.8.0/24",
		"192.168.10.0/24",
	}
}

// DefaultCIDR devuelve el CIDR por defecto seleccionado en la UI.
func (a *App) DefaultCIDR() string {
	return a.cidr
}

// SetCIDR fija el rango a escanear. Lo valida antes de aceptarlo;
// devuelve un error si el CIDR es inválido para no iniciar un
// escaneo que falle a mitad de camino.
func (a *App) SetCIDR(cidr string) error {
	if _, err := scanner.GetAllIPs(cidr); err != nil {
		return err
	}
	a.mu.Lock()
	a.cidr = cidr
	a.mu.Unlock()
	return nil
}

// IsScanning indica si hay un escaneo en curso (lo usa la UI para
// habilitar/deshabilitar el botón de iniciar).
func (a *App) IsScanning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.scanning
}

// StartScan arranca un escaneo en segundo plano. Devuelve un error
// si ya hay uno en curso o si el CIDR no es válido.
//
// Los resultados se van emitiendo como eventos `scan:result` y el
// progreso como `scan:progress`. Al terminar se emite `scan:complete`.
func (a *App) StartScan() error {
	a.mu.Lock()
	if a.scanning {
		a.mu.Unlock()
		return fmt.Errorf("ya hay un escaneo en curso")
	}
	cidr := a.cidr
	a.results = a.results[:0]
	a.scanning = true
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	a.mu.Unlock()

	go a.runScan(ctx, cidr)
	return nil
}

// StopScan solicita la cancelación del escaneo en curso. No es
// bloqueante: el evento `scan:complete` se emitirá cuando las
// goroutines en vuelo terminen.
func (a *App) StopScan() {
	a.mu.Lock()
	cancel := a.cancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Results devuelve una copia de los resultados acumulados hasta
// el momento. Es lo que la UI consulta si se reabre la ventana
// después de un escaneo.
func (a *App) Results() []scanner.ServerResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]scanner.ServerResult, len(a.results))
	copy(out, a.results)
	return out
}

// ClearResults vacía la lista de resultados.
func (a *App) ClearResults() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.results = a.results[:0]
}

// GetNics devuelve la información de las tarjetas de red del host.
// En sistemas no-Windows devuelve un slice vacío.
func (a *App) GetNics() ([]scanner.Nic, error) {
	return scanner.GetNics()
}

// SaveResults abre un diálogo de "Guardar como" y escribe los
// resultados en el archivo elegido. Devuelve la ruta escrita
// (vacía si el usuario canceló).
func (a *App) SaveResults() (string, error) {
	a.mu.Lock()
	results := make([]scanner.ServerResult, len(a.results))
	copy(results, a.results)
	a.mu.Unlock()

	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Guardar resultados",
		DefaultFilename: "resultados_busqueda.txt",
		Filters: []runtime.FileFilter{
			{DisplayName: "Archivos de texto (*.txt)", Pattern: "*.txt"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	if err := writeResultsFile(path, results); err != nil {
		return "", err
	}
	return path, nil
}

// ----- Lógica interna -----

// runScan ejecuta el escaneo y emite los eventos al frontend.
// Se ejecuta en su propia goroutine; el método retorna cuando el
// escaneo termina o se cancela.
func (a *App) runScan(ctx context.Context, cidr string) {
	start := time.Now()
	runtime.EventsEmit(a.ctx, "scan:start", map[string]any{"cidr": cidr})

	_, _ = scanner.ScanAll(ctx, scanner.Options{CIDR: cidr, Timeout: 5 * time.Second}, scanner.Callbacks{
		OnResult: func(r scanner.ServerResult) {
			a.mu.Lock()
			a.results = append(a.results, r)
			a.mu.Unlock()
			runtime.EventsEmit(a.ctx, "scan:result", r)
		},
		OnError: func(err error) {
			runtime.EventsEmit(a.ctx, "scan:error", map[string]string{"message": err.Error()})
		},
		OnProgress: func(scanned, total int) {
			runtime.EventsEmit(a.ctx, "scan:progress", map[string]int{
				"scanned": scanned,
				"total":   total,
			})
		},
	})

	a.mu.Lock()
	a.scanning = false
	a.cancel = nil
	count := len(a.results)
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "scan:complete", map[string]any{
		"count":      count,
		"durationMs": time.Since(start).Milliseconds(),
		"cancelled":  ctx.Err() != nil,
	})
}

// writeResultsFile persiste los resultados en un archivo de texto
// siguiendo el mismo formato que la versión CLI.
func writeResultsFile(path string, results []scanner.ServerResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	fmt.Fprintln(w, "------------------------")
	fmt.Fprintln(w, "- PROXMOX & NAS FINDER -")
	fmt.Fprintln(w, "------------------------")
	fmt.Fprintln(w)

	sections := []struct {
		label  string
		typ    scanner.ServerType
		scheme string
		port   int
	}{
		{"Servidores Proxmox", scanner.TypeProxmox, "https", 8006},
		{"Servidores Synology", scanner.TypeSynology, "http", 5000},
		{"Servidores QNAP", scanner.TypeQNAP, "http", 8080},
	}
	for _, s := range sections {
		fmt.Fprintf(w, "%s encontrados:\n", s.label)
		count := 0
		for _, r := range results {
			if r.Type == s.typ {
				fmt.Fprintf(w, "    %s -> %s://%s:%d\n", r.Title, s.scheme, r.IP, s.port)
				count++
			}
		}
		if count == 0 {
			fmt.Fprintln(w, "    (ninguno)")
		}
		fmt.Fprintln(w)
	}
	return nil
}
