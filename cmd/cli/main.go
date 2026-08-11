// Proxmox & NAS Finder - versión de línea de comandos.
//
// La lógica de detección vive en el paquete interno `scanner`.
// Este binario solo se encarga de la interacción con el usuario
// en consola, mostrando los resultados según se descubren y
// guardándolos al final en un archivo de texto.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"proxmox-findergo/scanner"
)

const outputFile = "resultados_busqueda.txt"

// presetCIDRs es la lista de rangos predefinidos que se ofrecen
// al usuario. La opción por defecto (la última) es 192.168.10.0/24.
var presetCIDRs = []string{
	"192.168.0.0/24",
	"192.168.1.0/24",
	"192.168.8.0/24",
	"192.168.10.0/24",
}

func main() {
	printBanner()

	reader := bufio.NewReader(os.Stdin)
	cidr := askCIDR(reader)
	fmt.Printf("\nEscaneando %s\n\n", cidr)

	ctx := context.Background()
	results, err := scanner.ScanAll(ctx, scanner.Options{CIDR: cidr, Timeout: 5 * time.Second}, scanner.Callbacks{
		OnResult: func(r scanner.ServerResult) {
			switch r.Type {
			case scanner.TypeProxmox:
				fmt.Printf("    [Proxmox]  %s -> https://%s:8006\n", r.Title, r.IP)
			case scanner.TypeSynology:
				fmt.Printf("    [Synology] %s -> http://%s:5000\n", r.Title, r.IP)
			case scanner.TypeQNAP:
				fmt.Printf("    [QNAP]     %s -> http://%s:8080\n", r.Title, r.IP)
			}
		},
	})
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		os.Exit(1)
	}

	printSummary(results)

	if err := saveResults(outputFile, results); err != nil {
		fmt.Printf("[-] Error guardando resultados: %v\n", err)
	} else {
		fmt.Printf("\n[+] Resultados guardados en: %s\n", outputFile)
	}

	if askYesNo(reader, "\n[+] ¿Mostrar información adicional de las tarjetas de red? (s/[n]): ") {
		printNics()
	}

	fmt.Println("\n[+] Programa finalizado (Pulsa ENTER para finalizar)")
	reader.ReadString('\n')
}

func printBanner() {
	fmt.Println("------------------------")
	fmt.Println("- PROXMOX & NAS FINDER -")
	fmt.Println("------------------------")
}

func askCIDR(reader *bufio.Reader) string {
	for i, c := range presetCIDRs {
		fmt.Printf("%d) %s\n", i+1, c)
	}
	fmt.Printf("  o introduce un CIDR manual [%s]: > ", presetCIDRs[len(presetCIDRs)-1])
	raw, _ := reader.ReadString('\n')
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return presetCIDRs[len(presetCIDRs)-1]
	}
	if idx, ok := parseInt(raw); ok {
		if idx >= 1 && idx <= len(presetCIDRs) {
			return presetCIDRs[idx-1]
		}
	}
	return raw
}

func parseInt(s string) (int, bool) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, false
	}
	return n, true
}

func askYesNo(reader *bufio.Reader, prompt string) bool {
	fmt.Print(prompt)
	raw, _ := reader.ReadString('\n')
	raw = strings.TrimSpace(strings.ToLower(raw))
	return raw == "s" || raw == "y" || raw == "si" || raw == "yes"
}

func printSummary(results []scanner.ServerResult) {
	buckets := map[scanner.ServerType][]scanner.ServerResult{
		scanner.TypeProxmox:  {},
		scanner.TypeSynology: {},
		scanner.TypeQNAP:     {},
	}
	for _, r := range results {
		buckets[r.Type] = append(buckets[r.Type], r)
	}
	for _, t := range []scanner.ServerType{scanner.TypeProxmox, scanner.TypeSynology, scanner.TypeQNAP} {
		fmt.Printf("\n%s encontrados: %d\n", t, len(buckets[t]))
		for _, r := range buckets[t] {
			fmt.Printf("  - %s (%s)\n", r.IP, r.Title)
		}
	}
}

// section describe cómo se imprime y persiste cada tipo de servidor.
type section struct {
	label  string
	typ    scanner.ServerType
	scheme string
	port   int
}

var sections = []section{
	{"Servidores Proxmox", scanner.TypeProxmox, "https", 8006},
	{"Servidores Synology", scanner.TypeSynology, "http", 5000},
	{"Servidores QNAP", scanner.TypeQNAP, "http", 8080},
}

func saveResults(path string, results []scanner.ServerResult) error {
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

func printNics() {
	fmt.Println("\n[+] Tarjetas de red:")
	nics, err := scanner.GetNics()
	if err != nil {
		fmt.Println("Error obteniendo tarjetas de red:", err)
		return
	}
	if len(nics) == 0 {
		fmt.Println("  (no disponible en este sistema)")
		return
	}
	for _, nic := range nics {
		fmt.Printf("\tHostname: %s\n", nic.Hostname)
		fmt.Printf("\tIP: %v\n", nic.IP)
		fmt.Printf("\tHardware: %s\n", nic.Hardware)
		fmt.Printf("\tMAC: %s\n", nic.MAC)
		fmt.Printf("\tGateway: %v\n", nic.Gateway)
		fmt.Println()
	}
}
