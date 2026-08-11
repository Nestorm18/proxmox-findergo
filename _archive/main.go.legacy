// Package main implementa un escáner de red para encontrar servidores Proxmox y dispositivos NAS (Synology y QNAP)
// en una red local. Utiliza goroutines para realizar búsquedas concurrentes y mejorar el rendimiento.
package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// cleanHTMLTitle limpia las entidades HTML comunes del título de la página
// reemplazándolas por sus equivalentes en texto plano.
func cleanHTMLTitle(title string) string {
	// Reemplazar &nbsp; por espacio
	title = strings.ReplaceAll(title, "&nbsp;", " ")
	// Reemplazar otros caracteres HTML comunes si es necesario
	title = strings.ReplaceAll(title, "&amp;", "&")
	title = strings.ReplaceAll(title, "&lt;", "<")
	title = strings.ReplaceAll(title, "&gt;", ">")
	title = strings.ReplaceAll(title, "&quot;", "\"")
	return title
}

// ServerResult representa el resultado de la búsqueda de un servidor.
// Contiene la dirección IP, el título de la página web y el tipo de servidor.
type ServerResult struct {
	IP    string // Dirección IP del servidor
	Title string // Título de la página web del servidor
	Type  string // Tipo de servidor (Proxmox, Synology, QNAP)
}

// synologyFinder busca servidores Synology en una dirección IP específica.
// Se ejecuta como una goroutine y envía los resultados a través del canal results.
// Utiliza el puerto 5000 para la detección.
func synologyFinder(ipAddr string, wg *sync.WaitGroup, results chan<- ServerResult) {
	defer wg.Done()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: tr,
	}

	resp, err := client.Get("http://" + ipAddr + ":5000")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyString := string(bodyBytes)
	re := regexp.MustCompile(`<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(bodyString)
	if len(matches) > 1 && strings.Contains(strings.ToLower(matches[1]), "synology") {
		results <- ServerResult{
			IP:    ipAddr,
			Title: cleanHTMLTitle(matches[1]),
			Type:  "Synology",
		}
	}
}

// proxmoxFinder busca servidores Proxmox en una dirección IP específica.
// Se ejecuta como una goroutine y envía los resultados a través del canal results.
// Utiliza el puerto 8006 y conexión HTTPS para la detección.
func proxmoxFinder(ipAddr string, wg *sync.WaitGroup, results chan<- ServerResult) {
	defer wg.Done()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	resp, err := client.Get("https://" + ipAddr + ":8006")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyString := string(bodyBytes)
	re := regexp.MustCompile(`<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(bodyString)
	if len(matches) > 1 && strings.Contains(matches[1], "Proxmox") {
		results <- ServerResult{
			IP:    ipAddr,
			Title: matches[1],
			Type:  "Proxmox",
		}
	}
}

// qnapFinder busca servidores QNAP en una dirección IP específica.
// Se ejecuta como una goroutine y envía los resultados a través del canal results.
// Utiliza el puerto 8080 para la detección.
func qnapFinder(ipAddr string, wg *sync.WaitGroup, results chan<- ServerResult) {
	defer wg.Done()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	resp, err := client.Get("http://" + ipAddr + ":8080")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyString := string(bodyBytes)
	re := regexp.MustCompile(`<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(bodyString)
	if len(matches) > 1 && strings.Contains(strings.ToLower(matches[1]), "qnap") {
		results <- ServerResult{
			IP:    ipAddr,
			Title: matches[1],
			Type:  "QNAP",
		}
	}
}

// inc incrementa una dirección IP en 1.
// Se utiliza para generar todas las IPs en un rango CIDR.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getAllIPs genera una lista de todas las direcciones IP en un rango CIDR.
// Recibe una IP y una máscara de red, y devuelve un slice con todas las IPs posibles.
func getAllIPs(ip net.IP, ipNet *net.IPNet) []string {
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

// writeResults guarda los resultados de la búsqueda en un archivo de texto.
// El archivo incluirá secciones separadas para cada tipo de servidor encontrado.
func writeResults(filename string, results []ServerResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	writer.WriteString("------------------------\n")
	writer.WriteString("- PROXMOX & NAS FINDER -\n")
	writer.WriteString("------------------------\n\n")

	// Escribir resultados Proxmox
	writer.WriteString("Servidores Proxmox encontrados:\n")
	for _, result := range results {
		if result.Type == "Proxmox" {
			writer.WriteString(fmt.Sprintf("    %s -> https://%s:8006\n", result.Title, result.IP))
		}
	}
	writer.WriteString("\n")

	// Escribir resultados Synology
	writer.WriteString("Servidores Synology encontrados:\n")
	for _, result := range results {
		if result.Type == "Synology" {
			writer.WriteString(fmt.Sprintf("    %s -> http://%s:5000\n", result.Title, result.IP))
		}
	}
	writer.WriteString("\n")

	// Escribir resultados QNAP
	writer.WriteString("Servidores QNAP encontrados:\n")
	for _, result := range results {
		if result.Type == "QNAP" {
			writer.WriteString(fmt.Sprintf("    %s -> http://%s:8080\n", result.Title, result.IP))
		}
	}

	return writer.Flush()
}

// C:\Users\Traballo\go\bin\rsrc.exe -manifest proxmox-findergo.exe.manifest -ico C:\Users\Traballo\GolandProjects\proxmox-findergo\icon.ico -o rsrc.syso
// go build -o ..\bin\proxmox-findergo.exe
func main() {
	fmt.Println("------------------------")
	fmt.Println("- PROXMOX & NAS FINDER -")
	fmt.Println("------------------------")

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("1) 192.168.0.0/24")
	fmt.Println("2) 192.168.1.0/24")
	fmt.Println("3) 192.168.8.0/24")
	fmt.Println("4) 192.168.10.0/24")
	fmt.Print("  [192.168.10.0/24]: > ")

	ipIn, _ := reader.ReadString('\n')
	ipIn = strings.TrimSpace(ipIn)
	if ipIn == "" {
		ipIn = "192.168.10.0/24"
	} else if ipIn == "1" {
		ipIn = "192.168.0.0/24"
	} else if ipIn == "2" {
		ipIn = "192.168.1.0/24"
	} else if ipIn == "3" {
		ipIn = "192.168.8.0/24"
	} else if ipIn == "4" {
		ipIn = "192.168.10.0/24"
	}

	// ipIn := "192.168.10.0/24"
	fmt.Printf("Escanear %s\n", ipIn)

	ip, ipNet, err := net.ParseCIDR(ipIn)
	if err != nil {
		fmt.Printf("[-] El rango %s no es valido\n", ipIn)
		return
	}

	// Obtener todas las IPs del rango
	ips := getAllIPs(ip, ipNet)

	results := make(chan ServerResult, len(ips))
	var wg sync.WaitGroup
	var foundResults []ServerResult

	// Búsqueda de Proxmox y mostrar resultados inmediatos
	fmt.Println("\nBuscando servidores Proxmox...")
	for _, ip := range ips {
		wg.Add(1)
		go proxmoxFinder(ip, &wg, results)
	}
	wg.Wait()

	// Mostrar resultados de Proxmox inmediatamente
	var proxmoxFound bool
	foundSoFar := len(results)
	for i := 0; i < foundSoFar; i++ {
		result := <-results
		foundResults = append(foundResults, result)
		if result.Type == "Proxmox" {
			if !proxmoxFound {
				fmt.Println("[+] Servidores Proxmox encontrados:")
				proxmoxFound = true
			}
			fmt.Printf("    %s -> https://%s:8006\n", result.Title, result.IP)
		}
	}
	if !proxmoxFound {
		fmt.Println("[-] No se han encontrado servidores Proxmox")
	}

	// Búsqueda de Synology y mostrar resultados inmediatos
	fmt.Println("\nBuscando servidores Synology...")
	for _, ip := range ips {
		wg.Add(1)
		go synologyFinder(ip, &wg, results)
	}
	wg.Wait()

	var synologyFound bool
	foundSoFar = len(results)
	for i := 0; i < foundSoFar; i++ {
		result := <-results
		foundResults = append(foundResults, result)
		if result.Type == "Synology" {
			if !synologyFound {
				fmt.Println("[+] Servidores Synology encontrados:")
				synologyFound = true
			}
			fmt.Printf("    %s -> http://%s:5000\n", result.Title, result.IP)
		}
	}
	if !synologyFound {
		fmt.Println("[-] No se han encontrado servidores Synology")
	}

	// Búsqueda de QNAP y mostrar resultados inmediatos
	fmt.Println("\nBuscando servidores QNAP...")
	for _, ip := range ips {
		wg.Add(1)
		go qnapFinder(ip, &wg, results)
	}
	wg.Wait()

	var qnapFound bool
	foundSoFar = len(results)
	for i := 0; i < foundSoFar; i++ {
		result := <-results
		foundResults = append(foundResults, result)
		if result.Type == "QNAP" {
			if !qnapFound {
				fmt.Println("[+] Servidores QNAP encontrados:")
				qnapFound = true
			}
			fmt.Printf("    %s -> http://%s:8080\n", result.Title, result.IP)
		}
	}
	if !qnapFound {
		fmt.Println("[-] No se han encontrado servidores QNAP")
	}

	close(results)

	// Después de mostrar todos los resultados y antes de mostrar la información adicional
	filename := "resultados_busqueda.txt"
	if err := writeResults(filename, foundResults); err != nil {
		fmt.Printf("[-] Error al guardar los resultados: %v\n", err)
	} else {
		fmt.Printf("\n[+] Resultados guardados en: %s\n", filename)
	}

	fmt.Print("\n[+] Mostrar Informacion adicional (s/[n]):\n> ")
	extra, _ := reader.ReadString('\n')
	extra = strings.TrimSpace(extra)
	if extra == "n" {
		fmt.Println("\n[+] Programa finalizado (Pulsa ENTER para finalizar)")
		reader.ReadString('\n')
		return
	}

	fmt.Println("\n[+] Tarjetas de red:")
	nics, err := GetNics()
	if err != nil {
		fmt.Println("Error obteniendo tarjetas de red:", err)
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

	fmt.Println("\n[+] Programa finalizado (Pulsa ENTER para finalizar)")
	reader.ReadString('\n')
}
