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

type ServerResult struct {
	IP    string
	Title string
	Type  string
}

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

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func getAllIPs(ip net.IP, ipNet *net.IPNet) []string {
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

// C:\Users\Traballo\go\bin\rsrc.exe -manifest proxmox-findergo.exe.manifest -ico C:\Users\Traballo\GolandProjects\proxmox-findergo\icon.ico -o rsrc.syso
// go build -o ..\bin\proxmox-findergo.exe

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

func main() {
	fmt.Println("------------------------")
	fmt.Println("- PROXMOX & NAS FINDER -")
	fmt.Println("------------------------")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Introduce ip [192.168.10.0/24]:\n> ")
	ipIn, _ := reader.ReadString('\n')
	ipIn = strings.TrimSpace(ipIn)
	if ipIn == "" {
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
