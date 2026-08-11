package scanner

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// titleRe captura el contenido de la primera etiqueta <title>...</title>
// que aparezca en la respuesta. La búsqueda no es multilínea porque las
// páginas de login de Proxmox, Synology y QNAP siempre la emiten en una
// sola línea, y esto evita trabajo extra en respuestas grandes.
var titleRe = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

// client construye un http.Client con TLS laxo y timeout dado.
// Se construye uno nuevo por probe para que el timeout se respete
// incluso si el caller reutiliza este paquete.
func client(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

// fetchTitle hace un GET al scheme://ip:port y devuelve el contenido
// del <title> limpio de entidades HTML comunes. Si la petición falla
// o no se encuentra título, devuelve ok=false.
func fetchTitle(ctx context.Context, scheme, addr string, timeout time.Duration) (string, bool) {
	c := client(timeout)
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+addr, nil)
	if err != nil {
		return "", false
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	m := titleRe.FindStringSubmatch(string(body))
	if len(m) < 2 {
		return "", false
	}
	return cleanHTMLTitle(m[1]), true
}

// cleanHTMLTitle reemplaza las entidades HTML más comunes por su
// equivalente en texto plano, para que los títulos se vean limpios
// tanto en consola como en la UI.
func cleanHTMLTitle(title string) string {
	repl := strings.NewReplacer(
		"&nbsp;", " ",
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", `"`,
		"&apos;", "'",
	)
	return repl.Replace(title)
}

// containsFold es un equivalente case-insensitive de strings.Contains
// sin asignar memoria intermedia (útil cuando se llama muchas veces
// dentro de un escaneo concurrente).
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// probeProxmox intenta detectar un servidor Proxmox en la IP y puerto
// dados. Devuelve el título y ok=true si la respuesta contiene
// "Proxmox" en el <title>.
func probeProxmox(ctx context.Context, ip string, timeout time.Duration) (string, bool) {
	addr := ip + ":8006"
	title, ok := fetchTitle(ctx, "https", addr, timeout)
	if !ok {
		return "", false
	}
	if !containsFold(title, "Proxmox") {
		return "", false
	}
	return title, true
}

// probeSynology intenta detectar un NAS Synology.
func probeSynology(ctx context.Context, ip string, timeout time.Duration) (string, bool) {
	addr := ip + ":5000"
	title, ok := fetchTitle(ctx, "http", addr, timeout)
	if !ok {
		return "", false
	}
	if !containsFold(title, "synology") {
		return "", false
	}
	return title, true
}

// probeQNAP intenta detectar un NAS QNAP.
func probeQNAP(ctx context.Context, ip string, timeout time.Duration) (string, bool) {
	addr := ip + ":8080"
	title, ok := fetchTitle(ctx, "http", addr, timeout)
	if !ok {
		return "", false
	}
	if !containsFold(title, "qnap") {
		return "", false
	}
	return title, true
}
