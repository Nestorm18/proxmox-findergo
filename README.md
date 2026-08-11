<h1 align="center">Proxmox & NAS Finder</h1>

<div align="center">

[![Status](https://img.shields.io/badge/status-active-success.svg)]() [![License](https://img.shields.io/badge/license-MIT-blue.svg)](/LICENSE)

</div>

---

<p align="center">
Una herramienta para encontrar servidores Proxmox y NAS (Synology, QNAP) en tu red local — disponible en versión <b>CLI</b> y <b>GUI</b>.
</p>

## 📝 Tabla de Contenidos

- [Sobre el Proyecto](#about)
- [Características](#features)
- [Estructura del proyecto](#structure)
- [Compilación](#building)
- [Uso (CLI)](#usage-cli)
- [Uso (GUI)](#usage-gui)
- [Tecnologías Utilizadas](#built_using)
- [Autores](#authors)

## 🧐 Sobre el Proyecto <a name = "about"></a>

Proxmox & NAS Finder es una herramienta escrita en Go que escanea tu red local en busca de servidores Proxmox y dispositivos NAS (Synology y QNAP). La lógica de detección vive en el paquete `scanner/` y se reutiliza desde dos frontales:

- **CLI** (`cmd/cli/`) — interfaz de línea de comandos clásica, sin dependencias.
- **GUI** (`main.go` + `app.go` + `frontend/`) — aplicación de escritorio construida con [Wails v2](https://wails.io), sin Node ni build de frontend: el HTML/CSS/JS se embebe con `embed.FS`.

La GUI se sirve con WebView2 (preinstalado en Windows 10/11), por lo que el `.exe` resultante es autónomo y de ~6 MB.

## ✨ Características <a name = "features"></a>

- Detección de servidores **Proxmox** (HTTPS puerto 8006)
- Detección de NAS **Synology** (HTTP puerto 5000)
- Detección de NAS **QNAP** (HTTP puerto 8080)
- Escaneo concurrente por IP para una detección rápida
- Rangos de red predefinidos + CIDR manual
- **Escaneo en vivo** en la GUI (los resultados aparecen según se descubren)
- Guardado de resultados en `resultados_busqueda.txt` desde ambas interfaces
- Información de las tarjetas de red del host (Windows, vía WMI)

## 🗂️ Estructura del proyecto <a name = "structure"></a>

```
proxmox-findergo/
├── main.go                  # Entrada de la GUI (Wails)
├── app.go                   # Métodos de la App expuestos al frontend
├── frontend/
│   └── index.html           # UI embebida (HTML + CSS + JS vanilla)
├── scanner/                 # Paquete de detección (compartido por CLI y GUI)
│   ├── scanner.go           #   API pública (ScanAll, GetAllIPs, tipos)
│   ├── probe.go             #   Probes HTTP/HTTPS por tipo de servidor
│   ├── nics.go              #   Tipo Nic
│   ├── nics_windows.go      #   GetNics vía WMI (solo Windows)
│   └── nics_other.go        #   Stub para otros sistemas
├── cmd/
│   └── cli/
│       └── main.go          # Entrada de la versión CLI
├── icon.ico                 # Icono de la app
├── rsrc.syso                # Recurso Windows generado con rsrc
└── proxmox-findergo.exe.manifest
```

## 🔨 Compilación <a name = "building"></a>

Necesitas Go 1.25+. Para la GUI también necesitas `rsrc` (un único `go install`, sin admin).

### Instalar dependencias auxiliares

```powershell
go install github.com/akavel/rsrc@latest
```

### Generar la GUI

```powershell
.\scripts\build-gui.ps1
```

El script:
1. Lee `icon.ico` y genera un `.ico` multi-resolución válido (16/32/48/64/128/256).
2. Usa `rsrc` para empaquetar el icono y `proxmox-findergo.exe.manifest` en un `.syso`.
3. Compila con `go build` aplicando los tags de Wails (`desktop,wv2runtime.download,production`) y `-H windowsgui` para que el `.exe` sea GUI pura.
4. Deja el binario en `bin\gui\proxmox-findergo.exe` y actualiza `main.exe` en la raíz para que ambos arranquen como GUI, sin consola.

> El manifest usa `asInvoker` (no necesita admin). Si algún día quieres que pida elevación, cambia el `level` a `requireAdministrator` en `proxmox-findergo.exe.manifest`.

> **¿Por qué un script en vez de `wails build`?** En Wails v2.13.0 el `.ico` que se genera en `build\windows\` sale corrupto (GDI+ no lo puede leer) y el binario resultante muestra el icono "W" por defecto. El script se salta ese paso y lo genera correctamente con .NET.

### Generar la CLI

```powershell
go build -o bin\cli\proxmox-findergo-cli.exe .\cmd\cli\
```

### Regenerar el icono a mano (opcional)

El script ya lo hace automáticamente, pero si quieres hacerlo manualmente:

```powershell
# 1) Generar .ico multi-resolución
#    (ver scripts/build-gui.ps1 para la lógica)
# 2) Crear el .syso
rsrc -manifest proxmox-findergo.exe.manifest -ico icon.ico -o proxmox-findergo-res.syso
# 3) Compilar
go build -tags desktop,wv2runtime.download,production -ldflags "-H windowsgui" -o bin\gui\proxmox-findergo.exe .
```

## 🎈 Uso — CLI <a name="usage-cli"></a>

```powershell
.\bin\cli\proxmox-findergo-cli.exe
```

1. Selecciona un rango (1-4) o introduce un CIDR manual.
2. El programa escanea y muestra los resultados por tipo.
3. Al finalizar guarda `resultados_busqueda.txt` en el directorio actual.
4. Opcionalmente muestra la información de las tarjetas de red.

## 🎈 Uso — GUI <a name="usage-gui"></a>

```powershell
.\bin\gui\proxmox-findergo.exe
```

La ventana tiene tres áreas:

- **Sidebar izquierda**
  - Selector de rango (predefinidos + CIDR manual con validación).
  - Botones **Iniciar**, **Detener**, **Limpiar** y **Guardar como…** (diálogo nativo).
  - Barra de progreso animada durante el escaneo.
  - Tarjetas con la info de las NICs del host.
- **Panel principal**
  - Cabecera con el total de servidores encontrados y un *pill* de estado (Listo / Escaneando / Completado / Error).
  - Tres grupos de resultados (Proxmox / Synology / QNAP) que se van llenando **en tiempo real** con una animación de entrada por cada servidor nuevo.
  - Cada resultado tiene un enlace "Abrir ↗" que lanza la URL correspondiente en el navegador por defecto.

Los resultados se van emitiendo desde el backend Go al frontend vía `runtime.EventsEmit` (eventos `scan:start`, `scan:result`, `scan:complete`, `scan:error`).

## ⛏️ Tecnologías Utilizadas <a name = "built_using"></a>

- [Go](https://go.dev/) — Lenguaje de programación
- [Wails v2](https://wails.io) — Backend Go + frontend embebido (sin Node)
- Paquetes estándar de Go:
  - `net/http`, `crypto/tls` — Peticiones HTTP
  - `sync`, `context` — Concurrencia y cancelación
  - `regexp` — Parsing de la etiqueta `<title>`
  - `encoding/xml`, `os/exec` — WMI para NICs en Windows
  - `embed` — Empaquetado del frontend
- WebView2 (Windows 10/11) — Render del frontend

## ✍️ Autores <a name = "authors"></a>

- [@Nestorm18](https://github.com/Nestorm18) — Idea & Development
