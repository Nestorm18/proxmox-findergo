<h1 align="center">Proxmox & NAS Finder</h1>

<div align="center">

[![Status](https://img.shields.io/badge/status-active-success.svg)]() [![License](https://img.shields.io/badge/license-MIT-blue.svg)](/LICENSE)

</div>

---

<p align="center">
Una herramienta para encontrar servidores Proxmox y NAS (Synology, QNAP) en tu red local
</p>

## 📝 Tabla de Contenidos

- [Sobre el Proyecto](#about)
- [Características](#features)
- [Instalación](#installation)
- [Uso](#usage)
- [Compilación](#building)
- [Tecnologías Utilizadas](#built_using)
- [Autores](#authors)

## 🧐 Sobre el Proyecto <a name = "about"></a>

Proxmox & NAS Finder es una herramienta de línea de comandos escrita en Go que escanea tu red local en busca de servidores Proxmox y dispositivos NAS (Synology y QNAP). La herramienta realiza búsquedas concurrentes para una rápida detección y guarda los resultados en un archivo de texto.

## ✨ Características <a name = "features"></a>

- Detección de servidores Proxmox (puerto 8006)
- Detección de NAS Synology (puerto 5000)
- Detección de NAS QNAP (puerto 8080)
- Escaneo concurrente para mayor velocidad
- Rangos de red predefinidos comunes
- Guardado automático de resultados
- Información adicional sobre tarjetas de red

## 🚀 Instalación <a name = "installation"></a>

### Descarga Directa
1. Descarga el archivo ejecutable más reciente desde la sección de releases
2. El programa no requiere instalación, simplemente ejecuta el archivo `.exe`

### Compilación desde Código Fuente

Para compilar el proyecto necesitarás:
1. Go 1.22.1 o superior
2. rsrc (para el icono de Windows)
```bash
go install github.com/akavel/rsrc@latest
```

## 🎈 Uso <a name="usage"></a>

1. Ejecuta el programa
2. Selecciona un rango de red:
   - 1) 192.168.0.0/24
   - 2) 192.168.1.0/24
   - 3) 192.168.8.0/24
   - 4) 192.168.10.0/24
   - O introduce manualmente un rango CIDR

El programa escaneará la red y:
- Mostrará los servidores encontrados en tiempo real
- Guardará los resultados en `resultados_busqueda.txt`
- Opcionalmente mostrará información sobre las tarjetas de red

## 🔨 Compilación <a name = "building"></a>

Para compilar el proyecto con el icono de Windows:

```powershell
# Generar el archivo de recursos
rsrc -manifest proxmox-findergo.exe.manifest -ico icon.ico -o rsrc.syso

# Compilar el ejecutable
go build -o bin/proxmox-findergo.exe
```

## ⛏️ Tecnologías Utilizadas <a name = "built_using"></a>

- [Go](https://go.dev/) - Lenguaje de programación
- Paquetes estándar de Go:
  - `net/http` - Peticiones HTTP
  - `sync` - Concurrencia
  - `regexp` - Análisis de respuestas
  - `crypto/tls` - Soporte TLS

## ✍️ Autores <a name = "authors"></a>

- [@Nestorm18](https://github.com/Nestorm18) - Idea & Development
