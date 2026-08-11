// main.go — entry point for the Wails GUI version.
//go:build desktop

// El frontend (HTML/CSS/JS) se embebe vía embed.FS, así que no
// hay paso de build de Node: `go build` produce un .exe autónomo.
package main

import (
	"embed"
	"log"
	"net/http"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"golang.org/x/sys/windows"
)

// quietFDs detaches from any inherited console and redirects stdout/stderr
// to the NUL device so a GUI-subsystem exe never spawns or attaches to a
// console window on Windows, regardless of what Wails/WebView2 writes.
func quietFDs() {
	k32 := windows.NewLazyDLL("kernel32")
	setHandle := k32.NewProc("SetStdHandle")
	freeConsole := k32.NewProc("FreeConsole")

	// 1) Detach from any inherited console.
	freeConsole.Call()

	// 2) Open NUL and point stdout/stderr/stdin handles at it so that
	//    any subsequent write goes to NUL — Windows will not allocate
	//    a console for those writes.
	nulName, _ := windows.UTF16PtrFromString("NUL")
	nulHandle, _ := windows.CreateFile(
		nulName,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if nulHandle != 0 && nulHandle != windows.InvalidHandle {
		setHandle.Call(uintptr(windows.STD_OUTPUT_HANDLE), uintptr(nulHandle))
		setHandle.Call(uintptr(windows.STD_ERROR_HANDLE), uintptr(nulHandle))
		setHandle.Call(uintptr(windows.STD_INPUT_HANDLE), uintptr(nulHandle))
	}

	// 3) Suppress Go's log package (it uses its own handle internally).
	log.SetOutput(os.NewFile(0, ""))
}

//go:embed all:frontend/dist
var assets embed.FS

// noCacheMiddleware fuerza a que WebView2 no use caché para los
// assets del frontend. Evita que arrastre versiones viejas del HTML/CSS
// entre builds.
func noCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func main() {
	quietFDs()
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "Proxmox & NAS Finder",
		Width:     1100,
		Height:    760,
		MinWidth:  900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets:     assets,
			Middleware: assetserver.ChainMiddleware(noCacheMiddleware),
		},
		BackgroundColour: &options.RGBA{R: 18, G: 20, B: 26, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		log.Fatalf("error iniciando Wails: %v", err)
	}
}
