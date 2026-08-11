package scanner

// Nic representa una tarjeta de red con su configuración. Se define
// aquí, sin build tag, para que sea visible desde la API pública
// del paquete en cualquier sistema operativo.
type Nic struct {
	Hostname string   `json:"hostname"`
	Name     string   `json:"name"`
	IP       []string `json:"ip"`
	Subnet   []string `json:"subnet"`
	Hardware string   `json:"hardware"`
	MAC      string   `json:"mac"`
	Gateway  []string `json:"gateway"`
}
