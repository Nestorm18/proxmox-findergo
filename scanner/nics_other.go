//go:build !windows

// Stub no-Windows de GetNics. Devuelve un slice vacío y nil para
// que la GUI compile en cross-platform, aunque los datos solo
// estén disponibles en Windows (vía WMI).
package scanner

// GetNics devuelve siempre un slice vacío en sistemas no-Windows.
func GetNics() ([]Nic, error) {
	return nil, nil
}
