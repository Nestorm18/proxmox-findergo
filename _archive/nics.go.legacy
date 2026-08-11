// Package main proporciona funcionalidad para obtener información
// sobre las tarjetas de red del sistema Windows usando WMI.
package main

import (
	"encoding/xml"
	"os/exec"
)

// Nic representa una tarjeta de red con su configuración.
type Nic struct {
	Hostname string   // Nombre del host DNS
	IP       []string // Lista de direcciones IP
	Hardware string   // Descripción del hardware
	MAC      string   // Dirección MAC
	Gateway  []string // Lista de gateways por defecto
}

// Property representa una propiedad simple en el formato XML de WMI.
type Property struct {
	Name  string `xml:"NAME,attr"` // Nombre de la propiedad
	Value string `xml:"VALUE"`     // Valor de la propiedad
}

// PropertyArray representa una propiedad que contiene un array de valores en el formato XML de WMI.
type PropertyArray struct {
	Name   string   `xml:"NAME,attr"`         // Nombre de la propiedad
	Values []string `xml:"VALUE.ARRAY>VALUE"` // Array de valores
}

// Instance representa una instancia de objeto WMI con sus propiedades.
type Instance struct {
	Properties     []Property      `xml:"PROPERTY"`       // Propiedades simples
	PropertyArrays []PropertyArray `xml:"PROPERTY.ARRAY"` // Propiedades tipo array
}

// Command representa la estructura principal del comando WMI.
type Command struct {
	Results Results `xml:"RESULTS"` // Resultados del comando
}

// Results representa los resultados del comando WMI.
type Results struct {
	Node      string     `xml:"NODE,attr"`    // Nodo de resultados
	Instances []Instance `xml:"CIM>INSTANCE"` // Instancias encontradas
}

// GetNics obtiene información detallada sobre todas las tarjetas de red activas del sistema.
// Utiliza WMI (Windows Management Instrumentation) para obtener la información.
// Devuelve un slice de Nic y un error si algo falla.
func GetNics() ([]Nic, error) {
	cmd := exec.Command("wmic.exe", "nicconfig", "where", "IPEnabled  = True", "get", "ipaddress,MACAddress,IPSubnet,DNSHostName,Caption,DefaultIPGateway", "/format:rawxml")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var command Command
	if err := xml.Unmarshal(output, &command); err != nil {
		return nil, err
	}

	var nics []Nic
	for _, instance := range command.Results.Instances {
		nic := Nic{}
		for _, prop := range instance.Properties {
			switch prop.Name {
			case "DNSHostName":
				nic.Hostname = prop.Value
			case "Caption":
				nic.Hardware = prop.Value
			case "MACAddress":
				nic.MAC = prop.Value
			}
		}
		for _, propArray := range instance.PropertyArrays {
			switch propArray.Name {
			case "IPAddress":
				nic.IP = append(nic.IP, propArray.Values...)
			case "DefaultIPGateway":
				nic.Gateway = append(nic.Gateway, propArray.Values...)
			case "IPSubnet":
				// Aquí se asume que IPSubnet es una lista de subredes
				nic.IP = append(nic.IP, propArray.Values...)
			}
		}
		nics = append(nics, nic)
	}

	return nics, nil
}
