package main

import (
	"encoding/xml"
	"os/exec"
)

type Nic struct {
	Hostname string
	IP       []string
	Hardware string
	MAC      string
	Gateway  []string
}

type Property struct {
	Name  string `xml:"NAME,attr"`
	Value string `xml:"VALUE"`
}

type PropertyArray struct {
	Name   string   `xml:"NAME,attr"`
	Values []string `xml:"VALUE.ARRAY>VALUE"`
}

type Instance struct {
	Properties     []Property      `xml:"PROPERTY"`
	PropertyArrays []PropertyArray `xml:"PROPERTY.ARRAY"`
}

type Command struct {
	Results Results `xml:"RESULTS"`
}

type Results struct {
	Node      string     `xml:"NODE,attr"`
	Instances []Instance `xml:"CIM>INSTANCE"`
}

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
