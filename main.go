package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/citrix/adc-nitro-go/service"
	"golang.org/x/term"
)

// IpAddress represents data related to NetScaler IP addresses.
type IpAddress struct {
	IpAddress net.IP
	Network   *net.IPNet
	Vlan
}

// Vlan represents data related to Vlans configured on a NetScaler.
type Vlan struct {
	Id        string
	Interface []string
	Channel   []string
	Snip      string
}

// SubnetMaskMap is a function that returns a map of subnet masks that map decimal notation to their
// equivalent CIDR notation.
func SubnetMaskMap() map[string]string {
	subnetMap := make(map[string]string)
	subnetMap["255.0.0.0"] = "8"
	subnetMap["255.128.0.0"] = "9"
	subnetMap["255.192.0.0"] = "10"
	subnetMap["255.224.0.0"] = "11"
	subnetMap["255.240.0.0"] = "12"
	subnetMap["255.248.0.0"] = "13"
	subnetMap["255.252.0.0"] = "14"
	subnetMap["255.254.0.0"] = "15"
	subnetMap["255.255.0.0"] = "16"
	subnetMap["255.255.128.0"] = "17"
	subnetMap["255.255.192.0"] = "18"
	subnetMap["255.255.224.0"] = "19"
	subnetMap["255.255.240.0"] = "20"
	subnetMap["255.255.248.0"] = "21"
	subnetMap["255.255.252.0"] = "22"
	subnetMap["255.255.254.0"] = "23"
	subnetMap["255.255.255.0"] = "24"
	subnetMap["255.255.255.128"] = "25"
	subnetMap["255.255.255.192"] = "26"
	subnetMap["255.255.255.224"] = "27"
	subnetMap["255.255.255.240"] = "28"
	subnetMap["255.255.255.248"] = "29"
	subnetMap["255.255.255.252"] = "30"
	subnetMap["255.255.255.254"] = "31"
	subnetMap["255.255.255.255"] = "32"
	return subnetMap
}

// ConvertMask is a function that converts subnet masks from decimal notation to CIDR notation.
func ConvertMask(mask string) string {
	maskMap := SubnetMaskMap()
	decimalMask := maskMap[mask]
	return "/" + decimalMask
}

// GetNetScalerResources is a general function of retreiving an array of NetScaler resources, such as lbvserver or routes, as an example.
func GetNetScalerResources(c *service.NitroClient, resource string) ([]map[string]interface{}, error) {
	netscalerResources, err := c.FindAllResources(resource)
	if err != nil {
		return nil, err
	}
	return netscalerResources, nil
}

// GetNetScalerResource is a general function for retreiving information for a specific NetScaler resource, such as, a vlan, as an example.
func GetNetScalerResource(c *service.NitroClient, resourceType, resourceName string) (map[string]interface{}, error) {
	netscalerResource, err := c.FindResource(resourceType, resourceName)
	if err != nil {
		return nil, err
	}
	return netscalerResource, nil
}

// BuildSnips is a function that retreives NetScaler SNIPs and converts them from raw text data to an IpAddress struct type.  It returns an array of
// IpAddress types, in addition to an error.
func BuildSnips(i []map[string]interface{}, ipType string) ([]IpAddress, error) {
	var ipaddresses []IpAddress
	for _, snip := range i {
		if snip["type"].(string) == ipType {
			var ipaddress IpAddress
			var err error
			ipaddress.IpAddress, ipaddress.Network, err = net.ParseCIDR(snip["ipaddress"].(string) + ConvertMask(snip["netmask"].(string)))
			if err != nil {
				fmt.Println(err)
			}
			ipaddresses = append(ipaddresses, ipaddress)
		}
	}
	return ipaddresses, nil
}

// GetVlanIds is a function that retrieves a list of vlan ids as an array of strings.
func GetVlanIds(c *service.NitroClient, resourceType string) ([]string, error) {
	var vlanIds []string
	vlans, err := GetNetScalerResources(c, resourceType)
	if err != nil {
		fmt.Println(err)
	}
	for _, vlan := range vlans {
		vlanIds = append(vlanIds, vlan["id"].(string))
	}
	return vlanIds, nil
}

// GetVlanInfo is a function that retrieves vlan information and converts them into a Vlan struct type and returns
// an array of Vlans.
func GetVlanInfo(c *service.NitroClient, vlandIds []string) ([]Vlan, error) {
	var vlans []Vlan
	for _, vlanId := range vlandIds {
		vlanInfo, err := GetNetScalerResource(c, "vlan_binding", vlanId)
		if err != nil {
			fmt.Println(err)
		}
		var vlan Vlan
		vlan.Id = vlanId
		for k, _ := range vlanInfo {
			switch k {
			case "vlan_interface_binding":
				vlanInterfaces := vlanInfo["vlan_interface_binding"].([]interface{})
				for _, vIf := range vlanInterfaces {
					vlan.Interface = append(vlan.Interface, vIf.(map[string]interface{})["ifnum"].(string))
				}
			case "vlan_channel_binding":
				vlanChannel := vlanInfo["vlan_channel_binding"].([]interface{})
				for _, vCh := range vlanChannel {
					vlan.Channel = append(vlan.Channel, vCh.(map[string]interface{})["ifnum"].(string))
				}
			case "vlan_nsip_binding":
				vlanIpaddress := vlanInfo["vlan_nsip_binding"].([]interface{})
				for _, vIp := range vlanIpaddress {
					vlan.Snip = vIp.(map[string]interface{})["ipaddress"].(string)
				}
			}
		}
		vlans = append(vlans, vlan)
	}
	return vlans, nil
}

// BindSnipWithVlan is a function that binds Vlans to their respective SNIPs.  This allows for all relevant information to be
// access from within the same struct type.
func BindSnipWithVlan(snips []IpAddress, vlans []Vlan) []IpAddress {
	var Ipaddresses []IpAddress
	for _, snip := range snips {
		for _, vlan := range vlans {
			if snip.Network.Contains(net.ParseIP(vlan.Snip)) {
				snip.Vlan = vlan
			}
		}
		Ipaddresses = append(Ipaddresses, snip)
	}
	return Ipaddresses
}

// DefaultRouteIPaddress is a function that returns the IpAddress and relevant Vlan info for the default route.
func DefaultRouteIPaddress(c *service.NitroClient, resourceType string) (IpAddress, error) {
	var ip IpAddress
	routes, err := GetNetScalerResources(c, resourceType)
	if err != nil {
		fmt.Println(err)
	}
	for _, route := range routes {
		if route["netmask"].(string) == "0.0.0.0" && route["network"].(string) == "0.0.0.0" {
			ip.IpAddress = net.ParseIP(route["gateway"].(string))
			return ip, nil
		}
	}
	return ip, nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	// Prompt for a username.
	fmt.Println("Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Prompt for a password (with hidden input).
	fmt.Println("Password: ")
	password, _ := term.ReadPassword(int(syscall.Stdin))
	// fmt.Println()

	// Prompt for a NetScaler.
	fmt.Println("NetScaler (Name or IP address): ")
	netscaler, _ := reader.ReadString('\n')
	netscaler = strings.TrimSpace(netscaler)

	// Prompt for Server IP address.
	fmt.Println("Server IP address: ")
	serverIP, _ := reader.ReadString('\n')
	serverIP = strings.TrimSpace(serverIP)

	// Parameters used for authentication.
	params := service.NitroParams{
		Url:      "https://" + netscaler,
		Username: username,
		Password: string(password),
	}

	// Initializes a client for connection and authentication to a NetScaler.
	client, err := service.NewNitroClientFromParams(params)
	if err != nil {
		fmt.Println(err)
	}

	// Retrieves an array of NetScaler IP addresses.
	ipAddresses, err := GetNetScalerResources(client, "nsip")
	if err != nil {
		fmt.Println(err)
	}

	// Generates NetScaler SNIPs into an IpAddress struct type.
	snips, err := BuildSnips(ipAddresses, "SNIP")
	if err != nil {
		fmt.Println(err)
	}

	// Retrieves an array of Vlan IDs.
	vlanIds, err := GetVlanIds(client, "vlan")
	if err != nil {
		fmt.Println(err)
	}

	// Retrieves an array of Vlan info as a struct type.
	vlanInfo, err := GetVlanInfo(client, vlanIds)
	if err != nil {
		fmt.Println(err)
	}

	// Binds Vlan information to their respective IpAddresses.
	bindIps := BindSnipWithVlan(snips, vlanInfo)

	// Validates if an IpAddress is a part of a specified network.
	var results []IpAddress
	for _, ip := range bindIps {
		parseIP := net.ParseIP(string(serverIP))
		if ip.Network.Contains(parseIP) {
			results = append(results, ip)
		}
	}

	// If no results are returned, the default route information will be used for communication.
	if len(results) != 0 {
		for _, ip := range results {
			if ip.Vlan.Channel != nil {
				fmt.Println("The server: " + string(serverIP) + " will interact with SNIP: " + ip.IpAddress.String() + " and it will use the " + ip.Vlan.Channel[0] + " interface and is on VLAN: " + ip.Vlan.Id)
			}
			if ip.Vlan.Interface != nil {
				fmt.Println("The server: " + string(serverIP) + " will interact with SNIP: " + ip.IpAddress.String() + " and it will use the " + ip.Vlan.Interface[0] + " interface and is on VLAN: " + ip.Vlan.Id)
			}
		}
	}

	// If results are returned, this information will be used for communication.
	if len(results) == 0 {
		gateway, err := DefaultRouteIPaddress(client, "route")
		if err != nil {
			fmt.Println(err)
		}
		for _, ip := range bindIps {
			if ip.Network.Contains(gateway.IpAddress) {
				if ip.Vlan.Channel != nil {
					fmt.Println("Default Route is being used to communicate with this server: " + string(serverIP) + " and will source from SNIP: " + ip.IpAddress.String() + ". It will use the " + ip.Vlan.Channel[0] + " interface and is on VLAN: " + ip.Vlan.Id)
				}
				if ip.Vlan.Interface != nil {
					fmt.Println("Default Route is being used to communicate with this server: " + string(serverIP) + " and will source from SNIP: " + ip.IpAddress.String() + ". It will use the " + ip.Vlan.Interface[0] + " interface and is on VLAN: " + ip.Vlan.Id)
				}
			}
		}
	}
}
