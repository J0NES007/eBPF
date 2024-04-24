package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
    "strconv"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

    var inputPort string
    var ifName string
	// Prompt the user to enter port number and network interface and set defaults if user input is empty
	fmt.Print("Enter a port (press Enter for default value): ")
    fmt.Scanln(&inputPort)
    if inputPort == "" {
		inputPort = "4040"
	}
    fmt.Println(inputPort)
    fmt.Print("Enter network interface name (press Enter for default value): ")
    fmt.Scanln(&ifName)
    if ifName == "" {
        ifName = "wlp2s0b1"
    }
    fmt.Println(ifName)
	port, err := strconv.Atoi(inputPort)
	if err != nil {
        log.Fatal("Error parsing input:", err)
	}

    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs drop_packetsObjects 
    if err := loadDrop_packetsObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() 

    // Update the port number in the eBPF map.
    portNumber := uint32(port)
    if err := objs.BpfPortMap.Update(uint32(0), &portNumber, 0); err != nil {
        log.Fatal("Updating port map:", err)
    }

    iface, err := net.InterfaceByName(ifName)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifName, err)
    }

    // Attach drop_packets to the network interface.
    link, err := link.AttachXDP(link.XDPOptions{ 
        Program:   objs.DropPackets,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatal("Attaching XDP:", err)
    }
    defer link.Close() 

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt)
    log.Printf("Recieving incoming packets on %s..", ifName)
    fmt.Println("Press Ctrl+C to stop...")

    // Wait for a signal
    <-stop
    
    fmt.Println("Stopping...")
}
