package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"log"
	"net"
    "unsafe"
	"os"
	"os/signal"
	"strconv"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)


func main() {
    var inputPort string
    var ifName string
	var processName string
	// Prompt the user to enter process name, network interface, and port. set defaults if user input is empty
	fmt.Print("Enter a port (press Enter for default value): ")
    fmt.Scanln(&inputPort)
    if inputPort == "" {
		inputPort = "5353"
	}
    fmt.Println(inputPort)
    fmt.Print("Enter network interface name (press Enter for default value): ")
    fmt.Scanln(&ifName)
    if ifName == "" {
        ifName = "eth0"
    }
    fmt.Println(ifName)
	fmt.Print("Enter process name (press Enter for default value): ")
    fmt.Scanln(&processName)
    if processName == "" {
		processName = "python"
	}
    fmt.Println(processName)
	port, err := strconv.Atoi(inputPort)
	if err != nil {
        log.Fatal("Error parsing input:", err)
	}

    
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs drop_packets_processObjects
    if err := loadDrop_packets_processObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() 

    processMapPath := "/sys/fs/bpf/process_map"
	if _, err := os.Stat(processMapPath); os.IsNotExist(err) {
        err = objs.ProcessMap.Pin("/sys/fs/bpf/process_map")
        if err != nil {
            log.Fatal("error pinning map", err)
        }
	}
    cstr := C.CString(processName)
    defer C.free(unsafe.Pointer(cstr))

    if err := objs.BpfPortMap.Update(uint32(port), cstr, 0); err != nil {
        log.Fatal("Updating port map:", err)
    }

    // Get interface by name
    iface, err := net.InterfaceByName(ifName)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifName, err)
    }

    // Attach drop_packets program to the network interface.
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
