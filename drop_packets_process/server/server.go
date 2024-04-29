package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"log"
    	"unsafe"
	"strconv"
    	"net"
    	"os"
	"os/signal"
	"github.com/cilium/ebpf"
)

func handleConnection(conn net.Conn) {
    defer conn.Close()
    fmt.Println("handling connection")
}

func main() {

    var inputPort string
	var processName string
	// Prompt the user to enter process name, network interface, and port. set defaults if user input is empty
	fmt.Print("Enter a port (press Enter for default value): ")
    fmt.Scanln(&inputPort)
    if inputPort == "" {
		inputPort = "1900"
	}
    fmt.Println(inputPort)
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

    // Load the pinned map
    processMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/process_map", &ebpf.LoadPinOptions{})
    if err != nil {
        log.Fatal("Loading pinned process map:", err)
    }
    cstr := C.CString(processName)
    defer C.free(unsafe.Pointer(cstr))
    // Update process name and port to map
    processMap.Update(uint32(port), cstr, 0)


    // Listen for incoming connections
    listener, err := net.Listen("tcp", ":"+inputPort)
    if err != nil {
        fmt.Println("Error listening:", err.Error())
        return
    }
    defer listener.Close()
    fmt.Printf("Server listening on port %s...", inputPort)

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt)
   
    // Seperate go routine to capture interrupt and delete port mapping in map
    go func() {
        <-stop
        processMap.Delete(uint32(port))
        os.Exit(0)
    }()

    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Println("Error accepting connection:", err.Error())
            return
        }
        fmt.Println("Connection accepted from:", conn.RemoteAddr())
        go handleConnection(conn)
    }
}
