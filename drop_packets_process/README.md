We create an xdp program to listen on a specified interface. 
We create two maps:

1. bpf_port_map - which contains the port to process name mapping that we set from userspace. This is the port and process that we wish to monitor
2. process_map - which contains the port and process mappings as and when a process is spun up. We pin this map in the bpf filesystem
   
We configure the port and process to monitor via a map called "bpf_port_map" from the userspace
Parse the packets as they arrive and lookup the destination port number specified in the packet in the "bpf_port_map". If the port look up succeeds, we get the process name. (Lets call this expected_process_name)
Look up the destination port number specified in the packet in the "process_map" to see if the process is actually running. (Lets call this actual_process_name)
If expected_process_name == actual_process_name then we allow packet, else drop it. 
We allow all other packets by default. 



Create a file called server.go to simulate running process. This takes process name and port as input parameters and creates a server listening on a specified port. 
We then update the process name and port to the pinned map "process_map"
When we exit the server function, it deletes the entry from the pinned map




Alternate approach:

We can also create a function using a Kprobe (inet_bind) which executes as and when a process is spun up to update the pinned "process_map" with the port_number to process mapping. 
