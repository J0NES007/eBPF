In the user-space, we create a map and insert an entry into it containing the port number

We attach an XDP program to a specific network interface

Parse the packets as they arrive and drop them if they are destined to the specified port. 
