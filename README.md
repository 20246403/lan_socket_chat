# Simple LAN Chat

For the demo select two network interfaces to run within same subnet. Currently used are:\
1- cvd-wtap-01\
2- cvd-wtap-02\
Run demo:
```
$ ./start_chat_demo.sh
```

To run app to listen to all interfaces change the following
```
# From
server_socket.bind((self.local_ip, PORT))
# To
server_socket.bind(('0.0.0.0', PORT))
```

Run Chat
```
$ sudo python lanChat.py <interface_name>
```
