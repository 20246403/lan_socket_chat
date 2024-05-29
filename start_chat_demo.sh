sudo ip addr add 192.168.20.222/24 dev cvd-wtap-01
sudo ip addr add 192.168.20.230/24 dev cvd-wtap-02
sudo python lanChat.py cvd-wtap-01 &
sudo python lanChat.py cvd-wtap-02 &
