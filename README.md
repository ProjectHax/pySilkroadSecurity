pySilkroadSecurity
==================
pySilkroadSecurity exposes Drew's SilkroadSecurity API to Python 3.2 and above. It does not implement the API in Python code.

Requirements
------------
1. Linux
2. Python 3.2+
3. boost

Debian 7
--------
1. apt-get update && apt-get upgrade
2. apt-get install build-essential python3.2 python3.2-dev libboost-all-dev git
3. git clone https://github.com/ProjectHax/pySilkroadSecurity.git
4. cd pySilkroadSecurity/src/
5. make -j4 && make install && make clean
6. cd ../python/
7. python3.2 pySilkroadStats.py

Fedora 20
---------
1. yum update
2. yum install gcc-c++ boost boost-devel boost-python3 boost-python3-devel python3-devel
3. git clone https://github.com/ProjectHax/pySilkroadSecurity.git
4. cd pySilkroadSecurity/src/
5. make -j4 && make install && make clean
6. cd ../python/
7. python3.3 pySilkroadStats.py

Arch
----

Make sure you have `base-devel` already installed.

1. pacman -Syu
2. pacman -S python3 boost git
3. git clone https://github.com/ProjectHax/pySilkroadSecurity.git
4. cd pySilkroadSecurity/src/
5. make -j4 && make install && make clean
6. cd ../python/
7. python pySilkroadStats.py

RaspberryPi (Raspbian)
----------------------
1. Follow the Debian 7 guide but use a single thread to compile instead of 4.

Installation
------------
`make install` will copy the compiled library to the python folder so you can run the examples more easily.

Examples
--------
**pySilkroadStats.py**

This small project shows you how the SilkroadSecurity API is to be used from Python. It will connect to iSRO and display the server list. This can be easily added to by adding a few lines to log into the servers and join the game world.

**pySilkroadProxy.py**

This project accepts connections on TCP port 15779 and will create a proxy between the Silkroad client and the Silkroad game servers. This will allow you to view all packets going to and from Silkroad. This project can also be easily modified to filter packets for a private server; although, I would recommend rewriting the network code to not use select() if you end up needing to handle more than 100 simultaneous connections.

Usage in Your Own Project
-------------------------
Copy pySilkroadSecurity.so and stream.py to your own project folder and import them like so:

`from pySilkroadSecurity import SilkroadSecurity`

`from stream import *`

Warnings
--------
* iSRO/SilkroadR client will crash after loading the game world if HackShield is disabled using edxSilkroadLoader5 (it's missing one client patch that was added recently)
* Stream classes have not been extensively tested/used and may have bugs
* With some modifications it can work under Python 2.7.X (it was originally written for 2.7.X)