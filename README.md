pySilkroadSecurity
==================

pySilkroadSecurity exposes Drew's SilkroadSecurity API to Python 3.2 and above. It does not implement the API in Python code.

Requirements
------------

1. Linux or Mac OSX
2. Python 3.2+
3. boost
4. git
5. cmake

Debian 7
--------

1. apt-get update && apt-get upgrade
2. apt-get install build-essential python3.2 python3.2-dev libboost-all-dev git cmake

Ubuntu 14.04
------------

1. apt-get update && apt-get upgrade
2. apt-get install build-essential python3-dev libboost-dev git cmake

Fedora 20
---------

1. yum update
2. yum install gcc-c++ boost boost-devel boost-python3 boost-python3-devel python3-devel cmake

Arch
----

Make sure you have `base-devel` already installed.

1. pacman -Syu
2. pacman -S python3 boost git cmake

RaspberryPi (Raspbian)
----------------------

1. Follow the Debian 7 guide.
2. Use a single thread to compile

Mac OSX 10.11
-------------

This will be a complete guide since the steps are quite different for compiling. You will need to update the Python version in the cmake string when 3.5+ is released.

1. `brew install boost`
2. `brew install python3`
3. `brew install boost-python --with-python3 --c++11`
4. `git clone https://github.com/ProjectHax/pySilkroadSecurity.git`
5. `cd pySilkroadSecurity/`
6. ```cmake -DPYTHON_INCLUDE_DIR=`python3-config --prefix`/include/python3.5m -DPYTHON_LIBRARY=`python3-config --prefix`/lib/libpython3.5m.dylib -DPython_FRAMEWORKS=`python3-config --prefix````
7. `make -j4`
8. `cd python/`
9. `python3 pySilkroadStats.py`

Compiling
=========

1. `git clone https://github.com/ProjectHax/pySilkroadSecurity.git`
2. `cd pySilkroadSecurity/`
3. `cmake .`
4. `make -j4`
5. `cd python/`
6. `python3 pySilkroadStats.py`

Examples
========

**pySilkroadStats.py**

This small project shows you how the SilkroadSecurity API is to be used from Python. It will connect to iSRO and display the server list. This can be easily added to by adding a few lines to log into the servers and join the game world.

**pySilkroadProxy.py**

This project accepts connections on TCP port 15779 and will create a proxy between the Silkroad client and the Silkroad game servers. This will allow you to view all packets going to and from Silkroad. This project can also be easily modified to filter packets for a private server; although, I would recommend rewriting the network code to not use select() if you end up needing to handle more than 100 simultaneous connections.

Usage in Your Own Project
-------------------------

Copy pySilkroadSecurity.so and stream.py to your own project folder and import them like so:

```
from pySilkroadSecurity import SilkroadSecurity
from stream import *
```

Warnings
========

* iSRO/SilkroadR client will crash after loading the game world if HackShield is disabled using edxSilkroadLoader5 (it's missing one client patch that was added recently)
* Stream classes have not been extensively tested/used and may have bugs
* With some modifications it can work under Python 2.7.X (it was originally written for 2.7.X)
