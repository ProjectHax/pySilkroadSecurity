pySilkroadSecurity
===

pySilkroadSecurity exposes Drew's SilkroadSecurity API to Python 3.2 and above. It does not implement the API in Python code.

Windows
---

Precompiled Boost.Python 1.82 and pySilkroadSecurity libs for Python 3.11.2 x64 are included for Windows in the `python` directory. You will need [vcredist x64](https://aka.ms/vs/17/release/vc_redist.x64.exe) if VS 2022 is not installed.

1. Download and install [Python 3.x x64](https://www.python.org/downloads/)
1. Download and extract [boost](https://www.boost.org/)
1. Open `x86 Native Tools Command Prompt for VS 2022`
1. Change to the extract boost directory
1. Run `bootstrap.bat`
1. Run `b2 -j8 --build-type=complete stage`

**Compiling**

1. `git clone https://github.com/ProjectHax/pySilkroadSecurity.git`
1. Open `pySilkroadSecurity.sln`
1. Edit the VC++ directories for boost and Python
1. Compile
1. Copy `boost_python311-vc143-mt-x64-1_82.dll` from `boost/stage/lib` to the Python script folder
1. Copy `x64/Release/pySilkroadSecurity.pyd` to your Python script folder

*nix
---

1. Install cmake, boost, python3 dev packages
1. `git clone https://github.com/ProjectHax/pySilkroadSecurity.git`
1. `cd src`
1. `mkdir build && cd build`
1. `cmake ..`
1. `make`

macOS
---

1. Install [Homebrew](https://brew.sh/)
1. `brew install python3 boost boost-python3 cmake`
1. Follow the `*nix` steps

Examples
---

**pySilkroadStats.py**

This small project shows you how the SilkroadSecurity API is to be used from Python. It will connect to iSRO and display the server list. This can be easily added to by adding a few lines to log into the servers and join the game world.

**pySilkroadProxy.py**

This project accepts connections on TCP port 15779 and will create a proxy between the Silkroad client and the Silkroad game servers. This will allow you to view all packets going to and from Silkroad. This project can also be easily modified to filter packets for a private server; although, I would recommend rewriting the network code to not use select() if you end up needing to handle more than 100 simultaneous connections.

Usage in Your Own Project
---

Copy pySilkroadSecurity.so and stream.py to your own project folder and import them like so:

```
from pySilkroadSecurity import SilkroadSecurity
from stream import *
```