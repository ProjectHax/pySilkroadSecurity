#pragma once

#ifndef NO_BOOST
	#include <boost/python/init.hpp>
	#include <boost/python.hpp>
	#include <boost/python/list.hpp>
	#include <boost/python/object.hpp>
	#include <boost/python/dict.hpp>
#else
	#error "Boost is required for pySilkroadSecurity to compile successfully"
	#error "https://github.com/ProjectHax/pySilkroadSecurity"
#endif

#include <stdint.h>
#include <list>
#include <exception>
#include <sstream>
#include <set>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <random>

#include "security/blowfish.h"
#include "security/stream_utility.h"
#include "security/silkroad_security.h"