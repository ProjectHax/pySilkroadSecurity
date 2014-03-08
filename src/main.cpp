#include <stdio.h>
#include <iostream>

#ifndef NO_BOOST
	#include <boost/python/init.hpp>
	#include <boost/python.hpp>
	#include <boost/python/list.hpp>
	#include <boost/python/object.hpp>
	#include <boost/python/dict.hpp>
	#include <boost/foreach.hpp>
#else
	#error "Boost is required for pySilkroadSecurity to compile successfully"
	#error "https://github.com/ProjectHax/pySilkroadSecurity"
#endif

#include "SilkroadSecurity/silkroad_security.h"
#include "SilkroadSecurity/stream_utility.h"

class SilkroadSecurityPIMPL
{
	SilkroadSecurity sec;

public:

	SilkroadSecurityPIMPL()
	{
	}

	~SilkroadSecurityPIMPL()
	{
	}

	void GenerateHandshake(bool blowfish = true, bool security_bytes = true, bool handshake = true)
	{
		sec.GenerateHandshake(blowfish, security_bytes, handshake);
	}

	void ChangeIdentity(const std::string & name, uint8_t flag)
	{
		sec.ChangeIdentity(name, flag);
	}

	void Recv(boost::python::list data)
	{
		std::vector<uint8_t> converted;

		size_t size = boost::python::len(data);
		converted.resize(size);

		for(size_t x = 0; x < size; ++x)
			converted[x] = boost::python::extract<uint8_t>(data[x]);

		sec.Recv(converted);
	}

	void Recv(std::string data)
	{
		sec.Recv((const uint8_t*)&data[0], data.size());
	}

	boost::python::object GetPacketToRecv()
	{
		boost::python::list result;

		std::list<PacketContainer> packets = sec.GetPacketToRecv();
		BOOST_FOREACH(PacketContainer & container, packets)
		{
			boost::python::dict processed;
			processed["opcode"] = container.opcode;
			processed["encrypted"] = container.encrypted;
			processed["massive"] = container.massive;

			const std::vector<uint8_t> & temp = container.data.GetStreamVector();
			boost::python::list converted;
			BOOST_FOREACH(const uint8_t & x, temp)
			{
				converted.append(x);
			}

			processed["data"] = converted;
			result.append(processed);
		}

		return packets.empty() ? boost::python::object() : result;
	}

	void Send(uint16_t opcode, boost::python::list data, bool encrypted = false, bool massive = false)
	{
		std::vector<uint8_t> converted;
		size_t size = boost::python::len(data);
		converted.resize(size);

		for(size_t x = 0; x < size; ++x)
			converted[x] = boost::python::extract<uint8_t>(data[x]);

		sec.Send(opcode, (const uint8_t*)&converted[0], size, encrypted, massive);
	}

	void Send(uint16_t opcode, std::string data, bool encrypted = false, bool massive = false)
	{
		sec.Send(opcode, (const uint8_t*)&data[0], data.size(), encrypted, massive);
	}

	boost::python::object GetPacketToSend()
	{
		boost::python::list result;
		std::list<std::vector<uint8_t> > packets = sec.GetPacketToSend();

		BOOST_FOREACH(std::vector<uint8_t> & p, packets)
		{
			boost::python::list converted;
			BOOST_FOREACH(const uint8_t & x, p)
			{
				converted.append(x);
			}
			result.append(converted);
		}

		return packets.empty() ? boost::python::object() : result;
	}

	void AddEncryptedOpcode(uint16_t opcode)
	{
		sec.AddEncryptedOpcode(opcode);
	}
};

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(Recv, SilkroadSecurityPIMPL::Recv, 1, 1)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(Send, SilkroadSecurityPIMPL::Send, 2, 4)

BOOST_PYTHON_MODULE(pySilkroadSecurity)
{
    using namespace boost::python;

	class_<SilkroadSecurityPIMPL>("SilkroadSecurity", init<>())
    	.def("GenerateHandshake", &SilkroadSecurityPIMPL::GenerateHandshake)
    	.def("ChangeIdentity", &SilkroadSecurityPIMPL::ChangeIdentity)

    	.def("Recv", static_cast<void(SilkroadSecurityPIMPL::*) (boost::python::list)>
            (&SilkroadSecurityPIMPL::Recv), Recv())
    	.def("Recv", static_cast<void(SilkroadSecurityPIMPL::*) (std::string)>
            (&SilkroadSecurityPIMPL::Recv), Recv())

    	.def("Send", static_cast<void(SilkroadSecurityPIMPL::*) (uint16_t, boost::python::list, bool, bool)>
            (&SilkroadSecurityPIMPL::Send), Send())
    	.def("Send", static_cast<void(SilkroadSecurityPIMPL::*) (uint16_t, std::string, bool, bool)>
            (&SilkroadSecurityPIMPL::Send), Send())

    	.def("GetPacketToSend", &SilkroadSecurityPIMPL::GetPacketToSend)
    	.def("GetPacketToRecv", &SilkroadSecurityPIMPL::GetPacketToRecv)
    	.def("AddEncryptedOpcode", &SilkroadSecurityPIMPL::AddEncryptedOpcode)
    ;
}