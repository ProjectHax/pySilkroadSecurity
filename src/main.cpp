#include "pch.h"

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

	void ChangeIdentity(const std::string& name, uint8_t flag)
	{
		sec.ChangeIdentity(name, flag);
	}

	void Recv(boost::python::list data)
	{
		std::vector<uint8_t> converted;

		const size_t size = boost::python::len(data);
		converted.resize(size);

		for (size_t x = 0; x < size; ++x)
			converted[x] = boost::python::extract<uint8_t>(data[x]);

		sec.Recv(converted);
	}

	void Recv(std::string data)
	{
		sec.Recv(reinterpret_cast<const uint8_t*>(&data[0]), static_cast<int>(data.size()));
	}

	boost::python::object GetPacketToRecv()
	{
		boost::python::list result;

		auto packets = sec.GetPacketToRecv();
		for (auto&& container : packets)
		{
			boost::python::dict processed;
			processed["opcode"] = container.opcode;
			processed["encrypted"] = container.encrypted;
			processed["massive"] = container.massive;

			auto temp = container.data.GetStreamVector();
			boost::python::list converted;
			for (auto&& x : temp)
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
		const size_t size = boost::python::len(data);
		converted.resize(size);

		for (size_t x = 0; x < size; ++x)
			converted[x] = boost::python::extract<uint8_t>(data[x]);

		sec.Send(opcode, reinterpret_cast<const uint8_t*>(&converted[0]), static_cast<int>(size), encrypted, massive);
	}

	void Send(uint16_t opcode, std::string data, bool encrypted = false, bool massive = false)
	{
		sec.Send(opcode, reinterpret_cast<const uint8_t*>(&data[0]), static_cast<int>(data.size()), encrypted, massive);
	}

	boost::python::object GetPacketToSend()
	{
		boost::python::list result;
		auto packets = sec.GetPacketToSend();

		for (auto&& p : packets)
		{
			boost::python::list converted;
			for(auto&& x : p)
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