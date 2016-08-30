/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

#include <unordered_map>

namespace plugin {

	struct HexCharStruct
	{
		unsigned char c;
		HexCharStruct(unsigned char _c) : c(_c) { }
	};

	inline std::ostream& operator<<(std::ostream& o, const HexCharStruct& hs)
	{
		return (o << std::hex << (int)hs.c);
	}

	inline HexCharStruct hex(unsigned char _c)
	{
		return HexCharStruct(_c);
	}

	struct DecCharStruct
	{
		unsigned char c;
		DecCharStruct(unsigned char _c) : c(_c) { }
	};

	inline std::ostream& operator<<(std::ostream& o, const DecCharStruct& hs)
	{
		return (o << std::dec << (int)hs.c);
	}

	inline DecCharStruct dec(unsigned char _c)
	{
		return DecCharStruct(_c);
	}

	typedef std::tuple<boost::uint8_t, boost::uint8_t> key_t;

	struct key_hash : public std::unary_function<key_t, std::size_t>
	{
		std::size_t operator()(const key_t& k) const
		{
			return boost::hash_value(k);
		}
	};

	struct key_equal : public std::binary_function<key_t, key_t, bool>
	{
		bool operator()(const key_t& v0, const key_t& v1) const
		{
			return std::get<0>(v0) == std::get<0>(v1) && std::get<1>(v0) == std::get<1>(v1);
		}
	};

	typedef std::unordered_map<key_t, boost::uint64_t, key_hash, key_equal> bigram_map_t;
	bigram_map_t bigram_map;
	

class NGramPlugin : public IPlugin
{
    int get_api_version() const override { return 1; }

    pString get_id() const override {
        return boost::make_shared<std::string>("ngrams");
    }

    pString get_description() const override {
        return boost::make_shared<std::string>("Extracts n-grams for the individual sections (currently 1 and 2-gram).");
    }

    pResult analyze(const mana::PE& pe) override
    {
        pResult res = create_result();
       
		mana::shared_sections sections = pe.get_sections();

		if (sections->size() == 0) {
			return res;
		}

		std::unordered_map<std::string, bigram_map_t> sectionBiGramMap;
		for (auto it = sections->begin(); it != sections->end(); ++it)
		{
			bigram_map_t sectionBiGram;

			auto section = *it;

			//TODO: Create 1-gram


			//Create n-grams
			auto rawbytes = *section.get()->get_raw_data();

			if (rawbytes.size()==0)
			{
				std::stringstream ss;
				ss << "Could not access raw bytes for: " << *section.get()->get_name();
				PRINT_ERROR << ss.str() << '\n';
				continue;
			}
			auto currentByte = std::begin(rawbytes);

			while (true) {
				auto nextByte = std::next(currentByte);

				if (nextByte == std::end(rawbytes)) {
					break;
				}

				auto bigram = std::make_tuple(*currentByte, *nextByte);

				auto got = sectionBiGram.find(bigram);

				if (got == sectionBiGram.end())
				{
					sectionBiGram.insert(std::make_pair(bigram, 1));
				}
				else
				{
					sectionBiGram[bigram]++;
				}

				currentByte = nextByte;
			}

			sectionBiGramMap.insert(std::make_pair(*section.get()->get_name(), sectionBiGram));
		}

		boost::filesystem::path p(*pe.get_path());

		for (auto& s : sectionBiGramMap) { 

			std::stringstream ss;

			ss << "bigram_" << s.first << ".csv";

			std::ofstream bigram(ss.str());

			bigram << "FirstByte_hex,SecondByte_hex,FirstByte_dec,SecondByte_dec,Count" << std::endl;

			bigram_map_t bimap = s.second;

			for (auto& entry : bimap) {

				auto tup = entry.first;
				auto count = entry.second;

				bigram << hex(std::get<0>(tup)) << "," << hex(std::get<1>(tup)) << "," << dec(std::get<0>(tup)) << "," << dec(std::get<1>(tup)) << "," << std::dec << count << "\n";
			}

			bigram.close();

			std::stringstream ssInfo;

			ssInfo << "n-grams calculated and saved to: "  << ss.str() ;

			res->add_information(s.first, ssInfo.str());			
		}

        return res;
    }
};

AutoRegister<NGramPlugin> auto_register_bigrams;

} // !namespace plugin
