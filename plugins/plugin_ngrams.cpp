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

	typedef std::unordered_map<boost::uint8_t, boost::uint64_t> unigram_map_t;
	unigram_map_t unigram_map;
	

class NGramPlugin : public IPlugin
{
    int get_api_version() const override { return 1; }

    pString get_id() const override {
        return boost::make_shared<std::string>("ngrams");
    }

    pString get_description() const override {
        return boost::make_shared<std::string>("Extracts n-grams for the individual sections (currently 1 and 2-gram).");
    }
	
	bigram_map_t GenerateBiGram(mana::shared_bytes rawbytes)
	{
		bigram_map_t biGram;

		if ((*rawbytes).size() == 0)
		{
			std::stringstream ss;
			ss << "Could not access raw bytes";
			PRINT_ERROR << ss.str() << '\n';
			return biGram;
		}

		auto currentByte = std::begin(*rawbytes);

		while (true) {
			auto nextByte = std::next(currentByte);

			if (nextByte == std::end(*rawbytes)) {
				break;
			}

			auto bigram = std::make_tuple(*currentByte, *nextByte);

			auto got = biGram.find(bigram);

			if (got == biGram.end())
			{
				biGram.insert(std::make_pair(bigram, 1));
			}
			else
			{
				biGram[bigram]++;
			}

			currentByte = nextByte;
		}

		return biGram;
	}

	unigram_map_t GenerateUniGram(mana::shared_bytes rawbytes)
	{
		unigram_map_t UniGram;

		if ((*rawbytes).size() == 0)
		{
			std::stringstream ss;
			ss << "Could not access raw bytes";
			PRINT_ERROR << ss.str() << '\n';
			return UniGram;
		}

		auto currentByte = std::begin(*rawbytes);

		while (true) {
			auto nextByte = std::next(currentByte);

			if (nextByte == std::end(*rawbytes)) {
				break;
			}

			auto got = UniGram.find(*currentByte);

			if (got == UniGram.end())
			{
				UniGram.insert(std::make_pair(*currentByte, 1));
			}
			else
			{
				UniGram[*currentByte]++;
			}

			currentByte = nextByte;
		}

		return UniGram;
	}

	void CreateUnigramFile(std::string filename, unigram_map_t unigramMap)
	{
		if (unigramMap.size() == 0)
			return;

		std::ofstream unigram(filename);

		unigram << "Byte_hex,First_dec,Count" << std::endl;

		for (auto& entry : unigramMap) {

			auto b = entry.first;
			auto count = entry.second;

			unigram << hex(b) << "," << dec(b) << "," << std::dec << count << "\n";
		}

		unigram.close();
	}

	void CreateBigramFile(std::string filename, bigram_map_t bigramMap)
	{
		if (bigramMap.size() == 0)
			return;

		std::ofstream bigram(filename);

		bigram << "FirstByte_hex,SecondByte_hex,FirstByte_dec,SecondByte_dec,Count" << std::endl;

		for (auto& entry : bigramMap) {

			auto tup = entry.first;
			auto count = entry.second;

			bigram << hex(std::get<0>(tup)) << "," << hex(std::get<1>(tup)) << "," << dec(std::get<0>(tup)) << "," << dec(std::get<1>(tup)) << "," << std::dec << count << "\n";
		}

		bigram.close();
	}

    pResult analyze(const mana::PE& pe) override
    {
		auto outputDir = _config->at("outputfolder");

        pResult res = create_result();
       
		mana::shared_sections sections = pe.get_sections();

		if (sections->size() == 0) {
			return res;
		}

		std::unordered_map<std::string, bigram_map_t> sectionBiGramMap;

		std::unordered_map<std::string, unigram_map_t> sectionUniGramMap;

		for (auto it = sections->begin(); it != sections->end(); ++it)
		{
			auto section = *it;

			//Create 1-gram
			auto sectionUniGram = GenerateUniGram(section.get()->get_raw_data());
			sectionUniGramMap.insert(std::make_pair(*section.get()->get_name(), sectionUniGram));

			//Create 2-grams			
			auto sectionBiGram = GenerateBiGram(section.get()->get_raw_data());
			
			sectionBiGramMap.insert(std::make_pair(*section.get()->get_name(), sectionBiGram));
		}

		for (auto& s : sectionUniGramMap) {

			std::stringstream ss;

			ss << outputDir << "\\unigram_" << s.first << ".csv";

			std::ofstream unigram(ss.str());

			CreateUnigramFile(ss.str(), s.second);

			std::stringstream ssInfo;

			ssInfo << "uni-grams calculated and saved to: " << ss.str();

			res->add_information(s.first, ssInfo.str());
		}

		for (auto& s : sectionBiGramMap) { 

			std::stringstream ss;

			ss << outputDir << "\\bigram_" << s.first << ".csv";

			CreateBigramFile(ss.str(), s.second);
			
			std::stringstream ssInfo;

			ssInfo << "bi-grams calculated and saved to: "  << ss.str() ;

			res->add_information(s.first, ssInfo.str());			
		}

		auto overlayRawbytes = pe.get_overlay().get()->get_raw_data();

		auto overlayUniGram = GenerateUniGram(overlayRawbytes);			
		auto overlayBiGram = GenerateBiGram(overlayRawbytes);		

		std::stringstream ss2;
		ss2 << outputDir << "\\unigram_Overlay.csv";
		CreateUnigramFile(ss2.str(), overlayUniGram);

		std::stringstream ss1;
		ss1 << outputDir << "\\bigram_Overlay.csv";
		CreateBigramFile(ss1.str(), overlayBiGram);
	
        return res;
    }
};

AutoRegister<NGramPlugin> auto_register_bigrams;

} // !namespace plugin
