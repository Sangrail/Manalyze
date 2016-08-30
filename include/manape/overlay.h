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

#pragma once

#include <stdio.h>
#include <boost/make_shared.hpp>
#include <boost/cstdint.hpp>
#include <boost/system/api_config.hpp>
#include <vector>

#include "manape/pe_structs.h"
#include "manape/utils.h"
#include "manape/color.h"
#include "manape/escape.h"

#if defined BOOST_WINDOWS_API
	#ifdef MANAPE_EXPORT
		#define DECLSPEC    __declspec(dllexport)
	#else
		#define DECLSPEC    __declspec(dllimport)
	#endif
#else
	#define DECLSPEC
#endif

namespace mana {

typedef boost::shared_ptr<std::string> pString;
typedef boost::shared_ptr<const std::vector<boost::uint8_t> > shared_bytes;
typedef boost::shared_ptr<FILE> pFile;

class Overlay
{

public:
	/**
	 *	@brief	Create a Overlay object from a raw image_section_header structure.
	 *
	 *	@param	const image_section_header& header The structure on which the section will be based.
	 *	@param	pFile handle An open handle to the executable on the filesystem.
	 *	@param	const std::vector<pString>& coff_string_table An optional COFF string table, in case section
	 *			names are located in it.
	 */
	DECLSPEC Overlay(pFile handle, boost::uint64_t file_size, boost::uint64_t overlayOffse);

	DECLSPEC virtual ~Overlay() {}

	/**
	 *	@brief	Returns the raw bytes of the overlay.
	 *
	 *	Note that calling this function for PEs which have a giant overlay may end up
	 *	eating a lot of memory.
	 *
	 *	@return	A shared vector containing the raw bytes of the section. If an error occurs, the vector
	 *			will be empty.
	 */
	DECLSPEC shared_bytes get_raw_data() const;
	DECLSPEC boost::uint64_t get_size_of_raw_data()			const { return _size_of_raw_data; }
	DECLSPEC boost::uint64_t get_pointer_to_raw_data()		const { return _pointer_to_raw_data; }
	DECLSPEC double			 get_entropy()					const { return utils::shannon_entropy(*get_raw_data()); }

private:

	boost::uint64_t _size_of_raw_data;
	boost::uint64_t _pointer_to_raw_data;

	// Handle to the file on the filesystem.
	pFile			_file_handle;
	// Size of the file. This is used to reject sections with a wrong size.
	boost::uint64_t	_file_size;
};
} // !namespace sg
