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

#include "manape/pe.h"
#include "manape/overlay.h"

namespace mana
{

	// ----------------------------------------------------------------------------	
	Overlay::Overlay(pFile handle, boost::uint64_t file_size, boost::uint64_t overlayOffset) :		
		_file_handle(handle),
		_file_size(file_size),
		_pointer_to_raw_data(overlayOffset)
	{		
		_size_of_raw_data = _file_size - _pointer_to_raw_data;
	}

	// ----------------------------------------------------------------------------	
	shared_bytes Overlay::get_raw_data() const
	{
		auto res = boost::make_shared<std::vector<boost::uint8_t> >();

		if (_size_of_raw_data == 0)
		{
			PRINT_ERROR << "No overlay!" << std::endl;
			return res;
		}
		
		if (fseek(_file_handle.get(), _pointer_to_raw_data, SEEK_SET)) {
			PRINT_ERROR << "Cannot seek to overlay!" << std::endl;
			return res;
		}

		try {
			res->resize(_size_of_raw_data);
		}
		catch (const std::exception& e)
		{
			PRINT_ERROR << "Failed to allocate enough space for overlay! (" << e.what() << ")"
				<< DEBUG_INFO << std::endl;
			res->resize(0);
			return res;
		}

		if (_size_of_raw_data != fread(&(*res)[0], 1, _size_of_raw_data, _file_handle.get()))
		{
			PRINT_WARNING << "Raw bytes from overlay could not be obtained." << std::endl;
			res->resize(0);
		}

		return res;
	}

} // !namespace mana
