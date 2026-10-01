# Copyright (c) 2025 VillageSQL Contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.18)
project(vsql_uuid_extension)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Extension name
set(EXTENSION_NAME "vsql_uuid")

# Find VillageSQL SDK
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(VillageSQL REQUIRED)

message(STATUS "VillageSQL SDK found at: ${VillageSQL_PREFIX}")
message(STATUS "VillageSQL include dir: ${VillageSQL_INCLUDE_DIR}")

# Find OpenSSL (required for UUID generation)
#
# On macOS, Homebrew's OpenSSL is keg-only and FindOpenSSL resolves it to a
# versioned Cellar path (e.g. Cellar/openssl@3/3.6.0). That path is removed
# when Homebrew upgrades OpenSSL, breaking existing build directories. Prefer
# the stable opt/ symlink and drop cached paths that no longer exist.
if(APPLE AND NOT OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
  find_program(BREW_EXECUTABLE brew)
  if(BREW_EXECUTABLE)
    execute_process(
      COMMAND ${BREW_EXECUTABLE} --prefix openssl@3
      OUTPUT_VARIABLE _brew_openssl_prefix
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE _brew_result
      ERROR_QUIET
    )
    if(_brew_result EQUAL 0 AND EXISTS "${_brew_openssl_prefix}")
      set(OPENSSL_ROOT_DIR "${_brew_openssl_prefix}")
    endif()
    unset(_brew_openssl_prefix)
    unset(_brew_result)
  endif()
endif()
foreach(_var OPENSSL_INCLUDE_DIR OPENSSL_CRYPTO_LIBRARY OPENSSL_SSL_LIBRARY)
  if(${_var} AND NOT EXISTS "${${_var}}")
    message(STATUS "Discarding stale cached ${_var}: ${${_var}}")
    unset(${_var} CACHE)
  endif()
endforeach()

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")

# Create the UUID shared library
add_library(uuid SHARED
    src/uuid.cc
)

# Include directories
target_include_directories(uuid PRIVATE
    ${VillageSQLExtensionFramework_INCLUDE_DIR}
)

# Link OpenSSL (only libcrypto is used)
target_link_libraries(uuid PRIVATE OpenSSL::Crypto)

# Create the VEB package
VEF_CREATE_VEB(
    NAME ${EXTENSION_NAME}
    LIBRARY_TARGET uuid
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
)
