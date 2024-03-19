cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(nyan VERSION 20240318)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

configure_file(src/config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SRC_FILES
	src/nyan.cpp
	src/cat.cpp
	src/authenticode.cpp
	src/sha1.cpp
	src/sha256.cpp
)

add_executable(nyan ${SRC_FILES})

find_package(OpenSSL REQUIRED)

target_link_libraries(nyan OpenSSL::Crypto)

if(NOT MSVC)
	target_compile_options(nyan PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
else()
	target_link_options(nyan PUBLIC /MANIFEST:NO)
endif()

# ----------------------------

add_executable(authenticode src/calcauthenticode.cpp
	src/authenticode.cpp
	src/sha1.cpp
	src/sha256.cpp)

if(NOT MSVC)
	target_compile_options(authenticode PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
else()
	target_link_options(authenticode PUBLIC /MANIFEST:NO)
endif()

# ----------------------------

add_executable(makecat src/makecat.cpp)

if(NOT MSVC)
	target_compile_options(makecat PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
else()
	target_link_options(makecat PUBLIC /MANIFEST:NO)
endif()
