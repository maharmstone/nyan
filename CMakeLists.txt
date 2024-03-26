cmake_minimum_required(VERSION 3.18)

project(nyan
	VERSION 20240320
	DESCRIPTION "CAT and INF file utilities"
	LANGUAGES CXX
)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(GNU_CXXFLAGS -Wall -Wextra -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wconversion)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13")
		# No std::format() in libstdc++ in gcc-12 or older.
		message(FATAL_ERROR "GCC version 13 or newer is required")
	endif()

	# With Clang, -Wcast-function-type is triggered by the OpenSSL headers.
	# Make this warning GCC-only for now.
	set(GNU_CXXFLAGS ${GNU_CXXFLAGS} -Wcast-function-type)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "14")
		# No std::format() in libc++ in clang-13 or older.
		message(FATAL_ERROR "Clang version 14 or newer is required")
	endif()

	if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17")
		# Required for std::format() with older Clang versions.
		set(GNU_CXXFLAGS -fexperimental-library ${GNU_CXXFLAGS})
		set(GNU_LDFLAGS -fexperimental-library)
	endif()

	set(GNU_CXXFLAGS --stdlib=libc++ ${GNU_CXXFLAGS})
	set(GNU_LDFLAGS --stdlib=libc++ ${GNU_LDFLAGS})
endif()

configure_file(src/config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

find_package(OpenSSL REQUIRED)

add_executable(authenticode src/calcauthenticode.cpp
	src/authenticode.cpp
	src/sha1.cpp
	src/sha256.cpp)

if(NOT MSVC)
	target_compile_options(authenticode PUBLIC ${GNU_CXXFLAGS})
	target_link_options(authenticode PUBLIC ${GNU_LDFLAGS})
else()
	target_link_options(authenticode PUBLIC /MANIFEST:NO)
endif()

# ----------------------------

add_executable(makecat src/makecat.cpp
	src/cat.cpp
	src/authenticode.cpp
	src/sha1.cpp
	src/sha256.cpp)

target_link_libraries(makecat OpenSSL::Crypto)

if(NOT MSVC)
	target_compile_options(makecat PUBLIC ${GNU_CXXFLAGS})
	target_link_options(makecat PUBLIC ${GNU_LDFLAGS})
else()
	target_link_options(makecat PUBLIC /MANIFEST:NO)
endif()

# ----------------------------

add_executable(stampinf src/stampinf.cpp)

if(NOT MSVC)
	target_compile_options(stampinf PUBLIC ${GNU_CXXFLAGS})
	target_link_options(stampinf PUBLIC ${GNU_LDFLAGS})
else()
	target_link_options(stampinf PUBLIC /MANIFEST:NO)
endif()

# ----------------------------

install(TARGETS authenticode DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS makecat DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS stampinf DESTINATION ${CMAKE_INSTALL_BINDIR})
