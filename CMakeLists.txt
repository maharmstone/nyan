cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(nyan VERSION 20240320)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

configure_file(src/config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

find_package(OpenSSL REQUIRED)

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

add_executable(makecat src/makecat.cpp
	src/cat.cpp
	src/authenticode.cpp
	src/sha1.cpp
	src/sha256.cpp)

target_link_libraries(makecat OpenSSL::Crypto)

if(NOT MSVC)
	target_compile_options(makecat PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
else()
	target_link_options(makecat PUBLIC /MANIFEST:NO)
endif()

# ----------------------------

add_executable(stampinf src/stampinf.cpp)

if(NOT MSVC)
	target_compile_options(stampinf PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
else()
	target_link_options(stampinf PUBLIC /MANIFEST:NO)
endif()

# ----------------------------

install(TARGETS authenticode DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS makecat DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS stampinf DESTINATION ${CMAKE_INSTALL_BINDIR})
