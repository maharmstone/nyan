cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(nyan)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(SRC_FILES
	src/nyan.cpp)

add_executable(nyan ${SRC_FILES})

add_definitions(-D_WIN32_WINNT=0x0600 -DNOMINMAX)

find_package(OpenSSL REQUIRED)

target_link_libraries(nyan OpenSSL::Crypto)

if(NOT MSVC)
	target_compile_options(nyan PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
else()
	target_link_options(nyan PUBLIC /MANIFEST:NO)
endif()
