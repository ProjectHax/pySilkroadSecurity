cmake_minimum_required(VERSION 3.2)

project(pySilkroadSecurity)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/../../python/)

set(CMAKE_C_FLAGS "-std=c++17 -O3 -fPIC")
set(CMAKE_CXX__FLAGS "-std=c++17 -O3 -fPIC")

find_package(Python3 COMPONENTS Interpreter Development)
find_package(Boost 1.70 COMPONENTS python REQUIRED)

include_directories(${Python3_INCLUDE_DIRS})
link_directories(${Python3_LIBRARIES})

set(HEADER_FILES pch.h)
set(SOURCE_FILES main.cpp security/blowfish.cpp security/stream_utility.cpp security/silkroad_security.cpp)
include_directories(. security)

add_library(pySilkroadSecurity SHARED ${SOURCE_FILES})
target_link_libraries(pySilkroadSecurity ${Boost_LIBRARIES} ${Python3_LIBRARIES})

set_target_properties(pySilkroadSecurity PROPERTIES PREFIX "")

if (APPLE)
    set_property(TARGET pySilkroadSecurity PROPERTY OUTPUT_NAME "pySilkroadSecurity.so")
    set_property(TARGET pySilkroadSecurity PROPERTY SUFFIX "")
endif()