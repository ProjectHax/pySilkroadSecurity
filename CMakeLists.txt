cmake_minimum_required(VERSION 2.8)

project(pySilkroadSecurity)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/python)

set(CMAKE_C_FLAGS "-O3 -fPIC")
set(CMAKE_CXX__FLAGS "-O3 -fPIC")

find_package(PythonInterp 3 REQUIRED)
find_package(PythonLibs 3 REQUIRED)
find_package(Boost COMPONENTS random python3 REQUIRED)

include_directories(${PYTHON_INCLUDE_DIRS})
link_directories(${PYTHON_LIBRARIES})

add_library(pySilkroadSecurity SHARED src/main.cpp src/SilkroadSecurity/blowfish src/SilkroadSecurity/silkroad_security src/SilkroadSecurity/stream_utility)
target_link_libraries(pySilkroadSecurity ${Boost_LIBRARIES} ${PYTHON_LIBRARIES})
set_target_properties(pySilkroadSecurity PROPERTIES PREFIX "")