cmake_minimum_required(VERSION 3.6)
project(SouyeInjector)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
set(SOURCE_FILES main.c)
add_executable(SouyeInjector ${SOURCE_FILES})