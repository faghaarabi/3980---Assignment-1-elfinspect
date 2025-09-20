cmake_minimum_required(VERSION 3.26)  # 4.0 is too new, CLion/CMake may complain
project(3980_Assignment1 C)

set(CMAKE_C_STANDARD 17)

# point to the correct file path
add_executable(elfinspect src/elfinspect.c)
