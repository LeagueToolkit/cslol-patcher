cmake_minimum_required(VERSION 3.20)

project(cslol-tools LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(cslol-dll SHARED src/cslol-api.h src/cslol-dll.c)

add_executable(cslol-inj src/cslol-inj.c)
target_link_libraries(cslol-inj PRIVATE cslol-dll)

