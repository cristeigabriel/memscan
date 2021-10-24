cmake_minimum_required(VERSION 3.21)
project(memscan)

# verify platform
if (NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
  message(FATAL_ERROR "${PROJECT_NAME}: Your platform is currently not supported.")
endif()

# verify compiler
if (NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  message("${PROJECT_NAME}: Your compiler is not officially supported. Issues or build errors may occur.")
endif()

# x86
set(CMAKE_SYSTEM_PROCESSOR "i686")
set(ARCH "x86")

# files
file(GLOB_RECURSE SRC
"${PROJECT_SOURCE_DIR}/src/memscan/util/util.c"

"${PROJECT_SOURCE_DIR}/src/memscan/memscan.c"

"${PROJECT_SOURCE_DIR}/src/dll.c"
)

# create library
add_library(${PROJECT_NAME} SHARED ${SRC})

# set standard
set_property(TARGET ${PROJECT_NAME} PROPERTY C_STANDARD 99)

# multi-processor compilation
add_definitions(/MP)

# max warnings
add_compile_options(/W4 /WX)

# options
macro(set_option option help value)
    option(${option} ${help} ${value})
    if(${option})
        message(STATUS "${PROJECT_NAME}: ${option}: ON")
        target_compile_definitions(${PROJECT_NAME} PUBLIC ${option})
    else()
        message(STATUS "${PROJECT_NAME}: ${option}: OFF")
    endif()
endmacro()

set_option(MEMSCAN_UNSAFE_OPTIMIZATIONS "Remove memscan safety checks" OFF)
set_option(UTIL_UNSAFE_OPTIMIZATIONS "Remove util safety checks" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)