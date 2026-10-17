cmake_minimum_required(VERSION 3.10)
project(libhcs C CXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/.cmake")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GMP REQUIRED)
find_package(OpenMP)

set(LIBRARY_NAME "hcs")
set(LIBRARY_DIR "lib/")
set(INCLUDE_DIR "include/")
set(SOURCE_DIR  "src/")
set(TEST_DIR    "test/")
set(BINARY_DIR  "bin/")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BINARY_DIR})

# BEGIN: Project configuration
file(GLOB srcs "src/*.c" "src/com/*.c")

include(TestBigEndian)
test_big_endian(IsBigEndian)
# END: Project configuration

# BEGIN: Build commands
add_library(${LIBRARY_NAME} SHARED ${srcs})

target_compile_options(${LIBRARY_NAME} PRIVATE -O2 -Wall -Wextra)
target_include_directories(${LIBRARY_NAME}
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIR}"
    PRIVATE "${GMP_INCLUDE_DIR}")
target_link_libraries(${LIBRARY_NAME} PUBLIC ${GMP_LIBRARIES})

if (IsBigEndian)
    target_compile_definitions(${LIBRARY_NAME} PRIVATE HCS_BIG_ENDIAN)
endif ()

if (OpenMP_C_FOUND)
    target_link_libraries(${LIBRARY_NAME} PUBLIC OpenMP::OpenMP_C)
endif ()
# END: Build commands

# BEGIN: Install commands
install(DIRECTORY ${LIBRARY_DIR} DESTINATION lib USE_SOURCE_PERMISSIONS)
install(DIRECTORY ${INCLUDE_DIR} DESTINATION include)
# END: Install commands

# BEGIN: Test commands
enable_testing()

file(GLOB test_srcs "${TEST_DIR}/*.cpp")
foreach(f ${test_srcs})
    get_filename_component(test_prog ${f} NAME_WE)
    add_executable(${test_prog} "${f}")

    target_compile_options(${test_prog} PRIVATE -Wall -Wextra)
    target_include_directories(${test_prog}
        PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_DIR}"
                "${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIR}"
                "${GMP_INCLUDE_DIR}")
    target_link_libraries(${test_prog}
        PRIVATE ${LIBRARY_NAME} ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

    if (OpenMP_CXX_FOUND)
        target_link_libraries(${test_prog} PRIVATE OpenMP::OpenMP_CXX)
    endif ()

    add_test(NAME ${test_prog} COMMAND ${test_prog})
endforeach()
# END: Test commands
