cmake_minimum_required(VERSION 3.16)
project(omniguard-sensor-cpp VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(HIREDIS REQUIRED hiredis)

add_executable(omniguard-sensor
    src/main.cpp
    src/capture.cpp
    src/classifier.cpp
    src/redis_publisher.cpp
)

target_include_directories(omniguard-sensor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
    ${HIREDIS_INCLUDE_DIRS}
)

target_link_libraries(omniguard-sensor PRIVATE
    ${PCAP_LIBRARIES}
    ${HIREDIS_LIBRARIES}
)

target_compile_options(omniguard-sensor PRIVATE -Wall -Wextra -O2)

# Pruebas unitarias del parser y el clasificador: cmake -DBUILD_TESTS=ON ..
option(BUILD_TESTS "Compilar pruebas unitarias" OFF)
if(BUILD_TESTS)
    add_executable(classifier_test
        test/test_classifier.cpp
        src/classifier.cpp
        src/capture.cpp
    )
    target_include_directories(classifier_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIRS}
    )
    target_link_libraries(classifier_test PRIVATE ${PCAP_LIBRARIES})
    target_compile_options(classifier_test PRIVATE -Wall -Wextra)
    enable_testing()
    add_test(NAME classifier COMMAND classifier_test)
endif()