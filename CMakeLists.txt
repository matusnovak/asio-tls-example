cmake_minimum_required(VERSION 3.9)

if(NOT DEFINED ENV{VCPKG_ROOT})
  message(FATAL_ERROR "VCPKG_ROOT not defined in the environment")
endif()

set(VCPKG_ROOT "$ENV{VCPKG_ROOT}")
message("VCPKG_ROOT: ${VCPKG_ROOT}")
set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")

project(AsioTlsExample)

find_package(asio CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE asio asio::asio OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 17)
