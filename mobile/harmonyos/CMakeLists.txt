# OpenHarmony N-API CMakeLists.txt for libvpcore_napi.so
cmake_minimum_required(VERSION 3.4.1)
project(vpcore_napi)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(
    ${NATIVERENDER_ROOT_PATH}/include
    ${NATIVERENDER_ROOT_PATH}/cpp
)

add_library(vpcore SHARED IMPORTED)
set_target_properties(vpcore PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/${OHOS_ARCH}/libvpcore.so
)

add_library(vpcore_napi SHARED
    cpp/vpcore_napi.cpp
)

target_link_libraries(vpcore_napi PUBLIC
    vpcore
    ace_napi.z
    hilog_ndk.z
)
