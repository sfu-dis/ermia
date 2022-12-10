set_property(GLOBAL APPEND PROPERTY ALL_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utils.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/util/hash.cc
)

if(POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

cmake_minimum_required(VERSION 3.11)
include(FetchContent)
include(ExternalProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-long-long -fPIC -march=native")
set(CMAKE_ENABLE_COMPILE_COMMANDS "ON")

if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message("-- Release mode, all optimizations enabled")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -DNDEBUG -Ofast")
endif()

# #################### Epoch Reclaim ####################
FetchContent_Declare(
  epoch_reclaimer
  GIT_REPOSITORY https://github.com/XiangpengHao/epoch-reclaimer.git
  GIT_TAG master
)

if(NOT epoch_reclaimer_POPULATED)
  FetchContent_Populate(epoch_reclaimer)
  include_directories(${epoch_reclaimer_SOURCE_DIR})
endif()

option(USE_PMEM "enable persistent memory support" ON)

set(libs_to_link
  pthread gflags)
