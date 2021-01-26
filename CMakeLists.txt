# No in-source build
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "In-source builds are not allowed.")
endif("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")

cmake_minimum_required(VERSION 3.19)

project(ermia)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -stdlib=libc++ -Woverloaded-virtual -Werror=reorder -Wno-address-of-packed-member")
set(LINK_FLAGS "-lc++abi -libverbs -lnuma -lpthread -pthread -lrt -lglog -lgflags")
link_libraries(${LINK_FLAGS})

# Pre-build glog and gflags with libc++
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/third-party/glog/lib)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/third-party/gflags/lib)

# Store shared libraries under /lib
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Use masstree for index
add_definitions(-DMASSTREE)

set(MASSTREE_CONFIG "--enable-max-key-len=1024 --with-malloc=malloc")

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-debug.h")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()

# Assume 64-byte cache line
add_definitions(-DCACHELINE_SIZE=64)

enable_testing()

include_directories(dbcore)
include_directories(masstree)
include_directories(third-party/sparsehash/src)

# The required headers for libc++.
include_directories(third-party/glog/include)
include_directories(third-party/gflags/include)

add_subdirectory(benchmarks)
add_subdirectory(dbcore)
add_subdirectory(masstree)

set_property(GLOBAL APPEND PROPERTY ALL_ERMIA_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/ermia.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/tuple.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/txn.cc
)

get_property(LIB_ERMIA_SRC GLOBAL PROPERTY ALL_ERMIA_SRC)

# Thread pool library
set_property(GLOBAL APPEND PROPERTY THREAD_POOL_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/dbcore/sm-thread.cpp
)
get_property(THREAD_POOL_SRC GLOBAL PROPERTY THREAD_POOL_SRC)
add_library(thread_pool SHARED ${THREAD_POOL_SRC})

# SI
add_library(ermia_si SHARED ${LIB_ERMIA_SRC})
add_executable(ermia_SI ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/dbtest.cc)
target_link_libraries(ermia_SI ermia_si thread_pool)

# Benchmark scripts
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run2.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run-cluster.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run-rdma-cluster.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run-tcp-cluster.sh" DESTINATION ${CMAKE_BINARY_DIR})
