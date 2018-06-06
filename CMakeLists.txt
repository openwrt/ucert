cmake_minimum_required(VERSION 2.6)

PROJECT(ucert C)
ADD_DEFINITIONS(-Os -ggdb -Wall --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

find_library(json NAMES json-c json)

ADD_EXECUTABLE(ucert ucert.c usign-exec.c)
TARGET_LINK_LIBRARIES(ucert ubox blobmsg_json ${json})
INSTALL(TARGETS ucert RUNTIME DESTINATION bin)
