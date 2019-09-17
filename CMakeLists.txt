cmake_minimum_required(VERSION 2.6)

PROJECT(ucert C)
ADD_DEFINITIONS(-Os -ggdb -Wall --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

FIND_PATH(ubox_include_dir NAMES libubox/usock.h)
FIND_PATH(jsonc_include_dir NAMES json-c/json.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${jsonc_include_dir})

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_LIBRARY(json NAMES json-c json)

IF(UCERT_HOST_BUILD)
ADD_DEFINITIONS(-DUCERT_HOST_BUILD)
ENDIF()

IF(USE_RPATH)
SET(CMAKE_INSTALL_RPATH "${USE_RPATH}")
SET(CMAKE_MACOSX_RPATH 1)
ENDIF()

ADD_EXECUTABLE(ucert ucert.c usign-exec.c)
IF(UCERT_FULL)
ADD_DEFINITIONS(-DUCERT_FULL)
TARGET_LINK_LIBRARIES(ucert ${ubox} ${blobmsg_json} ${json})
ELSE()
ADD_DEFINITIONS(-DUCERT_STRIP_MESSAGES)
TARGET_LINK_LIBRARIES(ucert ${ubox})
ENDIF()

INSTALL(TARGETS ucert RUNTIME DESTINATION bin)
