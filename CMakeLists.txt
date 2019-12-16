cmake_minimum_required(VERSION 2.6)

PROJECT(ucert C)

ADD_DEFINITIONS(-Wall -Werror)
IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
	ADD_DEFINITIONS(-Wextra -Werror=implicit-function-declaration)
	ADD_DEFINITIONS(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
ADD_DEFINITIONS(-Os -std=gnu99 -ggdb -Wmissing-declarations -Wno-unused-parameter)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

FIND_PATH(ubox_include_dir NAMES libubox/usock.h)
FIND_PATH(jsonc_include_dir NAMES json-c/json.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${jsonc_include_dir})

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_LIBRARY(json NAMES json-c json)

MACRO(ADD_UNIT_TEST_SAN name)
	ADD_EXECUTABLE(${name}-san ${name}.c)
	TARGET_COMPILE_OPTIONS(${name}-san PRIVATE -g -fno-omit-frame-pointer -fsanitize=undefined,address,leak -fno-sanitize-recover=all)
	TARGET_LINK_OPTIONS(${name}-san PRIVATE -fsanitize=undefined,address,leak)
	TARGET_LINK_LIBRARIES(${name}-san ucert_lib ${ubox} ${blobmsg_json} ${json})
	TARGET_INCLUDE_DIRECTORIES(${name}-san PRIVATE ${PROJECT_SOURCE_DIR})
ENDMACRO(ADD_UNIT_TEST_SAN)

IF(UCERT_HOST_BUILD)
	ADD_DEFINITIONS(-DUCERT_HOST_BUILD)
ENDIF()

IF(USE_RPATH)
	SET(CMAKE_INSTALL_RPATH "${USE_RPATH}")
	SET(CMAKE_MACOSX_RPATH 1)
ENDIF()

ADD_LIBRARY(ucert_lib STATIC usign-exec.c)
ADD_EXECUTABLE(ucert ucert.c)

IF(UCERT_FULL)
	ADD_DEFINITIONS(-DUCERT_FULL)
	TARGET_LINK_LIBRARIES(ucert ucert_lib ${ubox} ${blobmsg_json} ${json})
ELSE()
	ADD_DEFINITIONS(-DUCERT_STRIP_MESSAGES)
	TARGET_LINK_LIBRARIES(ucert ucert_lib ${ubox})
ENDIF()

IF(UNIT_TESTING)
	ENABLE_TESTING()
	ADD_SUBDIRECTORY(tests)
	ADD_UNIT_TEST_SAN(ucert)
ENDIF()

INSTALL(TARGETS ucert RUNTIME DESTINATION bin)
