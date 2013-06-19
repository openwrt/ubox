cmake_minimum_required(VERSION 2.6)

PROJECT(ubox C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

find_library(json NAMES json-c json)
SET(LIBS ubox uci ubus ${json} blobmsg_json)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

ADD_EXECUTABLE(mount_root mount_root.c)
TARGET_LINK_LIBRARIES(mount_root ${LIBS})

INSTALL(TARGETS mount_root
	RUNTIME DESTINATION sbin
)

ADD_EXECUTABLE(block block.c
		libblkid-tiny/libblkid-tiny.c
		libblkid-tiny/md5.c
		libblkid-tiny/mkdev.c
		libblkid-tiny/ext.c
		libblkid-tiny/jffs2.c
		libblkid-tiny/vfat.c
		libblkid-tiny/swap.c
		libblkid-tiny/squashfs.c)
TARGET_LINK_LIBRARIES(block ${LIBS} blobmsg_json)

INSTALL(TARGETS block
	RUNTIME DESTINATION sbin
)

ADD_EXECUTABLE(kmodloader kmodloader.c)
TARGET_LINK_LIBRARIES(kmodloader ${LIBS})

INSTALL(TARGETS kmodloader
	RUNTIME DESTINATION sbin
)

ADD_EXECUTABLE(board board.c)
TARGET_LINK_LIBRARIES(board ${LIBS})

INSTALL(TARGETS board
	RUNTIME DESTINATION sbin
)

ADD_EXECUTABLE(lsbloader lsbloader.c)
TARGET_LINK_LIBRARIES(lsbloader ${LIBS})

INSTALL(TARGETS lsbloader
	RUNTIME DESTINATION sbin
)
