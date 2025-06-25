DESTDIR = $$PWD/_bin

QMAKE_PROJECT_DEPTH = 0

TEMPLATE = app
TARGET = libssh-example

INCLUDEPATH += include

win32:DEFINES += NOMINMAX
win32:INCLUDEPATH += C:\vcpkg\installed\x64-windows\include
win32:LIBS += -LC:\vcpkg\installed\x64-windows\lib

LIBS += -lssh

HEADERS += main.h \
	include/EasySSH.h \
	src/joinpath.h
SOURCES += \
	src/EasySSH.cpp \
	main.cpp \
	src/joinpath.cpp
