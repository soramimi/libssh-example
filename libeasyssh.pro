
DESTDIR += $$PWD/lib

TEMPLATE = lib
TARGET = easyssh
CONFIG += staticlib

INCLUDEPATH += include

LIBS += -lssh


HEADERS += main.h \
	include/EasySSH.h \
	src/joinpath.h
SOURCES += \
	src/EasySSH.cpp \
	src/joinpath.cpp
