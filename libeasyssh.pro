
DESTDIR += $$PWD/lib

TEMPLATE = lib
TARGET = easyssh
CONFIG += staticlib

INCLUDEPATH += include

LIBS += -lssh


HEADERS += main.h \
	include/EasySSH.h
SOURCES += \
	src/EasySSH.cpp
