
TEMPLATE = app
TARGET = libssh-example

INCLUDEPATH += include

LIBS += -lssh


HEADERS += main.h \
	include/EasySSH.h
SOURCES += \
	src/EasySSH.cpp \
	main.cpp
