
TEMPLATE = app
TARGET = libssh-example

INCLUDEPATH += include

LIBS += -lssh


HEADERS += main.h \
	include/EasySSH.h \
	src/joinpath.h
SOURCES += \
	src/EasySSH.cpp \
	main.cpp \
	src/joinpath.cpp
