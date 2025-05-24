
TEMPLATE = app
TARGET = libssh-example

LIBS += -lssh


HEADERS += main.h \
	EasySSH.h
SOURCES += \
	EasySSH.cpp \
	main.cpp
