#!/bin/sh

mvn -Dsun.security.smartcardio.library=/usr/lib/arm-linux-gnueabihf/libpcsclite.so.1 -Dsmartcardio.reader='OMNIKEY AG 3121 USB 00 00' -Djava.util.logging.config.file=commons-logging.properties -Dnl.mansoft.isoappletprovider.alias=sim923 test
