#ifndef REPLYDNSRESULT_H
#define REPLYDNSRESULT_H

#include "MainHeader.h"

WEBADDR_TYPE getWebAddrType(char *, UINT32 *);
DNSPacket *getDNSResult(DNSPacket *, UINT32, WEBADDR_TYPE);

#endif