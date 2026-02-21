#pragma once

#include "concurrency/LockGuard.h"
#include "concurrency/OSThread.h"
#include "configuration.h"
#include "mesh/MeshModule.h"
#include "mesh/Router.h"
#include <Arduino.h>

#if !MESHTASTIC_EXCLUDE_BRIDGE

#define BRIDGE_FRAME_START 0xBD       // Frame delimiter byte for the bridge wire protocol
#define BRIDGE_MAX_PAYLOAD 400        // Max encoded MeshPacket size per frame (bytes)
// Number of (from, id) pairs tracked for loop prevention. Sized to cover multi-hop RF echo
// latency (~6s at max throughput). Cost: 256 * 8 = 2KB. If traffic exceeds ring capacity,
// evicted entries may cause echo loops -- but this is unlikely under normal mesh load.
#define BRIDGE_LOOP_RING_SIZE 256
#define BRIDGE_DEFAULT_BAUD 115200    // Recommended minimum baud rate for reliable operation
#define BRIDGE_MIN_BAUD 9600          // Lowest baud rate that can handle all LoRa presets
#define BRIDGE_MAX_RX_PER_SEC 20      // Max packets accepted from link per second (rate limit)

// Security: The wire protocol provides CRC16 error detection but no authentication,
// encryption of metadata, or replay protection. Physical link access is assumed trusted.
// Inbound packets are rate-limited to mitigate airtime flooding from UART injection.

// Abstract base class for bridge transport links.
class BridgeLink
{
  public:
    virtual ~BridgeLink() = default;
    virtual bool init() = 0;
    virtual int available() = 0;
    virtual int readBytes(uint8_t *buf, int maxLen) = 0;
    virtual void beginWrite() {}
    virtual void endWrite() {}
    virtual size_t writeBytes(const uint8_t *buf, size_t len) = 0;
    virtual void flush() = 0;
    virtual bool isInitialized() = 0;
};

// UART bridge link with optional RS485 DE (direction enable) pin.
class UartBridgeLink : public BridgeLink
{
  public:
    UartBridgeLink(uint32_t rxPin, uint32_t txPin, uint32_t dePin, uint32_t baud);
    bool init() override;
    int available() override;
    int readBytes(uint8_t *buf, int maxLen) override;
    void beginWrite() override;
    void endWrite() override;
    size_t writeBytes(const uint8_t *buf, size_t len) override;
    void flush() override;
    bool isInitialized() override { return initialized; }

  private:
    uint32_t rxPin, txPin, dePin, baud;
    Stream *serial = nullptr;
    bool initialized = false;
};

// Circular buffer for loop prevention -- tracks (from, id) pairs of packets received from link
struct PacketIdEntry {
    uint32_t from;
    uint32_t id;
};

class PacketIdRing
{
  public:
    void record(uint32_t from, uint32_t id);
    bool contains(uint32_t from, uint32_t id) const;

  private:
    PacketIdEntry entries[BRIDGE_LOOP_RING_SIZE] = {};
    uint16_t head = 0;
    uint16_t count = 0;
    mutable concurrency::Lock lock;
};

class BridgeModule : public MeshModule, private concurrency::OSThread
{
  public:
    BridgeModule();
    virtual ~BridgeModule();

  protected:
    virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    // Combined with isPromiscuous and encryptedOk, this ensures the bridge sees every packet
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override { return true; }
    virtual int32_t runOnce() override;

  private:
    BridgeLink *link = nullptr;
    PacketIdRing loopRing;

    // Frame parser state for receiving from link
    enum RxState { WAIT_START, WAIT_LEN_HI, WAIT_LEN_LO, WAIT_PAYLOAD, WAIT_CRC_HI, WAIT_CRC_LO };
    RxState rxState = WAIT_START;
    uint8_t rxBuf[BRIDGE_MAX_PAYLOAD];
    uint16_t rxLen = 0;
    uint16_t rxIdx = 0;
    uint8_t rxCrcHi = 0;
    uint32_t lastByteTime = 0;
    uint32_t frameTimeoutMs = 100;
    uint32_t lastActivityTime = 0;

    // Rate limiter for packets received from the link
    uint32_t rxWindowStart = 0;
    uint16_t rxWindowCount = 0;

    void sendToLink(const meshtastic_MeshPacket &mp);
    void processReceivedFrame(const uint8_t *payload, uint16_t len);
    void parseByte(uint8_t b);
    bool shouldFilter(const meshtastic_MeshPacket &mp) const;
    static uint32_t baudEnumToRate(meshtastic_ModuleConfig_SerialConfig_Serial_Baud baud);
};

extern BridgeModule *bridgeModule;

#endif
