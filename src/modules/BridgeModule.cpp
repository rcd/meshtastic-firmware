#include "configuration.h"

#if !MESHTASTIC_EXCLUDE_BRIDGE

#include "BridgeModule.h"
#include "mesh/Channels.h"
#include "mesh/NodeDB.h"
#include "mesh/Throttle.h"
#include "mesh/mesh-pb-constants.h"
#include "MeshService.h"
#include "mesh/MeshTypes.h"
#include "mesh/Router.h"
#include "mesh/generated/meshtastic/mesh.pb.h"
#include "meshUtils.h"
#include <pb_decode.h>
#include <pb_encode.h>

BridgeModule *bridgeModule = nullptr;

void PacketIdRing::record(uint32_t from, uint32_t id)
{
    concurrency::LockGuard g(&lock);
    entries[head] = {from, id};
    head = (head + 1) % BRIDGE_LOOP_RING_SIZE;
    if (count < BRIDGE_LOOP_RING_SIZE)
        count++;
}

bool PacketIdRing::contains(uint32_t from, uint32_t id) const
{
    concurrency::LockGuard g(&lock);
    for (uint8_t i = 0; i < count; i++) {
        if (entries[i].from == from && entries[i].id == id)
            return true;
    }
    return false;
}

UartBridgeLink::UartBridgeLink(uint32_t rxPin, uint32_t txPin, uint32_t dePin, uint32_t baud)
    : rxPin(rxPin), txPin(txPin), dePin(dePin), baud(baud)
{
}

bool UartBridgeLink::init()
{
    if (initialized)
        return true;

    if (dePin) {
        pinMode(dePin, OUTPUT);
        digitalWrite(dePin, LOW); // default to receive mode
    }

#if defined(ARCH_ESP32)
    Serial2.setRxBufferSize(512);
    Serial2.begin(baud, SERIAL_8N1, rxPin, txPin);
    serial = &Serial2;
#elif defined(ARCH_NRF52)
    Serial1.setPins(rxPin, txPin);
    Serial1.begin(baud, SERIAL_8N1);
    serial = &Serial1;
#elif defined(ARCH_RP2040)
    Serial2.setFIFOSize(512);
    Serial2.setPinout(txPin, rxPin);
    Serial2.begin(baud, SERIAL_8N1);
    serial = &Serial2;
#else
    Serial1.begin(baud, SERIAL_8N1);
    serial = &Serial1;
#endif

    initialized = true;
    if (dePin)
        LOG_INFO("UartBridgeLink initialized (RS485): rx=%u tx=%u de=%u baud=%u", rxPin, txPin, dePin, baud);
    else
        LOG_INFO("UartBridgeLink initialized (UART): rx=%u tx=%u baud=%u", rxPin, txPin, baud);
    return true;
}

int UartBridgeLink::available()
{
    if (!serial)
        return 0;
    return serial->available();
}

int UartBridgeLink::readBytes(uint8_t *buf, int maxLen)
{
    if (!serial)
        return 0;
    return serial->readBytes(buf, maxLen);
}

void UartBridgeLink::beginWrite()
{
    if (dePin)
        digitalWrite(dePin, HIGH);
}

void UartBridgeLink::endWrite()
{
    if (serial)
        serial->flush();
    if (dePin)
        digitalWrite(dePin, LOW);
}

size_t UartBridgeLink::writeBytes(const uint8_t *buf, size_t len)
{
    if (!serial)
        return 0;
    return serial->write(buf, len);
}

void UartBridgeLink::flush()
{
    if (serial)
        serial->flush();
}

// this should really be a utility function for use with SerialModule
uint32_t BridgeModule::baudEnumToRate(meshtastic_ModuleConfig_SerialConfig_Serial_Baud baud)
{
    switch (baud) {
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_110:
        return 110;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_300:
        return 300;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_600:
        return 600;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_1200:
        return 1200;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_2400:
        return 2400;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_4800:
        return 4800;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_9600:
        return 9600;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_19200:
        return 19200;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_38400:
        return 38400;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_57600:
        return 57600;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_115200:
        return 115200;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_230400:
        return 230400;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_460800:
        return 460800;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_576000:
        return 576000;
    case meshtastic_ModuleConfig_SerialConfig_Serial_Baud_BAUD_921600:
        return 921600;
    default:
        return BRIDGE_DEFAULT_BAUD;
    }
}


BridgeModule::BridgeModule()
    : MeshModule("bridge"), concurrency::OSThread("BridgeModule")
{
    isPromiscuous = true;
    loopbackOk = false;
    // Allow the bridge to see packets it can't decrypt (e.g. PKI DMs) — it always
    // forwards the encrypted copy via router->p_encrypted regardless.
    encryptedOk = true;

    uint32_t baud = baudEnumToRate(moduleConfig.bridge.baud);

    if (baud < BRIDGE_MIN_BAUD) {
        LOG_WARN("BridgeModule: baud %u below minimum %u, using %u", baud, BRIDGE_MIN_BAUD, BRIDGE_MIN_BAUD);
        baud = BRIDGE_MIN_BAUD;
    }

    // 3 character times (10 bits each) in ms, minimum 100ms
    uint32_t charTimeoutMs = 30000 / baud;
    frameTimeoutMs = (charTimeoutMs > 100) ? charTimeoutMs : 100;

    auto linkType = moduleConfig.bridge.link_type;
    if (linkType == meshtastic_ModuleConfig_BridgeConfig_BridgeLinkType_LINK_RS485 ||
        linkType == meshtastic_ModuleConfig_BridgeConfig_BridgeLinkType_LINK_UART) {
        uint32_t rxPin = moduleConfig.bridge.rxd;
        uint32_t txPin = moduleConfig.bridge.txd;
        uint32_t dePin = moduleConfig.bridge.de_pin;

        if (rxPin == 0 || txPin == 0) {
            LOG_ERROR("BridgeModule: invalid pin config (rxd=%u txd=%u), must be non-zero", rxPin, txPin);
            return;
        }
        if (linkType == meshtastic_ModuleConfig_BridgeConfig_BridgeLinkType_LINK_RS485 && dePin == 0) {
            LOG_ERROR("BridgeModule: RS485 requires de_pin to be non-zero");
            return;
        }

        if (moduleConfig.has_serial && moduleConfig.serial.enabled) {
            LOG_WARN("BridgeModule: SerialModule is also enabled — ensure they use different UARTs");
        }

        link = new UartBridgeLink(rxPin, txPin, dePin, baud);
        if (!link->init()) {
            LOG_ERROR("BridgeModule: UartBridgeLink init failed");
            delete link;
            link = nullptr;
        }
    }

    LOG_INFO("BridgeModule initialized");
}

BridgeModule::~BridgeModule()
{
    delete link;
}

bool BridgeModule::shouldFilter(const meshtastic_MeshPacket &mp) const
{
    if (mp.which_payload_variant != meshtastic_MeshPacket_decoded_tag)
        return false;

    if (mp.decoded.portnum == meshtastic_PortNum_ROUTING_APP)
        return true;

    if (moduleConfig.bridge.blocked_portnums_count > 0 &&
        is_in_repeated(moduleConfig.bridge.blocked_portnums, (uint32_t)mp.decoded.portnum))
        return true;

    return false;
}


ProcessMessage BridgeModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    if (!link || !link->isInitialized())
        return ProcessMessage::CONTINUE;

    // Filter unwanted portnums
    if (shouldFilter(mp))
        return ProcessMessage::CONTINUE;

    // Loop prevention: skip packets that came from link
    if (loopRing.contains(mp.from, mp.id))
        return ProcessMessage::CONTINUE;

    // Don't re-bridge packets that arrived via a bridge
    if (mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_BRIDGE)
        return ProcessMessage::CONTINUE;

    // This packet arrived via local RF; clear the bridge flag for its sender
    meshtastic_NodeInfoLite *srcNode = nodeDB->getMeshNode(mp.from);
    if (srcNode)
        srcNode->bitfield &= ~NODEINFO_BITFIELD_VIA_BRIDGE_MASK;

    // Skip unicast packets whose destination is reachable locally
    if (!isBroadcast(mp.to)) {
        meshtastic_NodeInfoLite *destNode = nodeDB->getMeshNode(mp.to);
        if (destNode && !(destNode->bitfield & NODEINFO_BITFIELD_VIA_BRIDGE_MASK)) {
            LOG_DEBUG("Bridge: skip unicast to local node 0x%08x", mp.to);
            return ProcessMessage::CONTINUE;
        }
    }

    // Access the encrypted copy of this packet from the router
    if (!router || !router->p_encrypted)
        return ProcessMessage::CONTINUE;

    sendToLink(*router->p_encrypted);

    return ProcessMessage::CONTINUE;
}

void BridgeModule::sendToLink(const meshtastic_MeshPacket &mp)
{
    uint8_t payload[meshtastic_MeshPacket_size];
    size_t payloadLen = pb_encode_to_bytes(payload, sizeof(payload), &meshtastic_MeshPacket_msg, &mp);
    if (payloadLen == 0) {
        LOG_WARN("Bridge: failed to encode packet");
        return;
    }

    if (payloadLen > BRIDGE_MAX_PAYLOAD) {
        LOG_WARN("Bridge: encoded payload %u exceeds max %u, dropping", payloadLen, BRIDGE_MAX_PAYLOAD);
        return;
    }

    uint16_t crc = crc16Ccitt(payload, payloadLen);

    uint8_t header[3] = {BRIDGE_FRAME_START, (uint8_t)(payloadLen >> 8), (uint8_t)(payloadLen & 0xFF)};
    uint8_t trailer[2] = {(uint8_t)(crc >> 8), (uint8_t)(crc & 0xFF)};

    link->beginWrite();
    link->writeBytes(header, sizeof(header));
    link->writeBytes(payload, payloadLen);
    link->writeBytes(trailer, sizeof(trailer));
    link->endWrite();
    lastActivityTime = millis();

    LOG_DEBUG("Bridge: sent %u bytes to link (from=0x%08x id=0x%08x)", payloadLen, mp.from, mp.id);
}


int32_t BridgeModule::runOnce()
{
    if (!link || !link->isInitialized())
        return 1000;

    // Reset parser if a partial frame has stalled
    if (rxState != WAIT_START && lastByteTime != 0 && (millis() - lastByteTime > frameTimeoutMs)) {
        LOG_WARN("Bridge: frame timeout, resetting parser");
        rxState = WAIT_START;
    }

    // Read available bytes and feed to state machine parser
    bool hadBytes = false;
    while (link->available() > 0) {
        uint8_t b;
        if (link->readBytes(&b, 1) == 1) {
            lastByteTime = millis();
            parseByte(b);
            hadBytes = true;
        }
    }

    // Adaptive polling: fast when active, back off when idle
    if (hadBytes) {
        lastActivityTime = millis();
        return 0;
    }
    if (Throttle::isWithinTimespanMs(lastActivityTime, 2000))
        return 5;
    return 250;
}

void BridgeModule::parseByte(uint8_t b)
{
    switch (rxState) {
    case WAIT_START:
        if (b == BRIDGE_FRAME_START)
            rxState = WAIT_LEN_HI;
        break;

    case WAIT_LEN_HI:
        rxLen = (uint16_t)b << 8;
        rxState = WAIT_LEN_LO;
        break;

    case WAIT_LEN_LO:
        rxLen |= b;
        if (rxLen == 0 || rxLen > BRIDGE_MAX_PAYLOAD) {
            LOG_WARN("Bridge: invalid frame length %u, resyncing", rxLen);
            rxState = WAIT_START;
        } else {
            rxIdx = 0;
            rxState = WAIT_PAYLOAD;
        }
        break;

    case WAIT_PAYLOAD:
        rxBuf[rxIdx++] = b;
        if (rxIdx >= rxLen)
            rxState = WAIT_CRC_HI;
        break;

    case WAIT_CRC_HI:
        rxCrcHi = b;
        rxState = WAIT_CRC_LO;
        break;

    case WAIT_CRC_LO: {
        uint16_t rxCrc = ((uint16_t)rxCrcHi << 8) | b;
        uint16_t calcCrc = crc16Ccitt(rxBuf, rxLen);
        if (rxCrc == calcCrc) {
            processReceivedFrame(rxBuf, rxLen);
        } else {
            LOG_WARN("Bridge: CRC mismatch (got 0x%04x, expected 0x%04x), dropping frame", rxCrc, calcCrc);
        }
        rxState = WAIT_START;
        break;
    }
    }
}

void BridgeModule::processReceivedFrame(const uint8_t *payload, uint16_t len)
{
    meshtastic_MeshPacket *p = packetPool.allocZeroed();
    if (!p) {
        LOG_WARN("Bridge: failed to allocate MeshPacket");
        return;
    }

    if (!pb_decode_from_bytes(payload, len, &meshtastic_MeshPacket_msg, p)) {
        LOG_WARN("Bridge: failed to decode MeshPacket from link");
        packetPool.release(p);
        return;
    }

    // Reject non-encrypted packets — only encrypted payloads should arrive over the link.
    // Accepting decoded packets would bypass the mesh encryption layer entirely.
    if (p->which_payload_variant != meshtastic_MeshPacket_encrypted_tag) {
        LOG_WARN("Bridge: rejecting non-encrypted packet from link");
        packetPool.release(p);
        return;
    }

    // Validate hop bounds to prevent amplification (same check as MQTT)
    if (p->hop_start > HOP_MAX)
        p->hop_start = HOP_MAX;
    if (p->hop_limit > HOP_MAX)
        p->hop_limit = HOP_MAX;

    // Record in loop prevention ring so we don't echo this back to the link
    loopRing.record(p->from, p->id);

    // Mark the sender as a bridge-side node (if already in NodeDB)
    meshtastic_NodeInfoLite *srcNode = nodeDB->getMeshNode(p->from);
    if (srcNode)
        srcNode->bitfield |= NODEINFO_BITFIELD_VIA_BRIDGE_MASK;

    // Give fresh hop budget for local mesh
    p->hop_limit = p->hop_start;

    // Clear routing hints — let local mesh routing decide
    p->relay_node = 0;
    p->next_hop = 0;

    // Remap channel hash to local channel 0 so the receiving router can find the matching
    // PSK for decryption. The hash varies by modem preset on the default channel, but the
    // underlying key is the same, so swapping the hash is sufficient.
    // Skip PKI packets (channel == 0) — they use recipient public key, not channel PSK.
    if (p->channel != 0)
        p->channel = channels.getHash(0);

    p->transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_BRIDGE;

    LOG_INFO("Bridge: injecting packet from link (from=0x%08x id=0x%08x hop_start=%u ch=0x%x)", p->from, p->id, p->hop_start,
             p->channel);

    if (router)
        router->enqueueReceivedMessage(p);
    else
        packetPool.release(p);
}

#endif // !MESHTASTIC_EXCLUDE_BRIDGE
