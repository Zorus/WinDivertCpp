#include "WinDivertCpp.h"
#include "WinDivertExceptions.h"
#include <iostream>

namespace WinDivertCpp
{
    
    WinDivert::WinDivert(std::filesystem::path baseDir)
        : m_winDiverLib(new WinDivertLib(baseDir)), m_winDivertHandle(INVALID_HANDLE_VALUE)
    {
       
    }

    WinDivert::WinDivert(std::shared_ptr<WinDivertLib> winDiverLib)
        : m_winDiverLib(winDiverLib), m_winDivertHandle(INVALID_HANDLE_VALUE)
    {

    }

    WinDivert::~WinDivert()
    {
        try
        {
            if (m_winDivertHandle != INVALID_HANDLE_VALUE)
            {
                m_winDiverLib->m_WinDivertClose(m_winDivertHandle);
                m_winDivertHandle = INVALID_HANDLE_VALUE;
            }
        }
        catch (std::exception&)
        {

        }
    }

    bool WinDivert::CheckHandle(bool silent)
    {
        bool isValid = m_winDivertHandle != INVALID_HANDLE_VALUE;
        if (!isValid && !silent)
        {
            throw std::runtime_error("Handle invalid.");
        }
        return isValid;
    }
    
    bool WinDivert::WinDivertOpen(const std::string& filter, ::WINDIVERT_LAYER layer,
        int16_t priority, uint64_t flags)
    {
        if (m_winDivertHandle != INVALID_HANDLE_VALUE)
        {
            WinDivertClose();
        }
        m_winDivertHandle = m_winDiverLib->m_WinDivertOpen(filter.c_str(), layer, priority, flags);
        return m_winDivertHandle != INVALID_HANDLE_VALUE;
    }

    void WinDivert::WinDivertRecv(std::vector<char>& packet, ::WINDIVERT_ADDRESS* pAddr)
    {
        CheckHandle();
        uint32_t recivedSize = 0;
        bool success = true;
        do
        {
            success = m_winDiverLib->m_WinDivertRecv(m_winDivertHandle,
                packet.data(), packet.size(), &recivedSize, pAddr);

            if (!success)
            {
                uint32_t lastError = ::GetLastError();
                if (ERROR_INSUFFICIENT_BUFFER == lastError)
                {
                    packet.resize(packet.size() * 2);
                    continue;
                }
                throw WinApiException(lastError, "WinDivertRecv failed.");
            }

        } while (!success);

        packet.resize(recivedSize);
    }

    bool WinDivert::WinDivertRecvEx(std::vector<char>& packet, uint64_t flags,
                                    std::vector<::WINDIVERT_ADDRESS>& pAddr,
                                    OverlappedEvent* overlappedEvent,
                                    OverlappedEvent::TimeoutType ioTimeOut)
    {
        CheckHandle();
        std::unique_ptr<OVERLAPPED> overlappedGuard;
        if (overlappedEvent)
        {
            overlappedGuard.reset(new OVERLAPPED());
            memset(overlappedGuard.get(), 0, sizeof(OVERLAPPED));
            overlappedEvent->Reset();
            overlappedGuard->hEvent = overlappedEvent->GetNativeHandle();
        }
        uint32_t recivedSizeInBytes = 0;
        uint32_t pAddrSizeInBytes = pAddr.size() * sizeof(std::remove_reference<decltype(pAddr)>::type::value_type);
        bool success = true;

        success = m_winDiverLib->m_WinDivertRecvEx(m_winDivertHandle,
            packet.data(), packet.size(), &recivedSizeInBytes, flags, 
            pAddr.data(), &pAddrSizeInBytes, overlappedGuard.get());

        uint32_t lastError = ::GetLastError();

        if (!success || ERROR_IO_PENDING == lastError)
        {
            if (ERROR_IO_PENDING != lastError)
            {
                throw WinApiException(lastError, "WinDivertRecvEx failed.");
            }

            if (!overlappedEvent)
            {
                throw WinApiException(lastError, "WinDivertRecvEx failed. WinDivertRecvEx returned status about IO Pending operation, but operationOverlappedEvent is null.");
            }

            uint32_t waitResult = overlappedEvent->Wait(ioTimeOut);
            
            if (WAIT_TIMEOUT == waitResult)
            {
                throw TimeoutException("WinDivertRecvEx call. IO Timeout occured.");
            }
            if (waitResult == WAIT_OBJECT_0)
            {
                DWORD overlappedOperationBytes = 0;
                        
                success = ::GetOverlappedResult(m_winDivertHandle, overlappedGuard.get(),
                    &overlappedOperationBytes, true);

                if (!success)
                {
                    if (ERROR_IO_INCOMPLETE != ::GetLastError())
                    {
                        throw WinApiException("WinDivertRecvEx call. GetOverlappedResult failed.");
                    }
                }
                recivedSizeInBytes = overlappedOperationBytes;
            }
            else
            {
                throw WinApiException(lastError, "WinDivertRecvEx failed. Unexpected wait result returned.");
            }
        }
        if (success)
        {
            packet.resize(recivedSizeInBytes);
            size_t addrCount = pAddrSizeInBytes / sizeof(std::remove_reference<decltype(pAddr)>::type::value_type);
            pAddr.resize(addrCount);
        }
        return success;
    }

    uint32_t WinDivert::WinDivertSend(const std::vector<char>& packet, const ::WINDIVERT_ADDRESS* pAddr)
    {
        CheckHandle();
        uint32_t sendLen = 0;
        bool success = m_winDiverLib->m_WinDivertSend(m_winDivertHandle,packet.data(), 
                       packet.size(), &sendLen, pAddr);
        if (!success)
        {
            throw WinApiException("WinDivertSend failed.");
        }
        return sendLen;
    }

    uint32_t WinDivert::WinDivertSendEx(const std::vector<char>& packet, uint64_t flags,
                                    const std::vector<::WINDIVERT_ADDRESS>& pAddr, 
                                    OverlappedEvent* overlappedEvent,
                                    OverlappedEvent::TimeoutType ioTimeOut)
    {
        CheckHandle();
        std::unique_ptr<OVERLAPPED> overlappedGuard;
        if (overlappedEvent)
        {
            overlappedGuard.reset(new OVERLAPPED());
            memset(overlappedGuard.get(), 0, sizeof(OVERLAPPED));
            overlappedEvent->Reset();
            overlappedGuard->hEvent = overlappedEvent->GetNativeHandle();
        }
        uint32_t result = 0;
        size_t pAddrSizeInBytes = pAddr.size() * sizeof(std::remove_reference<decltype(pAddr)>::type::value_type);
        bool success = m_winDiverLib->m_WinDivertSendEx(m_winDivertHandle, packet.data(),
            packet.size(), &result, flags, pAddr.data(), pAddrSizeInBytes, overlappedGuard.get());

        if (!success)
        {
            uint32_t lastError = ::GetLastError();
            if (ERROR_IO_PENDING != lastError)
            {
                throw WinApiException(lastError, "WinDivertSendEx failed.");
            }
            if (!overlappedEvent)
            {
                throw WinApiException(lastError, "WinDivertSendEx failed. WinDivertSendEx returned status about IO Pending operation, but operationOverlappedEvent is null.");
            }

            int32_t waitResult = overlappedEvent->Wait(ioTimeOut);
            if (waitResult == WAIT_TIMEOUT)
            {
                throw TimeoutException("WinDivertSendEx call. IO Timeout occured.");
            }
            else if (waitResult == WAIT_OBJECT_0)
            {
                DWORD overlappedOperationBytes = 0;
                success = ::GetOverlappedResult(m_winDivertHandle, overlappedGuard.get(),
                    &overlappedOperationBytes, false);
                if (!success)
                {
                    if (ERROR_IO_INCOMPLETE != ::GetLastError())
                    {
                        throw WinApiException("WinDivertSendEx call. GetOverlappedResult failed.");
                    }
                }
                result = overlappedOperationBytes;
            }
            else
            {
                throw WinApiException(lastError, "WinDivertSendEx failed. Unexpected wait result returned..");
            }
        }
        return result;
    }

    void WinDivert::WinDivertShutdown(::WINDIVERT_SHUTDOWN how)
    {
        CheckHandle();
        if (!m_winDiverLib->m_WinDivertShutdown(m_winDivertHandle, how))
        {
            throw WinApiException("WinDivertShutdown failed.");
        }
    }

    bool WinDivert::WinDivertClose()
    {
        bool success = true;
        if (m_winDivertHandle != INVALID_HANDLE_VALUE)
        {
            success = m_winDiverLib->m_WinDivertClose(m_winDivertHandle);
            m_winDivertHandle = INVALID_HANDLE_VALUE;
        }
        return success;
    }

    bool WinDivert::WinDivertSetParam(::WINDIVERT_PARAM param, uint64_t value)
    {
        CheckHandle();
        return m_winDiverLib->m_WinDivertSetParam(m_winDivertHandle, param, value);
    }

    bool WinDivert::WinDivertGetParam(::WINDIVERT_PARAM param, uint64_t& outValue)
    {
        CheckHandle();
        return m_winDiverLib->m_WinDivertGetParam(m_winDivertHandle, param, &outValue);
    }

    uint64_t WinDivert::WinDivertHelperHashPacket(const std::vector<char>& packet, uint64_t seed)
    {
        return m_winDiverLib->m_WinDivertHelperHashPacket(packet.data(), packet.size(), seed);
    }

    bool WinDivert::WinDivertHelperParsePacket(const void* pPacket, UINT packetLen, 
        PWINDIVERT_IPHDR* ppIpHdr,
        PWINDIVERT_IPV6HDR* ppIpv6Hdr, UINT8* pProtocol, PWINDIVERT_ICMPHDR* ppIcmpHdr,
        PWINDIVERT_ICMPV6HDR* ppIcmpv6Hdr, PWINDIVERT_TCPHDR* ppTcpHdr,
        PWINDIVERT_UDPHDR* ppUdpHdr, PVOID* ppData, UINT* pDataLen,
        PVOID* ppNext, UINT* pNextLen)
    {
        return m_winDiverLib->m_WinDivertHelperParsePacket(pPacket, packetLen, ppIpHdr, 
                                                           ppIpv6Hdr, pProtocol, ppIcmpHdr, 
                                                           ppIcmpv6Hdr, ppTcpHdr, ppUdpHdr, 
                                                           ppData, pDataLen, ppNext, pNextLen);
    }

    bool WinDivert::WinDivertHelperParsePacket(const std::vector<char>& packet, 
                                               std::vector<WinDivertPacket>& winDivertPackets)
    {
        bool result = false;;
        WinDivertPacket winDivertPacket = {0};
        const char* pPacket = packet.data();
        UINT packetSize = packet.size();
        char* pNextPacket = nullptr;
        UINT nextPacketSize = 0;
        UINT pDataLen = 0;
        while (pPacket && packetSize)
        {
            result = WinDivertHelperParsePacket(pPacket, packetSize, &winDivertPacket.pIpHdr,
                &winDivertPacket.pIpv6Hdr, &winDivertPacket.Protocol, &winDivertPacket.pIcmpHdr,
                &winDivertPacket.pIcmpv6Hdr, &winDivertPacket.pTcpHdr, &winDivertPacket.pUdpHdr,
                &winDivertPacket.pData, &winDivertPacket.DataLen, (PVOID*)&pNextPacket, &nextPacketSize);

            if (!result)
            {
                break;
            }

            winDivertPackets.push_back(winDivertPacket);
            memset(&winDivertPacket, 0, sizeof(WinDivertPacket));

            pPacket = pNextPacket;
            packetSize = nextPacketSize;
        }
        return result;
    }

    bool WinDivert::WinDivertHelperParseIPv4Address(const std::string& addrStr, uint32_t& pAddr)
    {
        return m_winDiverLib->m_WinDivertHelperParseIPv6Address(addrStr.c_str(), &pAddr);
    }

    bool WinDivert::WinDivertHelperParseIPv6Address(const std::string& addrStr,
        std::vector<uint32_t>& pAddr)
    {
        if (pAddr.size() < 4)
        {
            return false;
        }
        return m_winDiverLib->m_WinDivertHelperParseIPv6Address(addrStr.c_str(), pAddr.data());
    }

    bool WinDivert::WinDivertHelperFormatIPv4Address(uint32_t addr, std::vector<char>& buffer)
    {
        return m_winDiverLib->m_WinDivertHelperFormatIPv4Address(addr, buffer.data(), buffer.size());
    }

    bool WinDivert::WinDivertHelperFormatIPv6Address(const std::vector<uint32_t>& pAddr, 
                                                     std::vector<char>& buffer)
    {
        if (pAddr.size() < 4)
        {
            return false;
        }
        return m_winDiverLib->m_WinDivertHelperFormatIPv6Address(pAddr.data(), buffer.data(), buffer.size());
    }

    bool WinDivert::WinDivertHelperCalcChecksums(std::vector<char>& packet, 
                                                 WINDIVERT_ADDRESS* pAddr,
                                                 uint64_t flags)
    {
        return m_winDiverLib->m_WinDivertHelperCalcChecksums(packet.data(), packet.size(), pAddr, flags);
    }

    bool WinDivert::WinDivertHelperDecrementTTL(std::vector<char>& packet)
    {
        return m_winDiverLib->m_WinDivertHelperDecrementTTL(packet.data(), packet.size());
    }

    bool WinDivert::WinDivertHelperCompileFilter(const std::string& filter, ::WINDIVERT_LAYER layer,
        std::vector<char>& object, std::string& errorStr, uint32_t& errorPos)
    {
        const char* errorCStr = nullptr;
        bool success = m_winDiverLib->m_WinDivertHelperCompileFilter(filter.c_str(), layer,
            object.data(), object.size(), &errorCStr, &errorPos);
        
        if (!success && errorCStr != nullptr)
        {
            errorStr.assign(errorCStr);
        }
        return success;
    }

    void WinDivert::WinDivertHelperEvalFilter(const std::string& filter, 
                                              const std::vector<char>& packet,
                                              const ::WINDIVERT_ADDRESS* pAddr)
    {
        if (!m_winDiverLib->m_WinDivertHelperEvalFilter(filter.c_str(), packet.data(), 
                                                        packet.size(), pAddr))
        {
            throw WinApiException("WinDivertHelperEvalFilter failed.");
        }
    }

    void WinDivert::WinDivertHelperFormatFilter(const std::string& filter, ::WINDIVERT_LAYER layer,
                                                std::vector<char>& buffer)
    {
        if (!m_winDiverLib->m_WinDivertHelperFormatFilter(filter.c_str(), layer, 
            buffer.data(), buffer.size()))
        {
            throw WinApiException("WinDivertHelperFormatFilter failed.");
        }
    }

    uint16_t WinDivert::WinDivertHelperNtohs(uint16_t x)
    {
        return m_winDiverLib->m_WinDivertHelperNtohs(x);
    }

    uint16_t WinDivert::WinDivertHelperHtons(uint16_t x)
    {
        return m_winDiverLib->m_WinDivertHelperHtons(x);
    }

    uint32_t WinDivert::WinDivertHelperNtohl(uint32_t x)
    {
        return m_winDiverLib->m_WinDivertHelperNtohl(x);
    }

    uint32_t WinDivert::WinDivertHelperHtonl(uint32_t x)
    {
        return m_winDiverLib->m_WinDivertHelperHtonl(x);
    }

    uint64_t WinDivert::WinDivertHelperNtohll(uint64_t x)
    {
        return m_winDiverLib->m_WinDivertHelperNtohll(x);
    }

    uint64_t WinDivert::WinDivertHelperHtonll(uint64_t x)
    {
        return m_winDiverLib->m_WinDivertHelperHtonll(x);
    }

    void WinDivert::WinDivertHelperNtohIPv6Address(const uint32_t inAddr, uint32_t& outAddr)
    {
        m_winDiverLib->m_WinDivertHelperNtohIPv6Address(&inAddr, &outAddr);
    }

    void WinDivert::WinDivertHelperHtonIPv6Address(const uint32_t inAddr, uint32_t& outAddr)
    {
        m_winDiverLib->m_WinDivertHelperHtonIPv6Address(&inAddr, &outAddr);
    }

    void WinDivert::WinDivertHelperNtohIpv6Address(const uint32_t inAddr, uint32_t& outAddr)
    {
        m_winDiverLib->m_WinDivertHelperNtohIpv6Address(&inAddr, &outAddr);
    }

    void WinDivert::WinDivertHelperHtonIpv6Address(const uint32_t inAddr, uint32_t& outAddr)
    {
        m_winDiverLib->m_WinDivertHelperHtonIpv6Address(&inAddr, &outAddr);
    }
}
