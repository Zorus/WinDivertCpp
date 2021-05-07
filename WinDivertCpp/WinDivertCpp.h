#pragma once
#include <filesystem>
#include <chrono>
#include "WinDivertLib.h"
#include "WinDivertExceptions.h"

namespace WinDivertCpp
{

    class OverlappedEvent
    {
    public:
        typedef std::chrono::milliseconds TimeoutType;
    private:
        HANDLE m_handle;
    public:
        OverlappedEvent()
            :m_handle(INVALID_HANDLE_VALUE)
        {
            m_handle = ::CreateEventW(0, false, false, 0);
            if (m_handle == INVALID_HANDLE_VALUE)
            {
                throw WinApiException("CreateEventW failed.");
            }
        }

        HANDLE GetNativeHandle()
        {
            return m_handle;
        }

        bool Set() { return ::SetEvent(m_handle); }

        bool Reset() { return ::ResetEvent(m_handle);  }

        int32_t Wait(const TimeoutType& timeOut)
        {
            DWORD timeOutNative = static_cast<DWORD>(timeOut.count());
            return ::WaitForSingleObject(m_handle, timeOutNative);
        }

        ~OverlappedEvent()
        {
            if (m_handle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(m_handle);
            }
        }
    };

    struct WinDivertPacket
    {
        PWINDIVERT_IPHDR pIpHdr;
        PWINDIVERT_IPV6HDR pIpv6Hdr;
        UINT8 Protocol;
        PWINDIVERT_ICMPHDR pIcmpHdr;
        PWINDIVERT_ICMPV6HDR pIcmpv6Hdr;
        PWINDIVERT_TCPHDR pTcpHdr;
        PWINDIVERT_UDPHDR pUdpHdr;
        PVOID pData;
        UINT DataLen;
    };

    class WinDivert
    {
    private:
        std::shared_ptr<WinDivertLib> m_winDiverLib;
        HANDLE m_winDivertHandle;
    private:
        bool CheckHandle(bool silent = false);
    public:
        WinDivert(std::filesystem::path baseDir);
        WinDivert(std::shared_ptr<WinDivertLib> winDiverLib);
        virtual ~WinDivert();

        //Win Divert API
        void WinDivertOpen(const std::string& filter, ::WINDIVERT_LAYER layer, 
                           int16_t priority, uint64_t flags);

        void WinDivertRecv(std::vector<char> &packet, ::WINDIVERT_ADDRESS* pAddr);

        uint32_t WinDivertRecvEx(std::vector<char>& packet, uint64_t flags,
                                 std::vector<::WINDIVERT_ADDRESS> &pAddr, 
                                 OverlappedEvent* overlappedEvent,
                                 OverlappedEvent::TimeoutType ioTimeOut);

        uint32_t WinDivertSend(const std::vector<char>& packet, const ::WINDIVERT_ADDRESS* pAddr);

        uint32_t WinDivertSendEx(const std::vector<char>& packet, uint64_t flags,
                                const std::vector<::WINDIVERT_ADDRESS>& pAddr,
                                OverlappedEvent* overlappedEvent,
                                OverlappedEvent::TimeoutType ioTimeOut);

        void WinDivertShutdown(::WINDIVERT_SHUTDOWN how);

        bool WinDivertClose();
        
        bool WinDivertSetParam(::WINDIVERT_PARAM param, uint64_t value);

        bool WinDivertGetParam(::WINDIVERT_PARAM param, uint64_t& outValue);

        uint64_t WinDivertHelperHashPacket(const std::vector<char>& packet, uint64_t seed = 0);

        bool WinDivertHelperParsePacket(const void* pPacket, UINT packetLen, PWINDIVERT_IPHDR* ppIpHdr,
            PWINDIVERT_IPV6HDR* ppIpv6Hdr, UINT8* pProtocol,PWINDIVERT_ICMPHDR* ppIcmpHdr, 
            PWINDIVERT_ICMPV6HDR* ppIcmpv6Hdr, PWINDIVERT_TCPHDR* ppTcpHdr,
            PWINDIVERT_UDPHDR* ppUdpHdr, PVOID* ppData, UINT* pDataLen,
            PVOID* ppNext, UINT* pNextLen);

        bool WinDivertHelperParsePacket(const std::vector<char>& packet, 
                                        std::vector<WinDivertPacket> &winDivertPackets);

        bool WinDivertHelperParseIPv4Address(const std::string& addrStr, uint32_t& pAddr);

        bool WinDivertHelperParseIPv6Address(const std::string& addrStr, std::vector<uint32_t> &pAddr);

        bool WinDivertHelperFormatIPv4Address(uint32_t addr, std::vector<char>& buffer);

        bool WinDivertHelperFormatIPv6Address(const  std::vector<uint32_t>& pAddr, std::vector<char>& buffer);

        bool WinDivertHelperCalcChecksums(std::vector<char>& packet, WINDIVERT_ADDRESS* pAddr, 
                                          uint64_t flags);

        bool WinDivertHelperDecrementTTL(std::vector<char>& packet);

        bool WinDivertHelperCompileFilter(const std::string& filter, ::WINDIVERT_LAYER layer, 
                                          std::vector<char>& object, std::string& errorStr, 
                                          uint32_t& errorPos);

        void WinDivertHelperEvalFilter(const std::string& filter, const std::vector<char>& packet, 
                                       const ::WINDIVERT_ADDRESS* pAddr);
        
        void WinDivertHelperFormatFilter(const std::string& filter, ::WINDIVERT_LAYER layer, 
                                         std::vector<char>& buffer);
        
        uint16_t WinDivertHelperNtohs(uint16_t x);
        
        uint16_t WinDivertHelperHtons(uint16_t x);
        
        uint32_t WinDivertHelperNtohl(uint32_t x);
        
        uint32_t WinDivertHelperHtonl(uint32_t x);
        
        uint64_t WinDivertHelperNtohll(uint64_t x);
        
        uint64_t WinDivertHelperHtonll(uint64_t x);
        
        void WinDivertHelperNtohIPv6Address(const uint32_t inAddr, uint32_t& outAddr);
        
        void WinDivertHelperHtonIPv6Address(const uint32_t inAddr, uint32_t& outAddr);
        
        void WinDivertHelperNtohIpv6Address(const uint32_t inAddr, uint32_t& outAddr);
        
        void WinDivertHelperHtonIpv6Address(const uint32_t inAddr, uint32_t& outAddr);
    };

}
