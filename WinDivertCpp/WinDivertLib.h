#pragma once

#include <functional>
#include <filesystem>
#include <boost/dll/shared_library.hpp>
#include "windivert.h"

namespace WinDivertCpp
{
    class WinDivertLib
    {
    private:
        boost::dll::shared_library m_winDivertLib;
        const std::filesystem::path m_winDiverDllName;
    public:
        std::function<decltype(WinDivertOpen)> m_WinDivertOpen;
        std::function<decltype(WinDivertRecv)> m_WinDivertRecv;
        std::function<decltype(WinDivertRecvEx)> m_WinDivertRecvEx;
        std::function<decltype(WinDivertSend)> m_WinDivertSend;
        std::function<decltype(WinDivertSendEx)> m_WinDivertSendEx;
        std::function<decltype(WinDivertShutdown)> m_WinDivertShutdown;
        std::function<decltype(WinDivertClose)> m_WinDivertClose;
        std::function<decltype(WinDivertSetParam)> m_WinDivertSetParam;
        std::function<decltype(WinDivertGetParam)> m_WinDivertGetParam;
        std::function<decltype(WinDivertHelperHashPacket)> m_WinDivertHelperHashPacket;
        std::function<decltype(WinDivertHelperParsePacket)> m_WinDivertHelperParsePacket;
        std::function<decltype(WinDivertHelperParseIPv4Address)> m_WinDivertHelperParseIPv4Address;
        std::function<decltype(WinDivertHelperParseIPv6Address)> m_WinDivertHelperParseIPv6Address;
        std::function<decltype(WinDivertHelperFormatIPv4Address)> m_WinDivertHelperFormatIPv4Address;
        std::function<decltype(WinDivertHelperFormatIPv6Address)> m_WinDivertHelperFormatIPv6Address;
        std::function<decltype(WinDivertHelperCalcChecksums)> m_WinDivertHelperCalcChecksums;
        std::function<decltype(WinDivertHelperDecrementTTL)> m_WinDivertHelperDecrementTTL;
        std::function<decltype(WinDivertHelperCompileFilter)> m_WinDivertHelperCompileFilter;
        std::function<decltype(WinDivertHelperEvalFilter)> m_WinDivertHelperEvalFilter;
        std::function<decltype(WinDivertHelperFormatFilter)> m_WinDivertHelperFormatFilter;
        std::function<decltype(WinDivertHelperNtohs)> m_WinDivertHelperNtohs;
        std::function<decltype(WinDivertHelperHtons)> m_WinDivertHelperHtons;
        std::function<decltype(WinDivertHelperNtohl)> m_WinDivertHelperNtohl;
        std::function<decltype(WinDivertHelperHtonl)> m_WinDivertHelperHtonl;
        std::function<decltype(WinDivertHelperNtohll)> m_WinDivertHelperNtohll;
        std::function<decltype(WinDivertHelperHtonll)> m_WinDivertHelperHtonll;
        std::function<decltype(WinDivertHelperNtohIPv6Address)> m_WinDivertHelperNtohIPv6Address;
        std::function<decltype(WinDivertHelperHtonIPv6Address)> m_WinDivertHelperHtonIPv6Address;
        std::function<decltype(WinDivertHelperNtohIpv6Address)> m_WinDivertHelperNtohIpv6Address;
        std::function<decltype(WinDivertHelperHtonIpv6Address)> m_WinDivertHelperHtonIpv6Address;
    public:
        WinDivertLib(std::filesystem::path baseDir);
    };
}