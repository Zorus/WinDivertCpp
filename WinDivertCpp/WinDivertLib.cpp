#include "WinDivertLib.h"


namespace WinDivertCpp
{
    WinDivertLib::WinDivertLib(std::filesystem::path baseDir)
        :m_winDiverDllName(L"WinDivert.dll")
    {
        auto fullPathToWinDiverDll = baseDir / m_winDiverDllName;
        m_winDivertLib.load(fullPathToWinDiverDll.c_str());
        m_WinDivertOpen = m_winDivertLib.get<decltype(::WinDivertOpen)>("WinDivertOpen");
        m_WinDivertRecv = m_winDivertLib.get<decltype(::WinDivertRecv)>("WinDivertRecv");
        m_WinDivertRecvEx = m_winDivertLib.get<decltype(::WinDivertRecvEx)>("WinDivertRecvEx");
        m_WinDivertSend = m_winDivertLib.get<decltype(::WinDivertSend)>("WinDivertSend");
        m_WinDivertSendEx = m_winDivertLib.get<decltype(::WinDivertSendEx)>("WinDivertSendEx");
        m_WinDivertShutdown = m_winDivertLib.get<decltype(::WinDivertShutdown)>("WinDivertShutdown");
        m_WinDivertClose = m_winDivertLib.get<decltype(::WinDivertClose)>("WinDivertClose");
        m_WinDivertSetParam = m_winDivertLib.get<decltype(::WinDivertSetParam)>("WinDivertSetParam");
        m_WinDivertGetParam = m_winDivertLib.get<decltype(::WinDivertGetParam)>("WinDivertGetParam");
        m_WinDivertHelperHashPacket = m_winDivertLib.get<decltype(::WinDivertHelperHashPacket)>("WinDivertHelperHashPacket");
        m_WinDivertHelperParsePacket = m_winDivertLib.get<decltype(::WinDivertHelperParsePacket)>("WinDivertHelperParsePacket");
        m_WinDivertHelperParseIPv4Address = m_winDivertLib.get<decltype(::WinDivertHelperParseIPv4Address)>("WinDivertHelperParseIPv4Address");
        m_WinDivertHelperParseIPv6Address = m_winDivertLib.get<decltype(::WinDivertHelperParseIPv6Address)>("WinDivertHelperParseIPv6Address");
        m_WinDivertHelperFormatIPv4Address = m_winDivertLib.get<decltype(::WinDivertHelperFormatIPv4Address)>("WinDivertHelperFormatIPv4Address");
        m_WinDivertHelperFormatIPv6Address = m_winDivertLib.get<decltype(::WinDivertHelperFormatIPv6Address)>("WinDivertHelperFormatIPv6Address");
        m_WinDivertHelperCalcChecksums = m_winDivertLib.get<decltype(::WinDivertHelperCalcChecksums)>("WinDivertHelperCalcChecksums");
        m_WinDivertHelperDecrementTTL = m_winDivertLib.get<decltype(::WinDivertHelperDecrementTTL)>("WinDivertHelperDecrementTTL");
        m_WinDivertHelperCompileFilter = m_winDivertLib.get<decltype(::WinDivertHelperCompileFilter)>("WinDivertHelperCompileFilter");
        m_WinDivertHelperEvalFilter = m_winDivertLib.get<decltype(::WinDivertHelperEvalFilter)>("WinDivertHelperEvalFilter");
        m_WinDivertHelperFormatFilter = m_winDivertLib.get<decltype(::WinDivertHelperFormatFilter)>("WinDivertHelperFormatFilter");
        m_WinDivertHelperNtohs = m_winDivertLib.get<decltype(::WinDivertHelperNtohs)>("WinDivertHelperNtohs");
        m_WinDivertHelperHtons = m_winDivertLib.get<decltype(::WinDivertHelperHtons)>("WinDivertHelperHtons");
        m_WinDivertHelperNtohl = m_winDivertLib.get<decltype(::WinDivertHelperNtohl)>("WinDivertHelperNtohl");
        m_WinDivertHelperHtonl = m_winDivertLib.get<decltype(::WinDivertHelperHtonl)>("WinDivertHelperHtonl");
        m_WinDivertHelperNtohll = m_winDivertLib.get<decltype(::WinDivertHelperNtohll)>("WinDivertHelperNtohll");
        m_WinDivertHelperHtonll = m_winDivertLib.get<decltype(::WinDivertHelperHtonll)>("WinDivertHelperHtonll");
        m_WinDivertHelperNtohIPv6Address = m_winDivertLib.get<decltype(::WinDivertHelperNtohIPv6Address)>("WinDivertHelperNtohIPv6Address");
        m_WinDivertHelperHtonIPv6Address = m_winDivertLib.get<decltype(::WinDivertHelperHtonIPv6Address)>("WinDivertHelperHtonIPv6Address");
        m_WinDivertHelperNtohIpv6Address = m_winDivertLib.get<decltype(::WinDivertHelperNtohIpv6Address)>("WinDivertHelperNtohIpv6Address");
        m_WinDivertHelperHtonIpv6Address = m_winDivertLib.get<decltype(::WinDivertHelperHtonIpv6Address)>("WinDivertHelperHtonIpv6Address");
    }
}