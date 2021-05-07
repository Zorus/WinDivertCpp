#include <iostream>
#include <filesystem>
#include <thread>
#include <chrono>
#include "WinDivertCpp.h"

static std::atomic_int32_t g_recivedCount = 0;

void Filter(WinDivertCpp::WinDivert* winDivert, 
            const std::vector<WinDivertCpp::WinDivertPacket>& parsedRecvPackets,
            const std::vector<char>& recvPacketsRaw, 
            const std::vector<::WINDIVERT_ADDRESS>& recvAddrs, 
            std::vector<char>& sendPacketsRaw, 
            std::vector<::WINDIVERT_ADDRESS>& sendAddrs)
{
    sendPacketsRaw = recvPacketsRaw;
    sendAddrs = recvAddrs;
    g_recivedCount += parsedRecvPackets.size();
}

void PrintRevicedPackets()
{
    while (true)
    {
        if (g_recivedCount)
        {
            std::cout << "Packets handled count : " << std::to_string(g_recivedCount) << std::endl;
            g_recivedCount = 0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        auto baseDirectory = std::filesystem::weakly_canonical(std::filesystem::path(argv[0])).parent_path();
        auto winDiver = std::make_unique<WinDivertCpp::WinDivert>(baseDirectory);

        std::string filterRuleString = "tcp";
        std::string errorString;
        std::vector<char> obejct;
        uint32_t errorPos = 0;

        if (!winDiver->WinDivertHelperCompileFilter(filterRuleString, WINDIVERT_LAYER::WINDIVERT_LAYER_NETWORK,
            obejct, errorString, errorPos))
        {
            throw std::runtime_error(errorString);
        }
        
        winDiver->WinDivertOpen(filterRuleString, WINDIVERT_LAYER::WINDIVERT_LAYER_NETWORK, 0, 0);

        winDiver->WinDivertSetParam(WINDIVERT_PARAM::WINDIVERT_PARAM_QUEUE_LENGTH, 1000);
        winDiver->WinDivertSetParam(WINDIVERT_PARAM::WINDIVERT_PARAM_QUEUE_SIZE, 33554432);
        winDiver->WinDivertSetParam(WINDIVERT_PARAM::WINDIVERT_PARAM_QUEUE_TIME, 5000);
        
        std::vector<char> recvPacketsRaw;
        std::vector<WINDIVERT_ADDRESS> recvAddrs;
        
        std::vector<char> sendPacketsRaw;
        std::vector<WINDIVERT_ADDRESS> sendAddrs;
        
        WinDivertCpp::OverlappedEvent overlapedEvent;
        std::vector<WinDivertCpp::WinDivertPacket> parsedRecvPackets;
        auto maxTimeoutForIO = WinDivertCpp::OverlappedEvent::TimeoutType(1000000);

        std::cout << "Filter rule: \"" << filterRuleString <<"\"" << std::endl;
        std::thread printThread(PrintRevicedPackets);

        while (true)
        {            
            recvPacketsRaw.resize(WINDIVERT_BATCH_MAX * 1500);
            recvAddrs.resize(WINDIVERT_BATCH_MAX);
            parsedRecvPackets.resize(0);

            winDiver->WinDivertRecvEx(recvPacketsRaw, 0, 
                                      recvAddrs,
                                      &overlapedEvent,
                                      maxTimeoutForIO);

            if (!winDiver->WinDivertHelperParsePacket(recvPacketsRaw, parsedRecvPackets))
            {
                throw std::runtime_error("WinDivertHelperParsePacket failed.");
            }

            Filter(winDiver.get(), parsedRecvPackets, recvPacketsRaw, recvAddrs, sendPacketsRaw, sendAddrs);

            if (sendPacketsRaw.size() > 0 && sendAddrs.size() > 0)
            {
                winDiver->WinDivertSendEx(sendPacketsRaw, 0, sendAddrs,
                    &overlapedEvent, maxTimeoutForIO);

                sendPacketsRaw.resize(0);
                sendAddrs.resize(0);
            }
        }
       
    }
    catch (std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        std::system("pause");
        return 1;
    }
    return 0;
}

