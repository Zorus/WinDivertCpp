#pragma once
#include <exception>
#include <system_error>
#include <windows.h>

namespace WinDivertCpp
{
    class WinApiException : public std::exception
    {
    private:
         uint32_t m_lastError;
         std::string m_lastErrorMessage;
         std::string m_clientMessage;
         std::string m_whatMessage;
    public:
        WinApiException(uint32_t lastError, const std::string& clientMessage)
            : m_lastError(lastError), m_clientMessage(clientMessage)
        {
            if (m_lastError != 0) {
              m_lastErrorMessage = std::system_category().message(m_lastError);
            }
            m_whatMessage = m_clientMessage;
            m_whatMessage += " Error code: " + std::to_string(m_lastError);
            m_whatMessage += " Error description: " + m_lastErrorMessage;
        }

        WinApiException(const std::string& clientMessage)
            : m_lastError(::GetLastError()), m_clientMessage(clientMessage)
        {
            if (m_lastError != 0) {
                m_lastErrorMessage = std::system_category().message(m_lastError);
            }
            m_whatMessage = m_clientMessage;
            m_whatMessage += " Error code: " + std::to_string(m_lastError);
            m_whatMessage += " Error description: " + m_lastErrorMessage;
        }

        uint32_t GetLastErrorValue()
        {
            return m_lastError;
        }

        const char* what() const throw ()
        {
            return m_whatMessage.c_str();
        }
    };

    class TimeoutException : public std::exception
    {
    private:
        std::string m_clientMessage;
        std::string m_whatMessage;
    public:
        TimeoutException(const std::string& clientMessage)
            : m_clientMessage(clientMessage)
        {
            m_whatMessage = "Time out was occurred. Message: " + m_clientMessage;

        }

        const char* what() const throw ()
        {
            return m_whatMessage.c_str();
        }
    };
}