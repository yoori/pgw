#include <iostream>
#include <sstream>

#include <gears/Time.hpp>

#include <ndpi/ndpi_config.h>
#include <ndpi_api.h>

#include "NetworkUtils.hpp"
#include "PacketProcessor.hpp"
#include "MainUserSessionPacketProcessor.hpp"

namespace dpi
{
  PacketProcessor::PacketProcessor(
    UserStoragePtr user_storage,
    UserSessionPacketProcessorPtr user_session_packet_processor,
    LoggerPtr event_logger)
    : user_storage_(user_storage),
      event_logger_(event_logger),
      unknown_session_key_("unknown", std::string()),
      user_session_packet_processor_(std::move(user_session_packet_processor))
  {
    ip_categories_.emplace(string_to_ipv4_address("194.54.14.131"), "sber-online"); // online.sberbank.ru
    ip_categories_.emplace(string_to_ipv4_address("95.181.181.241"), "sber-online"); // app.sberbank.ru

    ip_categories_.emplace(string_to_ipv4_address("10.65.2.100"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("10.65.37.11"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.10"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.100"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.119"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.121"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.123"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.170"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.177"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.38"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.41"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.46"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.57"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.62"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.1.98"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.2.167"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.4.162"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.4.98"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.8.126"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.8.127"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.8.129"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.8.78"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.8.80"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("109.207.9.85"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("127.0.0.1"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("158.160.126.140"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("172.16.37.16"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("172.26.80.207"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("185.76.232.240"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("185.76.232.244"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("185.76.234.246"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("185.76.234.248"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("193.228.109.239"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("212.193.155.52"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.235.104"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.253.1"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.253.21"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.253.4"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.253.40"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.253.7"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.253.8"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.254.2"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.254.21"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.254.6"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.254.7"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("213.59.255.175"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.114"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.115"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.117"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.122"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.144"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.145"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.146"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.147"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.148"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.149"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.151"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.152"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.153"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.154"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.156"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.157"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.108.159"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("217.107.111.67"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("2.63.211.50"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("46.61.180.24"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("46.61.180.82"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("46.61.234.164"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("85.143.127.91"), "gosuslugi");
    ip_categories_.emplace(string_to_ipv4_address("85.143.161.164"), "gosuslugi");

    ip_categories_.emplace(string_to_ipv4_address("217.12.97.98"), "alfabank-online"); // zp-auth.alfabank.ru
    ip_categories_.emplace(string_to_ipv4_address("217.12.98.59"), "alfabank-online"); // mobile.auth.alfabank.ru
    ip_categories_.emplace(string_to_ipv4_address("217.12.105.56"), "alfabank-online"); // oauthap.alfabank.ru
    ip_categories_.emplace(string_to_ipv4_address("217.12.105.159"), "alfabank-online"); // tmobile.auth.alfabank.ru
    ip_categories_.emplace(string_to_ipv4_address("217.12.104.100"), "alfabank-online"); // mobileapp.alfabank.ru

    ip_categories_.emplace(string_to_ipv4_address("10.41.64.35"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("151.236.118.131"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("176.57.64.139"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("176.57.64.212"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("176.57.65.144"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("178.176.128.128"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("178.18.218.197"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("178.18.218.45"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("178.18.218.6"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("178.18.218.73"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("185.129.100.112"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("185.130.249.90"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("185.169.155.100"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("185.169.155.114"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("185.169.155.116"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("185.169.155.118"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("185.215.4.49"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("46.243.142.176"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("54.194.41.141"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("81.19.72.47"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("81.19.73.10"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("88.210.36.195"), "okko");
    ip_categories_.emplace(string_to_ipv4_address("93.171.230.8"), "okko");

    ip_categories_.emplace(string_to_ipv4_address("162.159.140.159"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("172.66.0.157"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("178.170.192.49"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("178.170.194.49"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("178.170.196.67"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("185.215.4.20"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("185.215.4.46"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("45.140.178.240"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("46.243.142.191"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("46.4.70.151"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("52.223.52.2"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("77.223.119.56"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("81.163.18.244"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("81.19.86.29"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("88.212.206.92"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("88.212.208.181"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("91.221.164.186"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("91.221.164.187"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("91.221.164.208"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("94.139.253.7"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("94.139.255.99"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("95.181.182.182"), "zvuk");
    ip_categories_.emplace(string_to_ipv4_address("91.221.164.24"), "zvuk");

    ip_categories_.emplace(string_to_ipv4_address("104.124.173.129"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.211.73.16"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.212.83.118"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.212.83.120"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.40.144.210"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.40.159.215"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.40.75.8"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.40.89.180"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.42.191.226"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("104.43.246.71"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("108.141.225.102"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("108.141.230.141"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("108.141.74.134"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("108.142.42.2"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("127.0.0.1"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("130.211.29.77"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.242.32"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.246.45"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.246.64"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.246.67"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.246.69"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.253.43"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.3.128"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.42.16"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.60.2"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.6.158"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.7.192"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.8.10"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.8.155"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.8.2"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.107.8.5"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.18.111"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.18.112"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.18.138"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.18.179"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.18.180"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.18.212"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.18.54"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("134.170.20.10"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("135.225.15.79"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("135.236.138.14"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("135.236.193.4"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("135.236.38.153"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("135.236.41.42"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("136.147.129.25"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("136.147.129.27"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("136.147.129.32"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.64.215.13"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.64.215.82"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.67.9.3"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.69.170.44"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.69.188.145"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.73.52.164"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.74.129.1"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.75.143.139"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.84.156.165"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.85.19.37"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.88.115.63"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.88.185.224"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.88.191.224"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("138.91.190.196"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("138.91.253.116"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.89.179.11"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.90.148.156"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("13.93.161.37"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("152.199.21.175"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.169.169.239"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.169.44.52"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.171.32.58"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.171.32.72"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.176.213.114"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.205.44.37"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.206.157.204"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("172.211.216.183"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("184.31.60.188"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("191.238.173.137"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.101.115.129"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.101.163.76"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.103.247.119"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.105.117.101"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.105.25.48"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.105.88.72"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.109.156.223"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.110.200.128"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.114.107.106"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.117.72.216"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.118.102.181"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.118.103.23"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.119.144.20"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.120.75.37"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.121.89.114"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.122.189.1"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.123.230.128"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.123.36.134"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.13.114.124"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.13.176.105"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.17.224.55"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.18.102.159"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.185.212.106"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.188.37.1"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.19.155.222"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.191.55.71"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.192.4.101"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.194.203.22"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.202.68.108"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.202.68.75"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.212.49.7"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.22.85.65"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.231.239.246"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.23.186.233"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.232.142.102"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.234.159.93"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.234.18.178"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.236.44.162"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.237.116.146"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.237.152.230"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.237.153.7"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.238.189.69"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.24.152.66"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.241.91.64"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.242.149.201"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.249.115.93"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.250.201.97"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.253.0.48"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.253.197.93"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.253.38.31"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.27.162.87"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.31.205.53"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.42.128.97"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.49.104.0"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("204.9.163.165"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.50.2.13"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.50.2.9"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.59.119.153"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.61.224.180"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.62.107.96"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.63.60.79"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.65.29.234"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.65.30.61"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.67.112.184"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.67.167.63"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.69.212.106"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.70.246.20"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.7.16.52"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.73.131.253"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.74.55.21"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.76.201.171"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.81.107.57"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.8.190.112"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.8.206.151"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.86.114.141"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.89.21.28"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.9.117.196"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.97.167.181"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("20.98.60.178"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.101.135.34"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.101.156.198"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.101.158.111"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.192.16.208"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.212.62.69"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.50.67.28"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.53.112.170"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.54.179.54"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("23.99.206.110"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.114.140.1"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.121.85.174"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.122.53.239"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.68.168.231"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.69.136.133"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.70.186.239"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.74.203.22"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.74.245.188"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.77.70.98"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.78.7.27"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.78.95.144"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.83.48.248"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("40.84.211.9"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.144.130.57"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.174.161.142"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.175.117.0"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.176.22.72"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.189.10.248"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.189.11.196"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.189.11.48"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.189.3.135"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.189.41.169"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.190.8.146"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.207.107.19"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.207.171.93"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.207.198.73"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.207.219.160"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.208.0.231"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.208.35.47"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.208.42.221"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.208.67.162"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.208.67.175"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.208.97.29"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.225.88.52"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.231.145.19"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.245.161.11"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.245.83.14"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.248.229.123"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.249.137.46"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("4.255.41.232"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("48.209.157.42"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("48.209.158.146"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("48.211.184.157"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("48.211.186.254"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("48.217.130.246"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("48.218.194.39"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("48.218.194.55"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.105.121.165"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.105.176.200"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.105.197.129"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.105.251.252"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.105.98.241"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.124.129.124"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.124.149.2"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.140.59.67"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.141.118.150"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.143.123.249"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("51.144.252.171"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.101.2"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.103.22"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.103.25"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.103.29"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.103.4"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.112.59"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.112.66"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.114.44"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.114.50"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.120.186"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.120.237"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.120.84"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.126.11"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.127.108"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.22.3"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.22.4"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.229.75"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.229.77"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.23.20"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.23.26"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.23.27"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.101"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.143"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.144"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.145"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.146"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.147"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.148"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.237"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.239"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.48"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.49"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.50"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.94"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.96"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.238.97"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.39.21"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.39.22"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.39.23"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.49.49"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.49.55"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.49.67"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.54.38"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.54.39"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.72.27"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.74.25"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.74.32"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.123"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.63"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.65"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.66"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.73"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.78"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.79"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.80"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.81"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.86.82"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.112.99.0"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.113.194.131"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.113.194.132"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.113.194.133"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.113.195.133"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.10.87"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.13.31"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.13.37"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.136.178"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.138.12"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.144.187"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.144.188"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.144.53"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.151.65"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.158.33"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.158.44"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.159.179"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.159.186"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.159.194"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.159.198"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.160.191"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.160.203"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.169.24"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.169.25"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.169.26"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.170.175"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.170.179"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.170.180"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.170.196"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.170.201"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.173.121"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.173.122"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.173.123"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.173.124"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.173.125"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.181.75"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.181.87"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.18.38"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.185.125"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.187.215"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.189.16"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.189.22"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.190.16"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.123.242.214"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.142.186.92"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.155.91.254"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.155.92.58"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.155.93.159"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.160.125.228"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.164.201.186"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.164.218.3"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.165.37.214"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.167.81.255"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.168.117.171"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.168.123.96"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.172.150.72"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.174.26.253"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.174.94.233"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.185.106.249"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.187.112.248"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.224.138.67"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.228.168.137"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.228.216.6"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.231.77.58"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.234.26.8"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.237.167.101"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.238.241.13"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.238.29.73"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("52.254.116.3"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("57.153.15.6"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("57.153.164.92"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("57.154.187.123"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("63.209.144.201"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.161"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.171"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.181"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.212"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.213"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.214"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.216"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.218"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.234"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.244"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.245"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.248"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.249"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.250"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.46.251"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.10"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.20"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.21"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.24"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.25"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.26"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.27"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.37"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.39"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.40"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.42"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.5"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.7"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("64.4.47.8"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("65.52.73.100"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("68.232.34.200"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("72.145.44.10"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("72.145.44.5"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("74.241.163.31"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("74.241.187.153"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("74.241.187.62"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("74.248.73.245"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("74.248.74.117"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("74.248.74.126"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("85.211.31.113"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("85.211.37.8"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("91.190.216.8"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("91.190.217.250"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("91.190.218.48"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("9.223.29.59"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("98.64.161.209"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("98.64.176.87"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("98.64.184.41"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("98.64.220.96"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("98.66.192.168"), "skype");
    ip_categories_.emplace(string_to_ipv4_address("98.66.244.235"), "skype");

    ip_categories_.emplace(string_to_ipv4_address("128.140.171.147"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("185.16.148.2"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("185.16.148.66"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("185.16.247.196"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("188.93.58.117"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.147.1"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.147.3"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.147.4"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.147.8"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.153.37"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.11"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.13"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.16"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.17"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.208"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.30"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.56"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.83"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.155.93"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.156.131"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.156.139"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.156.16"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.156.50"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("217.20.156.52"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("5.61.23.11"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("5.61.23.14"), "ok");
    ip_categories_.emplace(string_to_ipv4_address("5.61.23.9"), "ok");

    ip_categories_.emplace(string_to_ipv4_address("158.160.135.21"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("194.190.0.136"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("194.190.0.150"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("194.190.0.199"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("194.190.0.50"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("212.193.152.32"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("212.193.155.31"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("37.18.118.3"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("37.18.119.20"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("37.18.119.21"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("37.18.72.57"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("37.18.72.58"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("37.220.162.224"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("46.235.184.32"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("77.223.100.31"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("91.221.164.226"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("91.221.165.11"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("91.221.165.5"), "kuper");
    ip_categories_.emplace(string_to_ipv4_address("91.221.165.6"), "kuper");

    ip_categories_.emplace(string_to_ipv4_address("10.251.0.126"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("10.251.0.131"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("10.251.0.132"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("10.251.0.161"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("10.251.0.29"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("10.251.0.56"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("10.54.106.20"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("10.54.107.190"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("176.57.64.142"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("176.57.64.49"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("176.57.64.81"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("176.57.65.19"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("176.57.65.226"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("176.57.65.32"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("176.57.65.36"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("185.215.4.28"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("185.215.4.50"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("185.215.4.61"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("213.148.25.234"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("31.184.215.158"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("31.43.213.91"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("34.102.239.211"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("34.255.141.168"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("37.195.143.167"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("45.89.189.86"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("5.188.178.216"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("54.194.41.141"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("77.88.21.37"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("87.251.90.189"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.221.198.195"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.221.198.196"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.221.198.55"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.221.199.118"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.221.199.120"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.221.199.133"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.221.199.244"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.49.1"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.49.6"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.49.7"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.49.8"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.50.7"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.109"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.134"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.137"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.138"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.145"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.153"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.232"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.44"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.45"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.50"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.51"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.69"), "2gis");
    ip_categories_.emplace(string_to_ipv4_address("91.236.51.99"), "2gis");

    ip_categories_.emplace(string_to_ipv4_address("109.238.88.154"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("109.238.88.243"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("109.238.90.127"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("164.138.102.2"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("176.57.65.98"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("18.198.163.56"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("18.198.218.66"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("185.169.155.143"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("185.169.155.69"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("185.178.210.249"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("188.120.246.5"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("188.124.53.13"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("188.124.53.22"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("188.124.53.8"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("194.190.0.206"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("212.109.193.68"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("212.109.199.181"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("212.109.223.128"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("212.193.155.180"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("31.129.56.101"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("31.31.198.142"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("34.91.9.234"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("37.139.62.248"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("37.46.133.174"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("45.138.162.26"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("45.138.162.28"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("45.90.244.230"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("45.90.244.231"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("45.90.244.232"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("46.235.184.149"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("5.35.16.92"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("5.35.28.88"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("5.35.8.28"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("54.194.41.141"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("77.105.172.36"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("77.246.158.153"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("80.78.240.136"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("81.29.132.251"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("84.252.137.107"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("87.242.119.178"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("89.111.172.246"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("91.107.127.83"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("91.206.127.135"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("91.221.164.213"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("92.223.50.50"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("92.53.68.16"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("95.143.179.245"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("95.163.250.14"), "samokat");
    ip_categories_.emplace(string_to_ipv4_address("95.181.182.182"), "samokat");

    ip_categories_.emplace(string_to_ipv4_address("10.12.12.51"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("10.41.11.179"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("10.99.1.202"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("10.99.1.220"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("10.99.2.198"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("10.99.2.209"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("10.99.2.42"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("34.102.239.211"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("34.110.180.34"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("45.9.27.197"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("46.243.226.126"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.70.4"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.73.10"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.75.68"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.104"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.107"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.124"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.155"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.157"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.163"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.167"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.230"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.250"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.80"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.81"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.82"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.83"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.84"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.85"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.86"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.92"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.93"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.95"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.96"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.97"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.98"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.99"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("94.139.253.156"), "afisha");
    ip_categories_.emplace(string_to_ipv4_address("94.139.254.153"), "afisha");

    ip_categories_.emplace(string_to_ipv4_address("10.99.2.42"), "kassa.rambler");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.92"), "kassa.rambler");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.93"), "kassa.rambler");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.94"), "kassa.rambler");
    ip_categories_.emplace(string_to_ipv4_address("81.19.92.95"), "kassa.rambler");

    protocol_session_keys_.emplace(NDPI_PROTOCOL_UNKNOWN, SessionKey("unknown", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FTP_CONTROL, SessionKey("ftp_control", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MAIL_POP, SessionKey("mail_pop", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MAIL_SMTP, SessionKey("mail_smtp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MAIL_IMAP, SessionKey("mail_imap", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DNS, SessionKey("dns", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IPP, SessionKey("ipp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HTTP, SessionKey("http", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MDNS, SessionKey("mdns", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NTP, SessionKey("ntp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NETBIOS, SessionKey("netbios", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NFS, SessionKey("nfs", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SSDP, SessionKey("ssdp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BGP, SessionKey("bgp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SNMP, SessionKey("snmp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_XDMCP, SessionKey("xdmcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SMBV1, SessionKey("smbv1", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SYSLOG, SessionKey("syslog", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DHCP, SessionKey("dhcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_POSTGRES, SessionKey("postgres", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MYSQL, SessionKey("mysql", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MS_OUTLOOK, SessionKey("ms_outlook", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VK, SessionKey("vk", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MAIL_POPS, SessionKey("mail_pops", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TAILSCALE, SessionKey("tailscale", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX, SessionKey("yandex", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NTOP, SessionKey("ntop", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_COAP, SessionKey("coap", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VMWARE, SessionKey("vmware", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MAIL_SMTPS, SessionKey("mail_smtps", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DTLS, SessionKey("dtls", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_UBNTAC2, SessionKey("ubntac2", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BFCP, SessionKey("bfcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_MAIL, SessionKey("yandex_mail", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_MUSIC, SessionKey("yandex_music", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GNUTELLA, SessionKey("gnutella", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_EDONKEY, SessionKey("edonkey", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BITTORRENT, SessionKey("bittorrent", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MSTEAMS_CALL, SessionKey("msteams_call", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SIGNAL, SessionKey("signal", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MEMCACHED, SessionKey("memcached", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SMBV23, SessionKey("smbv23", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MINING, SessionKey("mining", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NEST_LOG_SINK, SessionKey("nest_log_sink", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MODBUS, SessionKey("modbus", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WHATSAPP_CALL, SessionKey("whatsapp_call", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DATASAVER, SessionKey("datasaver", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_XBOX, SessionKey("xbox", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_QQ, SessionKey("qq", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TIKTOK, SessionKey("tiktok", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RTSP, SessionKey("rtsp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MAIL_IMAPS, SessionKey("mail_imaps", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ICECAST, SessionKey("icecast", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CPHA, SessionKey("cpha", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IQIYI, SessionKey("iqiyi", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ZATTOO, SessionKey("zattoo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_MARKET, SessionKey("yandex_market", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_DISK, SessionKey("yandex_disk", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DISCORD, SessionKey("discord", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ADOBE_CONNECT, SessionKey("adobe_connect", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MONGODB, SessionKey("mongodb", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PLURALSIGHT, SessionKey("pluralsight", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_CLOUD, SessionKey("yandex_cloud", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OCSP, SessionKey("ocsp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VXLAN, SessionKey("vxlan", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IRC, SessionKey("irc", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MERAKI_CLOUD, SessionKey("meraki_cloud", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_JABBER, SessionKey("jabber", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NATS, SessionKey("nats", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AMONG_US, SessionKey("among_us", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YAHOO, SessionKey("yahoo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DISNEYPLUS, SessionKey("disneyplus", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HART_IP, SessionKey("hart_ip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_VRRP, SessionKey("ip_vrrp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_STEAM, SessionKey("steam", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HALFLIFE2, SessionKey("halflife2", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WORLDOFWARCRAFT, SessionKey("worldofwarcraft", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TELNET, SessionKey("telnet", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_STUN, SessionKey("stun", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IPSEC, SessionKey("ipsec", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_GRE, SessionKey("ip_gre", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_ICMP, SessionKey("ip_icmp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_IGMP, SessionKey("ip_igmp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_EGP, SessionKey("ip_egp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_SCTP, SessionKey("ip_sctp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_OSPF, SessionKey("ip_ospf", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_IP_IN_IP, SessionKey("ip_ip_in_ip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RTP, SessionKey("rtp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RDP, SessionKey("rdp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VNC, SessionKey("vnc", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TUMBLR, SessionKey("tumblr", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TLS, SessionKey("tls", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SSH, SessionKey("ssh", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_USENET, SessionKey("usenet", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MGCP, SessionKey("mgcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IAX, SessionKey("iax", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TFTP, SessionKey("tftp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AFP, SessionKey("afp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_METRIKA, SessionKey("yandex_metrika", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_DIRECT, SessionKey("yandex_direct", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SIP, SessionKey("sip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TRUPHONE, SessionKey("truphone", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_ICMPV6, SessionKey("ip_icmpv6", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DHCPV6, SessionKey("dhcpv6", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ARMAGETRON, SessionKey("armagetron", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CROSSFIRE, SessionKey("crossfire", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DOFUS, SessionKey("dofus", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ADS_ANALYTICS_TRACK, SessionKey("ads_analytics_track", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ADULT_CONTENT, SessionKey("adult_content", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GUILDWARS, SessionKey("guildwars", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AMAZON_ALEXA, SessionKey("amazon_alexa", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_KERBEROS, SessionKey("kerberos", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LDAP, SessionKey("ldap", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MAPLESTORY, SessionKey("maplestory", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MSSQL_TDS, SessionKey("mssql_tds", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PPTP, SessionKey("pptp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WARCRAFT3, SessionKey("warcraft3", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WORLD_OF_KUNG_FU, SessionKey("world_of_kung_fu", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SLACK, SessionKey("slack", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FACEBOOK, SessionKey("facebook", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TWITTER, SessionKey("twitter", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DROPBOX, SessionKey("dropbox", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GMAIL, SessionKey("gmail", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_MAPS, SessionKey("google_maps", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YOUTUBE, SessionKey("youtube", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MOZILLA, SessionKey("mozilla", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE, SessionKey("google", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MS_RPCH, SessionKey("ms_rpch", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NETFLOW, SessionKey("netflow", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SFLOW, SessionKey("sflow", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HTTP_CONNECT, SessionKey("http_connect", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HTTP_PROXY, SessionKey("http_proxy", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CITRIX, SessionKey("citrix", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NETFLIX, SessionKey("netflix", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LASTFM, SessionKey("lastfm", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WAZE, SessionKey("waze", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YOUTUBE_UPLOAD, SessionKey("youtube_upload", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HULU, SessionKey("hulu", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CHECKMK, SessionKey("checkmk", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AJP, SessionKey("ajp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APPLE, SessionKey("apple", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WEBEX, SessionKey("webex", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WHATSAPP, SessionKey("whatsapp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APPLE_ICLOUD, SessionKey("apple_icloud", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VIBER, SessionKey("viber", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APPLE_ITUNES, SessionKey("apple_itunes", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RADIUS, SessionKey("radius", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WINDOWS_UPDATE, SessionKey("windows_update", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TEAMVIEWER, SessionKey("teamviewer", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_EGD, SessionKey("egd", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LOTUS_NOTES, SessionKey("lotus_notes", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SAP, SessionKey("sap", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GTP, SessionKey("gtp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WSD, SessionKey("wsd", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LLMNR, SessionKey("llmnr", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TOCA_BOCA, SessionKey("toca_boca", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SPOTIFY, SessionKey("spotify", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FACEBOOK_MESSENGER, SessionKey("facebook_messenger", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_H323, SessionKey("h323", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OPENVPN, SessionKey("openvpn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NOE, SessionKey("noe", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CISCOVPN, SessionKey("ciscovpn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TEAMSPEAK, SessionKey("teamspeak", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TOR, SessionKey("tor", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SKINNY, SessionKey("skinny", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RTCP, SessionKey("rtcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RSYNC, SessionKey("rsync", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ORACLE, SessionKey("oracle", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CORBA, SessionKey("corba", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_UBUNTUONE, SessionKey("ubuntuone", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WHOIS_DAS, SessionKey("whois_das", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SD_RTN, SessionKey("sd_rtn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SOCKS, SessionKey("socks", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NINTENDO, SessionKey("nintendo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RTMP, SessionKey("rtmp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FTP_DATA, SessionKey("ftp_data", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WIKIPEDIA, SessionKey("wikipedia", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ZMQ, SessionKey("zmq", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AMAZON, SessionKey("amazon", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_EBAY, SessionKey("ebay", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CNN, SessionKey("cnn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MEGACO, SessionKey("megaco", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RESP, SessionKey("resp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PINTEREST, SessionKey("pinterest", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VHUA, SessionKey("vhua", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TELEGRAM, SessionKey("telegram", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_COD_MOBILE, SessionKey("cod_mobile", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PANDORA, SessionKey("pandora", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_QUIC, SessionKey("quic", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ZOOM, SessionKey("zoom", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_EAQ, SessionKey("eaq", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OOKLA, SessionKey("ookla", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AMQP, SessionKey("amqp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_KAKAOTALK, SessionKey("kakaotalk", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_KAKAOTALK_VOICE, SessionKey("kakaotalk_voice", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TWITCH, SessionKey("twitch", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DOH_DOT, SessionKey("doh_dot", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WECHAT, SessionKey("wechat", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MPEGTS, SessionKey("mpegts", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SNAPCHAT, SessionKey("snapchat", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SINA, SessionKey("sina", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_MEET, SessionKey("google_meet", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IFLIX, SessionKey("iflix", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GITHUB, SessionKey("github", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BJNP, SessionKey("bjnp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_REDDIT, SessionKey("reddit", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WIREGUARD, SessionKey("wireguard", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SMPP, SessionKey("smpp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DNSCRYPT, SessionKey("dnscrypt", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TINC, SessionKey("tinc", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DEEZER, SessionKey("deezer", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_INSTAGRAM, SessionKey("instagram", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MICROSOFT, SessionKey("microsoft", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_STARCRAFT, SessionKey("starcraft", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TEREDO, SessionKey("teredo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HOTSPOT_SHIELD, SessionKey("hotspot_shield", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IMO, SessionKey("imo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_DRIVE, SessionKey("google_drive", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OCS, SessionKey("ocs", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MICROSOFT_365, SessionKey("microsoft_365", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CLOUDFLARE, SessionKey("cloudflare", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MS_ONE_DRIVE, SessionKey("ms_one_drive", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MQTT, SessionKey("mqtt", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RX, SessionKey("rx", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APPLESTORE, SessionKey("applestore", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OPENDNS, SessionKey("opendns", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GIT, SessionKey("git", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DRDA, SessionKey("drda", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PLAYSTORE, SessionKey("playstore", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SOMEIP, SessionKey("someip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FIX, SessionKey("fix", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PLAYSTATION, SessionKey("playstation", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PASTEBIN, SessionKey("pastebin", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LINKEDIN, SessionKey("linkedin", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SOUNDCLOUD, SessionKey("soundcloud", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VALVE_SDR, SessionKey("valve_sdr", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LISP, SessionKey("lisp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DIAMETER, SessionKey("diameter", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APPLE_PUSH, SessionKey("apple_push", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_SERVICES, SessionKey("google_services", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AMAZON_VIDEO, SessionKey("amazon_video", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_DOCS, SessionKey("google_docs", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WHATSAPP_FILES, SessionKey("whatsapp_files", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TARGUS_GETDATA, SessionKey("targus_getdata", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DNP3, SessionKey("dnp3", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IEC60870, SessionKey("iec60870", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BLOOMBERG, SessionKey("bloomberg", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CAPWAP, SessionKey("capwap", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ZABBIX, SessionKey("zabbix", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_S7COMM, SessionKey("s7comm", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MSTEAMS, SessionKey("msteams", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WEBSOCKET, SessionKey("websocket", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ANYDESK, SessionKey("anydesk", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SOAP, SessionKey("soap", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APPLE_SIRI, SessionKey("apple_siri", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SNAPCHAT_CALL, SessionKey("snapchat_call", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HPVIRTGRP, SessionKey("hpvirtgrp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GENSHIN_IMPACT, SessionKey("genshin_impact", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ACTIVISION, SessionKey("activision", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FORTICLIENT, SessionKey("forticlient", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_Z3950, SessionKey("z3950", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LIKEE, SessionKey("likee", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GITLAB, SessionKey("gitlab", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AVAST_SECUREDNS, SessionKey("avast_securedns", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CASSANDRA, SessionKey("cassandra", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AMAZON_AWS, SessionKey("amazon_aws", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SALESFORCE, SessionKey("salesforce", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VIMEO, SessionKey("vimeo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FACEBOOK_VOIP, SessionKey("facebook_voip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SIGNAL_VOIP, SessionKey("signal_voip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FUZE, SessionKey("fuze", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GTP_U, SessionKey("gtp_u", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GTP_C, SessionKey("gtp_c", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GTP_PRIME, SessionKey("gtp_prime", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ALIBABA, SessionKey("alibaba", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CRASHLYSTICS, SessionKey("crashlystics", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MICROSOFT_AZURE, SessionKey("microsoft_azure", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ICLOUD_PRIVATE_RELAY, SessionKey("icloud_private_relay", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ETHERNET_IP, SessionKey("ethernet_ip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BADOO, SessionKey("badoo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ACCUWEATHER, SessionKey("accuweather", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_CLASSROOM, SessionKey("google_classroom", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HSRP, SessionKey("hsrp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CYBERSECURITY, SessionKey("cybersecurity", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_CLOUD, SessionKey("google_cloud", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TENCENT, SessionKey("tencent", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RAKNET, SessionKey("raknet", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_XIAOMI, SessionKey("xiaomi", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_EDGECAST, SessionKey("edgecast", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CACHEFLY, SessionKey("cachefly", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SOFTETHER, SessionKey("softether", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MPEGDASH, SessionKey("mpegdash", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DAZN, SessionKey("dazn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOTO, SessionKey("goto", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RSH, SessionKey("rsh", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_1KXUN, SessionKey("1kxun", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_PGM, SessionKey("ip_pgm", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IP_PIM, SessionKey("ip_pim", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_COLLECTD, SessionKey("collectd", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TUNNELBEAR, SessionKey("tunnelbear", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CLOUDFLARE_WARP, SessionKey("cloudflare_warp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_I3D, SessionKey("i3d", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RIOTGAMES, SessionKey("riotgames", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PSIPHON, SessionKey("psiphon", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ULTRASURF, SessionKey("ultrasurf", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_THREEMA, SessionKey("threema", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ALICLOUD, SessionKey("alicloud", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_AVAST, SessionKey("avast", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TIVOCONNECT, SessionKey("tivoconnect", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_KISMET, SessionKey("kismet", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FASTCGI, SessionKey("fastcgi", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FTPS, SessionKey("ftps", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NATPMP, SessionKey("natpmp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SYNCTHING, SessionKey("syncthing", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CRYNET, SessionKey("crynet", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LINE, SessionKey("line", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LINE_CALL, SessionKey("line_call", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APPLETVPLUS, SessionKey("appletvplus", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DIRECTV, SessionKey("directv", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HBO, SessionKey("hbo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VUDU, SessionKey("vudu", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SHOWTIME, SessionKey("showtime", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DAILYMOTION, SessionKey("dailymotion", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LIVESTREAM, SessionKey("livestream", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TENCENTVIDEO, SessionKey("tencentvideo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IHEARTRADIO, SessionKey("iheartradio", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TIDAL, SessionKey("tidal", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TUNEIN, SessionKey("tunein", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SIRIUSXMRADIO, SessionKey("siriusxmradio", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MUNIN, SessionKey("munin", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ELASTICSEARCH, SessionKey("elasticsearch", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TUYA_LP, SessionKey("tuya_lp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TPLINK_SHP, SessionKey("tplink_shp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SOURCE_ENGINE, SessionKey("source_engine", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BACNET, SessionKey("bacnet", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OICQ, SessionKey("oicq", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HOTS, SessionKey("hots", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FACEBOOK_REEL_STORY, SessionKey("facebook_reel_story", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SRTP, SessionKey("srtp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OPERA_VPN, SessionKey("opera_vpn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_EPICGAMES, SessionKey("epicgames", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GEFORCENOW, SessionKey("geforcenow", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NVIDIA, SessionKey("nvidia", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BITCOIN, SessionKey("bitcoin", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PROTONVPN, SessionKey("protonvpn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APACHE_THRIFT, SessionKey("apache_thrift", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ROBLOX, SessionKey("roblox", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SERVICE_LOCATION, SessionKey("service_location", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MULLVAD, SessionKey("mullvad", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HTTP2, SessionKey("http2", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HAPROXY, SessionKey("haproxy", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RMCP, SessionKey("rmcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CAN, SessionKey("can", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PROTOBUF, SessionKey("protobuf", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ETHEREUM, SessionKey("ethereum", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TELEGRAM_VOIP, SessionKey("telegram_voip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SINA_WEIBO, SessionKey("sina_weibo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TESLA_SERVICES, SessionKey("tesla_services", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PTPV2, SessionKey("ptpv2", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RTPS, SessionKey("rtps", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OPC_UA, SessionKey("opc_ua", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_S7COMM_PLUS, SessionKey("s7comm_plus", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FINS, SessionKey("fins", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ETHERSIO, SessionKey("ethersio", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_UMAS, SessionKey("umas", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BECKHOFF_ADS, SessionKey("beckhoff_ads", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ISO9506_1_MMS, SessionKey("iso9506_1_mms", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IEEE_C37118, SessionKey("ieee_c37118", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ETHERSBUS, SessionKey("ethersbus", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MONERO, SessionKey("monero", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DCERPC, SessionKey("dcerpc", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PROFINET_IO, SessionKey("profinet_io", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HISLIP, SessionKey("hislip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_UFTP, SessionKey("uftp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OPENFLOW, SessionKey("openflow", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_JSON_RPC, SessionKey("json_rpc", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WEBDAV, SessionKey("webdav", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_APACHE_KAFKA, SessionKey("apache_kafka", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NOMACHINE, SessionKey("nomachine", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_IEC62056, SessionKey("iec62056", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HL7, SessionKey("hl7", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CEPH, SessionKey("ceph", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_CHAT, SessionKey("google_chat", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ROUGHTIME, SessionKey("roughtime", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PIA, SessionKey("pia", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_KCP, SessionKey("kcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DOTA2, SessionKey("dota2", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MUMBLE, SessionKey("mumble", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YOJIMBO, SessionKey("yojimbo", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ELECTRONICARTS, SessionKey("electronicarts", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_STOMP, SessionKey("stomp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RADMIN, SessionKey("radmin", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RAFT, SessionKey("raft", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CIP, SessionKey("cip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GEARMAN, SessionKey("gearman", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TENCENTGAMES, SessionKey("tencentgames", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GAIJIN, SessionKey("gaijin", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_C1222, SessionKey("c1222", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HUAWEI, SessionKey("huawei", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HUAWEI_CLOUD, SessionKey("huawei_cloud", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DLEP, SessionKey("dlep", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BFD, SessionKey("bfd", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NETEASE_GAMES, SessionKey("netease_games", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PATHOFEXILE, SessionKey("pathofexile", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GOOGLE_CALL, SessionKey("google_call", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PFCP, SessionKey("pfcp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_FLUTE, SessionKey("flute", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LOLWILDRIFT, SessionKey("lolwildrift", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TESO, SessionKey("teso", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LDP, SessionKey("ldp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_KNXNET_IP, SessionKey("knxnet_ip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_BLUESKY, SessionKey("bluesky", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MASTODON, SessionKey("mastodon", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_THREADS, SessionKey("threads", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VIBER_VOIP, SessionKey("viber_voip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ZUG, SessionKey("zug", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_JRMI, SessionKey("jrmi", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RIPE_ATLAS, SessionKey("ripe_atlas", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_HLS, SessionKey("hls", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CLICKHOUSE, SessionKey("clickhouse", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NANO, SessionKey("nano", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_OPENWIRE, SessionKey("openwire", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CNP_IP, SessionKey("cnp_ip", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_ATG, SessionKey("atg", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TRDP, SessionKey("trdp", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LUSTRE, SessionKey("lustre", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NORDVPN, SessionKey("nordvpn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SURFSHARK, SessionKey("surfshark", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_CACTUSVPN, SessionKey("cactusvpn", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_WINDSCRIBE, SessionKey("windscribe", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SONOS, SessionKey("sonos", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DINGTALK, SessionKey("dingtalk", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PALTALK, SessionKey("paltalk", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_NAVER, SessionKey("naver", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_SHEIN, SessionKey("shein", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TEMU, SessionKey("temu", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_TAOBAO, SessionKey("taobao", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_MIKROTIK, SessionKey("mikrotik", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DICOM, SessionKey("dicom", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_PARAMOUNTPLUS, SessionKey("paramountplus", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_YANDEX_ALICE, SessionKey("yandex_alice", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_VIVOX, SessionKey("vivox", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_DIGITALOCEAN, SessionKey("digitalocean", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_RUTUBE, SessionKey("rutube", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_LAGOFAST, SessionKey("lagofast", std::string()));
    protocol_session_keys_.emplace(NDPI_PROTOCOL_GEARUP_BOOSTER, SessionKey("gearup_booster", std::string()));
  }

  
  bool PacketProcessor::process_packet(
    struct ndpi_workflow* workflow,
    const ndpi_flow_info* flow,
    const pcap_pkthdr* header,
    UserSessionPacketProcessor::Direction direction)
  {
    ++packet_i_;

    const u_int16_t proto = flow ?
      (flow->detected_protocol.proto.app_protocol ? flow->detected_protocol.proto.app_protocol :
        flow->detected_protocol.proto.master_protocol) :
      0;

    bool res = true;

    if (flow)
    {
      res = process_packet_(
        proto,
        flow->src_ip,
        flow->dst_ip,
        header->len,
        direction
        );
    }

    return res;
  }

  const SessionKey&
  PacketProcessor::proto_to_session_key_(u_int16_t proto) const
  {
    auto session_key_it = protocol_session_keys_.find(proto);
    if (session_key_it != protocol_session_keys_.end())
    {
      return session_key_it->second;
    }

    return unknown_session_key_;
  }

  bool PacketProcessor::process_packet_(
    u_int16_t proto,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint64_t packet_size,
    UserSessionPacketProcessor::Direction direction
    )
  {
    // find SessionKey by proto
    const SessionKey& base_session_key = proto_to_session_key_(proto);
    const std::string* category = nullptr;

    {
      // find category by ip
      auto cat_it = ip_categories_.find(dst_ip);
      if (cat_it != ip_categories_.end())
      {
        category = &cat_it->second;
      }
      else
      {
        cat_it = ip_categories_.find(src_ip);
        if (cat_it != ip_categories_.end())
        {
          category = &cat_it->second;
        }
      }
    }

    SessionKey use_session_key = !category ? base_session_key :
      SessionKey(base_session_key.traffic_type, *category);

    const Gears::Time now = Gears::Time::get_time_of_day();

    UserPtr user = get_user_(src_ip, dst_ip, now);

    PacketProcessingState processing_state =
      user_session_packet_processor_->process_user_session_packet(
        now,
        user,
        src_ip,
        dst_ip,
        direction,
        use_session_key,
        packet_size);

    /*
    if (processing_state.block_packet)
    {
      std::cout << "BLOCK PACKET BY: "
        "traffic_type = '" << use_session_key.traffic_type << "', "
        "category_type = '" << use_session_key.category_type << "'" <<
        std::endl;
    }
    */

    return !processing_state.block_packet;
  }

  UserPtr PacketProcessor::get_user_(
    uint32_t& src_ip,
    uint32_t& dst_ip,
    const Gears::Time& now) const
  {
    UserPtr user = user_storage_->get_user_by_ip(src_ip, now);
    if (user)
    {
      return user;
    }

    user = user_storage_->get_user_by_ip(dst_ip, now);
    if (user)
    {
      std::swap(src_ip, dst_ip);
      return user;
    }

    user = std::make_shared<User>(std::string());
    user->set_ip(src_ip);
    return user;
  }
}
