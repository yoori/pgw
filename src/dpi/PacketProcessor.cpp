#include <iostream>
#include <sstream>

#include <gears/Time.hpp>
#include <gears/DirSelector.hpp>

#include <ndpi/ndpi_config.h>
#include <ndpi_api.h>

#include "NetworkUtils.hpp"
#include "IpList.hpp"
#include "PacketProcessor.hpp"
#include "MainUserSessionPacketProcessor.hpp"

namespace dpi
{
  struct IpListFileSelector
  {
    IpListFileSelector(std::vector<std::string>& ip_list_files)
      : ip_list_files_(ip_list_files)
    {}

    bool operator()(const char* full_path, const struct stat&) const
    {
      ip_list_files_.emplace_back(full_path);
      return true;
    }

  private:
    std::vector<std::string>& ip_list_files_;
  };

  PacketProcessor::PacketProcessor(
    UserStoragePtr user_storage,
    UserSessionStoragePtr user_session_storage,
    UserSessionPacketProcessorPtr user_session_packet_processor,
    LoggerPtr event_logger,
    std::string_view ip_rules_path,
    dpi::DiameterSessionPtr gx_diameter_session,
    dpi::DiameterSessionPtr gy_diameter_session,
    PccConfigProviderPtr pcc_config_provider,
    SessionKeyEvaluatorPtr session_key_evaluator
    )
    : user_storage_(user_storage),
      user_session_storage_(user_session_storage),
      event_logger_(event_logger),
      unknown_session_key_("unknown", std::string()),
      user_session_packet_processor_(std::move(user_session_packet_processor)),
      gx_diameter_session_(std::move(gx_diameter_session)),
      gy_diameter_session_(std::move(gy_diameter_session)),
      pcc_config_provider_(std::move(pcc_config_provider)),
      session_key_evaluator_(std::move(session_key_evaluator))
  {
    if (!ip_rules_path.empty())
    {
      std::vector<std::string> ip_list_files;
      IpListFileSelector ip_list_file_selector(ip_list_files);

      Gears::DirSelect::directory_selector(
        std::string(ip_rules_path).c_str(),
        ip_list_file_selector,
        false,
        Gears::DirSelect::default_failed_to_open_directory,
        Gears::DirSelect::default_failed_to_stat_file
        );

      for (const auto& ip_list_file : ip_list_files)
      {
        const std::string rule_name = Gears::DirSelect::file_name(ip_list_file.c_str());
        if (!rule_name.empty() && rule_name[0] != '.')
        {
          std::cout << "Read ip rule by " << ip_list_file << std::endl;
          IpList ip_list = IpList::load(ip_list_file);
          for (uint32_t ip : ip_list.ips())
          {
            ip_categories_.emplace(ip, rule_name);
          }
        }
      }
    }

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

  
  PacketProcessingState
  PacketProcessor::process_packet(
    const FlowTraits& flow_traits,
    unsigned long packet_size,
    const void* packet,
    Direction direction,
    NetInterfacePtr send_interface)
  {
    ++packet_i_;

    return process_packet_(
      flow_traits,
      packet_size,
      direction,
      packet
      );
  }

  SessionKey
  PacketProcessor::proto_to_session_key_(const std::string& protocol)
  {
    return SessionKey(protocol, std::string());
  }

  PacketProcessingState
  PacketProcessor::process_packet_(
    const FlowTraits& orig_flow_traits,
    uint64_t packet_size,
    Direction direction, // TODO: push to FlowTraits
    const void* packet
    )
  {
    // find SessionKey by proto
    const SessionKey& base_session_key = proto_to_session_key_(orig_flow_traits.protocol);

    const std::string* category = nullptr;

    {
      // find category by ip
      auto cat_it = ip_categories_.find(orig_flow_traits.dst_ip);
      if (cat_it != ip_categories_.end())
      {
        category = &cat_it->second;
      }
      else
      {
        cat_it = ip_categories_.find(orig_flow_traits.src_ip);
        if (cat_it != ip_categories_.end())
        {
          category = &cat_it->second;
        }
      }
    }

    SessionKey use_session_key = !category ? base_session_key :
      SessionKey(base_session_key.traffic_type(), *category);

    if (session_key_evaluator_)
    {
      SessionKey eval_session_key = session_key_evaluator_->evaluate(orig_flow_traits);

      if (!eval_session_key.traffic_type().empty() || !eval_session_key.category_type().empty())
      {
        if (eval_session_key.traffic_type().empty())
        {
          // if evaluated traffic_type is empty override only category_type
          use_session_key = dpi::SessionKey(use_session_key.traffic_type(), eval_session_key.category_type());
        }
        else
        {
          use_session_key = eval_session_key;
        }
      }
    }

    const Gears::Time now = Gears::Time::get_time_of_day();

    FlowTraits flow_traits(orig_flow_traits);

    UserPtr user = get_user_(flow_traits.src_ip, flow_traits.dst_ip, now);

    PacketProcessingState processing_state;
    ConstPccConfigPtr pcc_config;

    if (pcc_config_provider_)
    {
      pcc_config = pcc_config_provider_->get_config();
      /*
      auto session_key_rule_it = pcc_config->session_keys.find(processing_state.session_key);
      if (session_key_rule_it != pcc_config->session_keys.end())
      {
        const PccConfig::SessionKeyRule& session_key_rule = session_key_rule_it->second;
        processing_state.allowed = true;
      }
      */
    }

    processing_state.user = user;
    processing_state.session_key = use_session_key;
    user_session_packet_processor_->process_user_session_packet(
      processing_state,
      now,
      user,
      flow_traits,
      direction,
      use_session_key,
      packet_size,
      packet);

    //std::cout << "Process packet " << processing_state.session_key.to_string() << ": " << packet_size << std::endl;

    return processing_state;
  }

  UserPtr PacketProcessor::get_user_(
    uint32_t& src_ip,
    uint32_t& dst_ip,
    const Gears::Time& now) const
  {
    UserSessionPtr user_session = user_session_storage_->get_user_session_by_ip(src_ip);

    if (user_session)
    {
      return user_session->user();
    }

    user_session = user_session_storage_->get_user_session_by_ip(dst_ip);

    if (user_session)
    {
      return user_session->user();
    }

    return UserPtr();

    /*
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

    user = std::make_shared<User>(std::string(), std::string());
    user->set_ip(src_ip);
    return user;
    */
  }
}
