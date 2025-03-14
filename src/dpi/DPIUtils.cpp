#include <math.h>
#include <float.h> /* FLT_EPSILON */

#include "DPIUtils.hpp"

FILE* csv_fp = NULL;
u_int8_t verbose = 0;
u_int8_t enable_flow_stats = 0;
u_int8_t enable_payload_analyzer = 0;
FILE* serialization_fp = NULL; /**< for TLV,CSV,JSON export */
DPIHandleHolder dpi_handle_holder;

void print_flow(u_int32_t id, struct ndpi_flow_info *flow, u_int16_t thread_id)
{
  FILE *out = stdout;
  u_int8_t known_tls;
  char buf[32], buf1[64];
  char buf_ver[16];
  char buf2_ver[16];
  char l4_proto_name[32];
  u_int i;

  if (csv_fp != NULL)
  {
    float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
    double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;

    fprintf(csv_fp, "%u|%u|%.3f|%.3f|%.3f|%s|%u|%s|%u|",
            flow->flow_id,
            flow->protocol,
            f/1000.0, l/1000.0,
            (l-f)/1000.0,
            flow->src_name, ntohs(flow->src_port),
            flow->dst_name, ntohs(flow->dst_port)
            );

    fprintf(csv_fp, "%s|",
            ndpi_protocol2id(flow->detected_protocol, buf, sizeof(buf)));

    fprintf(csv_fp, "%s|%s|%s|",
            ndpi_protocol2name(
              dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
              flow->detected_protocol, buf, sizeof(buf)),
            ndpi_get_proto_name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                flow->detected_protocol.protocol_by_ip),
            flow->host_server_name);

    fprintf(csv_fp, "%u|%llu|%llu|", flow->src2dst_packets,
            (long long unsigned int) flow->src2dst_bytes, (long long unsigned int) flow->src2dst_goodput_bytes);
    fprintf(csv_fp, "%u|%llu|%llu|", flow->dst2src_packets,
            (long long unsigned int) flow->dst2src_bytes, (long long unsigned int) flow->dst2src_goodput_bytes);
    fprintf(csv_fp, "%.3f|%s|", data_ratio, ndpi_data_ratio2str(data_ratio));
    fprintf(csv_fp, "%.1f|%.1f|", 100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
            100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));

    /* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|",
            (unsigned long long int)ndpi_data_min(flow->iat_flow), ndpi_data_average(flow->iat_flow),
            (unsigned long long int)ndpi_data_max(flow->iat_flow), ndpi_data_stddev(flow->iat_flow));

    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|%llu|%.1f|%llu|%.1f|",
            (unsigned long long int)ndpi_data_min(flow->iat_c_to_s), ndpi_data_average(flow->iat_c_to_s),
            (unsigned long long int)ndpi_data_max(flow->iat_c_to_s), ndpi_data_stddev(flow->iat_c_to_s),
            (unsigned long long int)ndpi_data_min(flow->iat_s_to_c), ndpi_data_average(flow->iat_s_to_c),
            (unsigned long long int)ndpi_data_max(flow->iat_s_to_c), ndpi_data_stddev(flow->iat_s_to_c));

    /* Packet Length */
    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|%llu|%.1f|%llu|%.1f|",
            (unsigned long long int)ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_c_to_s),
            (unsigned long long int)ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_stddev(flow->pktlen_c_to_s),
            (unsigned long long int)ndpi_data_min(flow->pktlen_s_to_c), ndpi_data_average(flow->pktlen_s_to_c),
            (unsigned long long int)ndpi_data_max(flow->pktlen_s_to_c), ndpi_data_stddev(flow->pktlen_s_to_c));

    /* TCP flags */
    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->cwr_count, flow->ece_count, flow->urg_count, flow->ack_count, flow->psh_count, flow->rst_count, flow->syn_count, flow->fin_count);

    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->src2dst_cwr_count, flow->src2dst_ece_count, flow->src2dst_urg_count, flow->src2dst_ack_count,
            flow->src2dst_psh_count, flow->src2dst_rst_count, flow->src2dst_syn_count, flow->src2dst_fin_count);

    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->dst2src_cwr_count, flow->dst2src_ece_count, flow->dst2src_urg_count, flow->dst2src_ack_count,
            flow->dst2src_psh_count, flow->dst2src_rst_count, flow->dst2src_syn_count, flow->dst2src_fin_count);

    /* TCP window */
    fprintf(csv_fp, "%u|%u|", flow->c_to_s_init_win, flow->s_to_c_init_win);

    fprintf(csv_fp, "%s|",
            (flow->ssh_tls.server_info[0] != '\0')  ? flow->ssh_tls.server_info : "");

    fprintf(csv_fp, "%s|%s|%s|",
            (flow->ssh_tls.ssl_version != 0)        ? ndpi_ssl_version2str(buf_ver, sizeof(buf_ver), flow->ssh_tls.ssl_version, &known_tls) : "0",
            (flow->ssh_tls.quic_version != 0)       ? ndpi_quic_version2str(buf2_ver, sizeof(buf2_ver), flow->ssh_tls.quic_version) : "0",
            (flow->ssh_tls.ja3_server[0] != '\0')   ? flow->ssh_tls.ja3_server : "");

    fprintf(csv_fp, "%s|%s|%s|",
            flow->ssh_tls.advertised_alpns          ? flow->ssh_tls.advertised_alpns : "",
            flow->ssh_tls.negotiated_alpn           ? flow->ssh_tls.negotiated_alpn : "",
            flow->ssh_tls.tls_supported_versions    ? flow->ssh_tls.tls_supported_versions : ""
            );

#if 0
    fprintf(csv_fp, "%s|%s|",
            flow->ssh_tls.tls_issuerDN              ? flow->ssh_tls.tls_issuerDN : "",
            flow->ssh_tls.tls_subjectDN             ? flow->ssh_tls.tls_subjectDN : ""
            );
#endif

    fprintf(csv_fp, "%s|%s",
            (flow->ssh_tls.client_hassh[0] != '\0') ? flow->ssh_tls.client_hassh : "",
            (flow->ssh_tls.server_hassh[0] != '\0') ? flow->ssh_tls.server_hassh : ""
            );

    fprintf(csv_fp, "|%s|", flow->info);

#ifndef DIRECTION_BINS
    print_bin(csv_fp, NULL, &flow->payload_len_bin);
#endif

    fprintf(csv_fp, "|%s", flow->http.user_agent);

    if ((verbose != 1) && (verbose != 2))
    {
      if (csv_fp && enable_flow_stats)
      {
        flowGetBDMeanandVariance(flow);
      }

      if (csv_fp)
        fprintf(csv_fp, "\n");
      //  return;
    }
  }

  if (csv_fp || (verbose > 1))
  {
#if 1
    fprintf(out, "\t%u", id);
#else
    fprintf(out, "\t%u(%u)", id, flow->flow_id);
#endif

    fprintf(out, "\t%s ", ndpi_get_ip_proto_name(flow->protocol, l4_proto_name, sizeof(l4_proto_name)));

    fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
            (flow->ip_version == 6) ? "[" : "",
            flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
            flow->bidirectional ? "<->" : "->",
            (flow->ip_version == 6) ? "[" : "",
            flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
            );

    if (flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);
    if (enable_payload_analyzer) fprintf(out, "[flowId: %u]", flow->flow_id);

    if (enable_flow_stats)
    {
      /* Print entropy values for monitored flows. */
      flowGetBDMeanandVariance(flow);
      fflush(out);
      fprintf(out, "[score: %.4f]", flow->entropy->score);
    }

    //if (csv_fp) fprintf(csv_fp, "\n");

    fprintf(out, "[proto: ");
    if (flow->tunnel_type != ndpi_no_tunnel)
      fprintf(out, "%s:", ndpi_tunnel2str(flow->tunnel_type));

    fprintf(out, "%s/%s][IP: %u/%s]",
            ndpi_protocol2id(flow->detected_protocol, buf, sizeof(buf)),
            ndpi_protocol2name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                               flow->detected_protocol, buf1, sizeof(buf1)),
            flow->detected_protocol.protocol_by_ip,
            ndpi_get_proto_name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                flow->detected_protocol.protocol_by_ip));

    if (flow->multimedia_flow_types != ndpi_multimedia_unknown_flow)
    {
      char content[64] = {0};

      fprintf(out, "[Stream Content: %s]", ndpi_multimedia_flowtype2str(content, sizeof(content), flow->multimedia_flow_types));
    }

    if ((flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_RTP) || (flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_RTP))
    {
      if (flow->rtp[0 /* cli -> srv */].payload_detected || flow->rtp[1].payload_detected)
      {
        fprintf(out, "[Payload Type: ");

        if (flow->rtp[0].payload_detected)
          fprintf(out, "%s (%u.%u)",
                  ndpi_rtp_payload_type2str(flow->rtp[0].payload_type, flow->rtp[0].evs_subtype), flow->rtp[0].payload_type, flow->rtp[0].evs_subtype);

        if (flow->rtp[1 /* srv -> cli */].payload_detected)
        {
          if (flow->rtp[0].payload_detected) fprintf(out, " / ");

          fprintf(out, "%s (%u.%u)]",
                  ndpi_rtp_payload_type2str(flow->rtp[1].payload_type, flow->rtp[1].evs_subtype), flow->rtp[1].payload_type, flow->rtp[1].evs_subtype);
        } else
          fprintf(out, "]");
      }
    }

    fprintf(out, "[%s]",
            ndpi_is_encrypted_proto(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                    flow->detected_protocol) ? "Encrypted" : "ClearText");

    fprintf(out, "[Confidence: %s]", ndpi_confidence_get_name(flow->confidence));

    if (flow->fpc.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
    {
      fprintf(out, "[FPC: %u/%s, ",
              flow->fpc.proto.app_protocol,
              ndpi_get_proto_name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                  flow->fpc.proto.app_protocol));
    } else {
      fprintf(out, "[FPC: %u.%u/%s.%s, ",
              flow->fpc.proto.master_protocol,
              flow->fpc.proto.app_protocol,
              ndpi_get_proto_name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                  flow->fpc.proto.master_protocol),
              ndpi_get_proto_name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                  flow->fpc.proto.app_protocol));
    }
    fprintf(out, "Confidence: %s]",
            ndpi_fpc_confidence_get_name(flow->fpc.confidence));

    /* If someone wants to have the num_dissector_calls variable per flow, he can print it here.
       Disabled by default to avoid too many diffs in the unit tests...
    */
#if 0
    fprintf(out, "[Num calls: %d]", flow->num_dissector_calls);
#endif
    fprintf(out, "[DPI packets: %d]", flow->dpi_packets);

    if (flow->num_packets_before_monitoring > 0)
      fprintf(out, "[DPI packets before monitoring: %d]", flow->num_packets_before_monitoring);

    if (flow->detected_protocol.category != 0)
      fprintf(out, "[cat: %s/%u]",
              ndpi_category_get_name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                     flow->detected_protocol.category),
              (unsigned int)flow->detected_protocol.category);

    fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
    fprintf(out, "%s %u pkts/%llu bytes]",
            (flow->dst2src_packets > 0) ? "<->" : "->",
            flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

    fprintf(out, "[Goodput ratio: %.0f/%.0f]",
            100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
            100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));

    if (flow->last_seen_ms > flow->first_seen_ms)
      fprintf(out, "[%.2f sec]", ((float)(flow->last_seen_ms - flow->first_seen_ms))/(float)1000);
    else
      fprintf(out, "[< 1 sec]");

    if (flow->telnet.username)  fprintf(out, "[Username: %s]", flow->telnet.username);
    if (flow->telnet.password)  fprintf(out, "[Password: %s]", flow->telnet.password);

    if (flow->http.username[0])  fprintf(out, "[Username: %s]", flow->http.username);
    if (flow->http.password[0])  fprintf(out, "[Password: %s]", flow->http.password);

    if (flow->host_server_name[0] != '\0') fprintf(out, "[Hostname/SNI: %s]", flow->host_server_name);

    switch (flow->info_type)
      {
      case INFO_INVALID:
        break;

      case INFO_GENERIC:
        if (flow->info[0] != '\0')
          {
            fprintf(out, "[%s]", flow->info);
          }
        break;

      case INFO_KERBEROS:
        if (flow->kerberos.domain[0] != '\0' ||
            flow->kerberos.hostname[0] != '\0' ||
            flow->kerberos.username[0] != '\0')
          {
            fprintf(out, "[%s%s%s%s]",
                    flow->kerberos.domain,
                    (flow->kerberos.hostname[0] != '\0' ||
                     flow->kerberos.username[0] != '\0' ? "\\" : ""),
                    flow->kerberos.hostname,
                    flow->kerberos.username);
          }
        break;

      case INFO_SOFTETHER:
        if (flow->softether.ip[0] != '\0')
        {
          fprintf(out, "[Client IP: %s]", flow->softether.ip);
        }

        if (flow->softether.port[0] != '\0')
        {
          fprintf(out, "[Client Port: %s]", flow->softether.port);
        }

        if (flow->softether.hostname[0] != '\0')
        {
          fprintf(out, "[Hostname: %s]", flow->softether.hostname);
        }

        if (flow->softether.fqdn[0] != '\0')
        {
          fprintf(out, "[FQDN: %s]", flow->softether.fqdn);
        }

        break;

      case INFO_TIVOCONNECT:
        if (flow->tivoconnect.identity_uuid[0] != '\0')
          {
            fprintf(out, "[UUID: %s]", flow->tivoconnect.identity_uuid);
          }
        if (flow->tivoconnect.machine[0] != '\0')
          {
            fprintf(out, "[Machine: %s]", flow->tivoconnect.machine);
          }
        if (flow->tivoconnect.platform[0] != '\0')
          {
            fprintf(out, "[Platform: %s]", flow->tivoconnect.platform);
          }
        if (flow->tivoconnect.services[0] != '\0')
          {
            fprintf(out, "[Services: %s]", flow->tivoconnect.services);
          }
        break;

      case INFO_SIP:
        if (flow->sip.from[0] != '\0')
          {
            fprintf(out, "[SIP From: %s]", flow->sip.from);
          }
        if (flow->sip.from_imsi[0] != '\0')
          {
            fprintf(out, "[SIP From IMSI: %s]", flow->sip.from_imsi);
          }
        if (flow->sip.to[0] != '\0')
          {
            fprintf(out, "[SIP To: %s]", flow->sip.to);
          }
        if (flow->sip.to_imsi[0] != '\0')
          {
            fprintf(out, "[SIP To IMSI: %s]", flow->sip.to_imsi);
          }
        break;

      case INFO_NATPMP:
        if (flow->natpmp.internal_port != 0 && flow->natpmp.ip[0] != '\0')
          {
            fprintf(out, "[Result: %u][Internal Port: %u][External Port: %u][External Address: %s]",
                    flow->natpmp.result_code, flow->natpmp.internal_port, flow->natpmp.external_port,
                    flow->natpmp.ip);
          }
        break;

      case INFO_FTP_IMAP_POP_SMTP:
        if (flow->ftp_imap_pop_smtp.username[0] != '\0')
          {
            fprintf(out, "[User: %s][Pwd: %s]",
                    flow->ftp_imap_pop_smtp.username,
                    flow->ftp_imap_pop_smtp.password);
            if (flow->ftp_imap_pop_smtp.auth_failed != 0)
              {
                fprintf(out, "[%s]", "Auth Failed");
              }
          }
        break;
      }

    if (flow->ssh_tls.advertised_alpns)
      fprintf(out, "[(Advertised) ALPNs: %s]", flow->ssh_tls.advertised_alpns);

    if (flow->ssh_tls.negotiated_alpn)
      fprintf(out, "[(Negotiated) ALPN: %s]", flow->ssh_tls.negotiated_alpn);

    if (flow->ssh_tls.tls_supported_versions)
      fprintf(out, "[TLS Supported Versions: %s]", flow->ssh_tls.tls_supported_versions);

    if (flow->mining.currency[0] != '\0') fprintf(out, "[currency: %s]", flow->mining.currency);

    if (flow->dns.geolocation_iata_code[0] != '\0') fprintf(out, "[GeoLocation: %s]", flow->dns.geolocation_iata_code);
    if (flow->dns.transaction_id != 0) fprintf(out, "[DNS Id: 0x%.4x]", flow->dns.transaction_id);
    if (flow->dns.ptr_domain_name[0] != '\0') fprintf(out, "[DNS Ptr: %s]", flow->dns.ptr_domain_name);

    if ((flow->src2dst_packets+flow->dst2src_packets) > 5)
    {
      if (flow->iat_c_to_s && flow->iat_s_to_c)
      {
        float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

        fprintf(out, "[bytes ratio: %.3f (%s)]", data_ratio, ndpi_data_ratio2str(data_ratio));

        /* IAT (Inter Arrival Time) */
        fprintf(out, "[IAT c2s/s2c min/avg/max/stddev: %llu/%llu %.0f/%.0f %llu/%llu %.0f/%.0f]",
                (unsigned long long int)ndpi_data_min(flow->iat_c_to_s),
                (unsigned long long int)ndpi_data_min(flow->iat_s_to_c),
                (float)ndpi_data_average(flow->iat_c_to_s), (float)ndpi_data_average(flow->iat_s_to_c),
                (unsigned long long int)ndpi_data_max(flow->iat_c_to_s),
                (unsigned long long int)ndpi_data_max(flow->iat_s_to_c),
                (float)ndpi_data_stddev(flow->iat_c_to_s),  (float)ndpi_data_stddev(flow->iat_s_to_c));

        /* Packet Length */
        fprintf(out, "[Pkt Len c2s/s2c min/avg/max/stddev: %llu/%llu %.0f/%.0f %llu/%llu %.0f/%.0f]",
                (unsigned long long int)ndpi_data_min(flow->pktlen_c_to_s),
                (unsigned long long int)ndpi_data_min(flow->pktlen_s_to_c),
                ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_s_to_c),
                (unsigned long long int)ndpi_data_max(flow->pktlen_c_to_s),
                (unsigned long long int)ndpi_data_max(flow->pktlen_s_to_c),
                ndpi_data_stddev(flow->pktlen_c_to_s),  ndpi_data_stddev(flow->pktlen_s_to_c));
      }
    }

    print_ndpi_address_port_list_file(out, "Mapped IP/Port", &flow->stun.mapped_address);
    print_ndpi_address_port_list_file(out, "Peer IP/Port", &flow->stun.peer_address);
    print_ndpi_address_port_list_file(out, "Relayed IP/Port", &flow->stun.relayed_address);
    print_ndpi_address_port_list_file(out, "Rsp Origin IP/Port", &flow->stun.response_origin);
    print_ndpi_address_port_list_file(out, "Other IP/Port", &flow->stun.other_address);

    /* These counters make sense only if the flow entered the monitor state */
    if (flow->num_packets_before_monitoring > 0)
      fprintf(out, "[RTP packets: %d/%d]", flow->stun.rtp_counters[0], flow->stun.rtp_counters[1]);

    if (flow->http.url[0] != '\0')
    {
      ndpi_risk_enum risk = ndpi_validate_url(flow->http.url);

      if (risk != NDPI_NO_RISK)
        NDPI_SET_BIT(flow->risk, risk);

      fprintf(out, "[URL: %s]", flow->http.url);
    }

    if (flow->http.response_status_code)
      fprintf(out, "[StatusCode: %u]", flow->http.response_status_code);

    if (flow->http.request_content_type[0] != '\0')
      fprintf(out, "[Req Content-Type: %s]", flow->http.request_content_type);

    if (flow->http.content_type[0] != '\0')
      fprintf(out, "[Content-Type: %s]", flow->http.content_type);

    if (flow->http.nat_ip[0] != '\0')
      fprintf(out, "[Nat-IP: %s]", flow->http.nat_ip);

    if (flow->http.server[0] != '\0')
      fprintf(out, "[Server: %s]", flow->http.server);

    if (flow->http.user_agent[0] != '\0')
      fprintf(out, "[User-Agent: %s]", flow->http.user_agent);

    if (flow->http.filename[0] != '\0')
      fprintf(out, "[Filename: %s]", flow->http.filename);

    if (flow->risk)
    {
      u_int i;
      u_int16_t cli_score, srv_score;
      fprintf(out, "[Risk: ");

      for (i=0; i<NDPI_MAX_RISK; i++)
        if (NDPI_ISSET_BIT(flow->risk, i))
          fprintf(out, "** %s **", ndpi_risk2str((ndpi_risk_enum)i));

      fprintf(out, "]");

      fprintf(out, "[Risk Score: %u]", ndpi_risk2score(flow->risk, &cli_score, &srv_score));

      if (flow->risk_str)
        fprintf(out, "[Risk Info: %s]", flow->risk_str);
    }

    if (flow->tcp_fingerprint)
      fprintf(out, "[TCP Fingerprint: %s]", flow->tcp_fingerprint);

    if (flow->ssh_tls.ssl_version != 0) fprintf(out, "[%s]", ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
                                                                                 flow->ssh_tls.ssl_version, &known_tls));

    if (flow->ssh_tls.quic_version != 0) fprintf(out, "[QUIC ver: %s]", ndpi_quic_version2str(buf_ver, sizeof(buf_ver),
                                                                                             flow->ssh_tls.quic_version));

    if (flow->ssh_tls.client_hassh[0] != '\0') fprintf(out, "[HASSH-C: %s]", flow->ssh_tls.client_hassh);

    if (flow->ssh_tls.ja4_client[0] != '\0') fprintf(out, "[JA4: %s%s]", flow->ssh_tls.ja4_client,
                                                    print_cipher(flow->ssh_tls.client_unsafe_cipher));

    if (flow->ssh_tls.ja4_client_raw != NULL) fprintf(out, "[JA4_r: %s]", flow->ssh_tls.ja4_client_raw);

    if (flow->ssh_tls.server_info[0] != '\0') fprintf(out, "[Server: %s]", flow->ssh_tls.server_info);

    if (flow->ssh_tls.server_names) fprintf(out, "[ServerNames: %s]", flow->ssh_tls.server_names);
    if (flow->ssh_tls.server_hassh[0] != '\0') fprintf(out, "[HASSH-S: %s]", flow->ssh_tls.server_hassh);

    if (flow->ssh_tls.ja3_server[0] != '\0') fprintf(out, "[JA3S: %s]", flow->ssh_tls.ja3_server);

    if (flow->ssh_tls.tls_issuerDN)  fprintf(out, "[Issuer: %s]", flow->ssh_tls.tls_issuerDN);
    if (flow->ssh_tls.tls_subjectDN) fprintf(out, "[Subject: %s]", flow->ssh_tls.tls_subjectDN);

    if (flow->ssh_tls.encrypted_ch.version != 0)
    {
      fprintf(out, "[ECH: version 0x%x]", flow->ssh_tls.encrypted_ch.version);
    }

    if (flow->ssh_tls.sha1_cert_fingerprint_set)
    {
      fprintf(out, "[Certificate SHA-1: ");
      for (i=0; i<20; i++)
        fprintf(out, "%s%02X", (i > 0) ? ":" : "",
                flow->ssh_tls.sha1_cert_fingerprint[i] & 0xFF);
      fprintf(out, "]");
    }

  if (flow->idle_timeout_sec) fprintf(out, "[Idle Timeout: %d]", flow->idle_timeout_sec);

#ifdef HEURISTICS_CODE
    if (flow->ssh_tls.browser_heuristics.is_safari_tls)  fprintf(out, "[Safari]");
    if (flow->ssh_tls.browser_heuristics.is_firefox_tls) fprintf(out, "[Firefox]");
    if (flow->ssh_tls.browser_heuristics.is_chrome_tls)  fprintf(out, "[Chrome]");
#endif

    if (flow->ssh_tls.notBefore && flow->ssh_tls.notAfter)
    {
      char notBefore[32], notAfter[32];
      struct tm a, b;
      struct tm *before = ndpi_gmtime_r(&flow->ssh_tls.notBefore, &a);
      struct tm *after  = ndpi_gmtime_r(&flow->ssh_tls.notAfter, &b);

      strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
      strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);

      fprintf(out, "[Validity: %s - %s]", notBefore, notAfter);
    }

    char unknown_cipher[8];
    if (flow->ssh_tls.server_cipher != '\0')
      {
        fprintf(out, "[Cipher: %s]", ndpi_cipher2str(flow->ssh_tls.server_cipher, unknown_cipher));
      }
    if (flow->bittorent_hash != NULL) fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);
    if (flow->dhcp_fingerprint != NULL) fprintf(out, "[DHCP Fingerprint: %s]", flow->dhcp_fingerprint);
    if (flow->dhcp_class_ident) fprintf(out, "[DHCP Class Ident: %s]",
                                       flow->dhcp_class_ident);

    if (flow->has_human_readeable_strings) fprintf(out, "[PLAIN TEXT (%s)]",
                                                  flow->human_readeable_string_buffer);

#ifdef DIRECTION_BINS
    print_bin(out, "Plen c2s", &flow->payload_len_bin_src2dst);
    print_bin(out, "Plen s2c", &flow->payload_len_bin_dst2src);
#else
    print_bin(out, "Plen Bins", &flow->payload_len_bin);
#endif

    if (flow->flow_payload && (flow->flow_payload_len > 0))
    {
      u_int i;

      fprintf(out, "[Payload: ");

      for (i=0; i<flow->flow_payload_len; i++)
        fprintf(out, "%c", ndpi_isspace(flow->flow_payload[i]) ? '.' : flow->flow_payload[i]);

      fprintf(out, "]");
    }

    fprintf(out, "\n");
  }
}

/**
 * @brief Get flow byte distribution mean and variance
 */
void
flowGetBDMeanandVariance(struct ndpi_flow_info* flow)
{
  FILE *out = stdout;
  const uint32_t *array = NULL;
  uint32_t tmp[256], i;
  unsigned int num_bytes;
  double mean = 0.0, variance = 0.0;
  struct ndpi_entropy *last_entropy = flow->last_entropy;

  fflush(out);

  if (!last_entropy)
    return;

  /*
   * Sum up the byte_count array for outbound and inbound flows,
   * if this flow is bidirectional
   */
  /* TODO: we could probably use ndpi_data_* generic functions to simplify the code and
     to get rid of `ndpi_flow_get_byte_count_entropy()` */
  if (!flow->bidirectional)
  {
    array = last_entropy->src2dst_byte_count;
    num_bytes = last_entropy->src2dst_l4_bytes;
    for (i = 0; i < 256; i++)
    {
      tmp[i] = last_entropy->src2dst_byte_count[i];
    }

    if (last_entropy->src2dst_num_bytes != 0)
    {
      mean = last_entropy->src2dst_bd_mean;
      variance = last_entropy->src2dst_bd_variance/(last_entropy->src2dst_num_bytes - 1);
      variance = sqrt(variance);

      if (last_entropy->src2dst_num_bytes == 1)
      {
        variance = 0.0;
      }
    }
  }
  else
  {
    for (i = 0; i < 256; i++)
    {
      tmp[i] = last_entropy->src2dst_byte_count[i] + last_entropy->dst2src_byte_count[i];
    }
    array = tmp;
    num_bytes = last_entropy->src2dst_l4_bytes + last_entropy->dst2src_l4_bytes;

    if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes != 0)
    {
      mean = ((double)last_entropy->src2dst_num_bytes) /
	((double)(last_entropy->src2dst_num_bytes+last_entropy->dst2src_num_bytes)) *
          last_entropy->src2dst_bd_mean +
	((double)last_entropy->dst2src_num_bytes) /
          ((double)(last_entropy->dst2src_num_bytes+last_entropy->src2dst_num_bytes)) *
	  last_entropy->dst2src_bd_mean;

      variance = ((double)last_entropy->src2dst_num_bytes) /
	((double)(last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes)) *
          last_entropy->src2dst_bd_variance +
	((double)last_entropy->dst2src_num_bytes) /
          ((double)(last_entropy->dst2src_num_bytes+last_entropy->src2dst_num_bytes)) *
	  last_entropy->dst2src_bd_variance;

      variance = variance/((double)(last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes - 1));
      variance = sqrt(variance);
      if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes == 1)
      {
        variance = 0.0;
      }
    }
  }

  if (enable_flow_stats)
  {
    /* Output the mean */
    if (num_bytes != 0)
    {
      double entropy = ndpi_flow_get_byte_count_entropy(array, num_bytes);

      if (csv_fp)
      {
        fprintf(csv_fp, "|%.3f|%.3f|%.3f|%.3f", mean, variance, entropy, entropy * num_bytes);
      }
      else
      {
        fprintf(out, "[byte_dist_mean: %.3f", mean);
        fprintf(out, "][byte_dist_std: %.3f]", variance);
        fprintf(out, "[entropy: %.3f]", entropy);
        fprintf(out, "[total_entropy: %.3f]", entropy * num_bytes);
      }
    }
    else
    {
      if (csv_fp)
      {
        fprintf(csv_fp, "|%.3f|%.3f|%.3f|%.3f", 0.0, 0.0, 0.0, 0.0);
      }
    }
  }
}

void print_bin(FILE *fout, const char *label, struct ndpi_bin *b)
{
  u_int16_t i;
  const char *sep = label ? "," : ";";

  ndpi_normalize_bin(b);

  if (label) fprintf(fout, "[%s: ", label);

  for (i=0; i<b->num_bins; i++)
  {
    switch(b->family)
    {
    case ndpi_bin_family8:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins8[i]);
      break;
    case ndpi_bin_family16:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins16[i]);
      break;
    case ndpi_bin_family32:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins32[i]);
      break;
    case ndpi_bin_family64:
      fprintf(fout, "%s%llu", (i > 0) ? sep : "", (unsigned long long)b->u.bins64[i]);
      break;
    }
  }

  if (label) fprintf(fout, "]");
}

const char* print_cipher(ndpi_cipher_weakness c)
{
  switch(c)
  {
  case ndpi_cipher_insecure:
    return " (INSECURE)";
    break;

  case ndpi_cipher_weak:
    return " (WEAK)";
    break;

  default:
    return "";
  }
}

void print_ndpi_address_port_list_file(FILE *out, const char *label, ndpi_address_port_list *list)
{
  unsigned int i;
  ndpi_address_port *ap;

  if (list->num_aps == 0)
    return;
  fprintf(out, "[%s: ", label);
  for (i = 0; i < list->num_aps; i++)
  {
    ap = &list->aps[i];
    if (ap->port != 0)
    {
      char buf[INET6_ADDRSTRLEN];

      if (ap->is_ipv6)
      {
        inet_ntop(AF_INET6, &ap->address, buf, sizeof(buf));
        fprintf(out, "[%s]:%u", buf, ap->port);
      }
      else
      {
        inet_ntop(AF_INET, &ap->address, buf, sizeof(buf));
        fprintf(out, "%s:%u", buf, ap->port);
      }

      if (i != list->num_aps - 1)
	fprintf(out, ", ");
    }
  }
  fprintf(out, "]");
}

double ndpi_flow_get_byte_count_entropy(
  const uint32_t byte_count[256],
  unsigned int num_bytes)
{
  double sum = 0.0;

  for (int i = 0; i < 256; ++i)
  {
    double tmp = (double) byte_count[i] / (double) num_bytes;

    if (tmp > FLT_EPSILON)
    {
      sum -= tmp * logf(tmp);
    }
  }

  return(sum / log(2.0));
}

void print_flowSerialized(struct ndpi_flow_info *flow)
{
  char *json_str = NULL;
  u_int32_t json_str_len = 0;
  ndpi_serializer * const serializer = &flow->ndpi_flow_serializer;
  //float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
  double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;
  float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

  ndpi_serialize_string_uint32(serializer, "flow_id", flow->flow_id);
  ndpi_serialize_string_double(serializer, "first_seen", f / 1000., "%.3f");
  ndpi_serialize_string_double(serializer, "last_seen", l / 1000., "%.3f");
  ndpi_serialize_string_double(serializer, "duration", (l-f)/1000.0, "%.3f");
  ndpi_serialize_string_uint32(serializer, "vlan_id", flow->vlan_id);
  ndpi_serialize_string_uint32(serializer, "bidirectional", flow->bidirectional);

  /* XFER Packets/Bytes */
  ndpi_serialize_start_of_block(serializer, "xfer");
  ndpi_serialize_string_float(serializer, "data_ratio", data_ratio, "%.3f");
  ndpi_serialize_string_string(serializer, "data_ratio_str", ndpi_data_ratio2str(data_ratio));
  ndpi_serialize_string_uint32(serializer, "src2dst_packets", flow->src2dst_packets);
  ndpi_serialize_string_uint64(serializer, "src2dst_bytes",
                               (u_int64_t)flow->src2dst_bytes);
  ndpi_serialize_string_uint64(serializer, "src2dst_goodput_bytes",
                               (u_int64_t)flow->src2dst_goodput_bytes);
  ndpi_serialize_string_uint32(serializer, "dst2src_packets", flow->dst2src_packets);
  ndpi_serialize_string_uint64(serializer, "dst2src_bytes",
                               (u_int64_t)flow->dst2src_bytes);
  ndpi_serialize_string_uint64(serializer, "dst2src_goodput_bytes",
                               (u_int64_t)flow->dst2src_goodput_bytes);
  ndpi_serialize_end_of_block(serializer);

  /* IAT (Inter Arrival Time) */
  ndpi_serialize_start_of_block(serializer, "iat");
  ndpi_serialize_string_uint32(serializer, "flow_min", ndpi_data_min(flow->iat_flow));
  ndpi_serialize_string_float(serializer, "flow_avg",
                              ndpi_data_average(flow->iat_flow), "%.1f");
  ndpi_serialize_string_uint32(serializer, "flow_max", ndpi_data_max(flow->iat_flow));
  ndpi_serialize_string_float(serializer, "flow_stddev",
                              ndpi_data_stddev(flow->iat_flow), "%.1f");

  ndpi_serialize_string_uint32(serializer, "c_to_s_min",
                               ndpi_data_min(flow->iat_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_avg",
                              ndpi_data_average(flow->iat_c_to_s), "%.1f");
  ndpi_serialize_string_uint32(serializer, "c_to_s_max",
                               ndpi_data_max(flow->iat_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_stddev",
                              ndpi_data_stddev(flow->iat_c_to_s), "%.1f");

  ndpi_serialize_string_uint32(serializer, "s_to_c_min",
                               ndpi_data_min(flow->iat_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_avg",
                              ndpi_data_average(flow->iat_s_to_c), "%.1f");
  ndpi_serialize_string_uint32(serializer, "s_to_c_max",
                               ndpi_data_max(flow->iat_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_stddev",
                              ndpi_data_stddev(flow->iat_s_to_c), "%.1f");
  ndpi_serialize_end_of_block(serializer);

  /* Packet Length */
  ndpi_serialize_start_of_block(serializer, "pktlen");
  ndpi_serialize_string_uint32(serializer, "c_to_s_min",
                               ndpi_data_min(flow->pktlen_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_avg",
                              ndpi_data_average(flow->pktlen_c_to_s), "%.1f");
  ndpi_serialize_string_uint32(serializer, "c_to_s_max",
                               ndpi_data_max(flow->pktlen_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_stddev",
                              ndpi_data_stddev(flow->pktlen_c_to_s), "%.1f");

  ndpi_serialize_string_uint32(serializer, "s_to_c_min",
                               ndpi_data_min(flow->pktlen_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_avg",
                              ndpi_data_average(flow->pktlen_s_to_c), "%.1f");
  ndpi_serialize_string_uint32(serializer, "s_to_c_max",
                               ndpi_data_max(flow->pktlen_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_stddev",
                              ndpi_data_stddev(flow->pktlen_s_to_c), "%.1f");
  ndpi_serialize_end_of_block(serializer);

  /* TCP flags */
  ndpi_serialize_start_of_block(serializer, "tcp_flags");
  ndpi_serialize_string_int32(serializer, "cwr_count", flow->cwr_count);
  ndpi_serialize_string_int32(serializer, "ece_count", flow->ece_count);
  ndpi_serialize_string_int32(serializer, "urg_count", flow->urg_count);
  ndpi_serialize_string_int32(serializer, "ack_count", flow->ack_count);
  ndpi_serialize_string_int32(serializer, "psh_count", flow->psh_count);
  ndpi_serialize_string_int32(serializer, "rst_count", flow->rst_count);
  ndpi_serialize_string_int32(serializer, "syn_count", flow->syn_count);
  ndpi_serialize_string_int32(serializer, "fin_count", flow->fin_count);

  ndpi_serialize_string_int32(serializer, "src2dst_cwr_count", flow->src2dst_cwr_count);
  ndpi_serialize_string_int32(serializer, "src2dst_ece_count", flow->src2dst_ece_count);
  ndpi_serialize_string_int32(serializer, "src2dst_urg_count", flow->src2dst_urg_count);
  ndpi_serialize_string_int32(serializer, "src2dst_ack_count", flow->src2dst_ack_count);
  ndpi_serialize_string_int32(serializer, "src2dst_psh_count", flow->src2dst_psh_count);
  ndpi_serialize_string_int32(serializer, "src2dst_rst_count", flow->src2dst_rst_count);
  ndpi_serialize_string_int32(serializer, "src2dst_syn_count", flow->src2dst_syn_count);
  ndpi_serialize_string_int32(serializer, "src2dst_fin_count", flow->src2dst_fin_count);

  ndpi_serialize_string_int32(serializer, "dst2src_cwr_count", flow->dst2src_cwr_count);
  ndpi_serialize_string_int32(serializer, "dst2src_ece_count", flow->dst2src_ece_count);
  ndpi_serialize_string_int32(serializer, "dst2src_urg_count", flow->dst2src_urg_count);
  ndpi_serialize_string_int32(serializer, "dst2src_ack_count", flow->dst2src_ack_count);
  ndpi_serialize_string_int32(serializer, "dst2src_psh_count", flow->dst2src_psh_count);
  ndpi_serialize_string_int32(serializer, "dst2src_rst_count", flow->dst2src_rst_count);
  ndpi_serialize_string_int32(serializer, "dst2src_syn_count", flow->dst2src_syn_count);
  ndpi_serialize_string_int32(serializer, "dst2src_fin_count", flow->dst2src_fin_count);
  ndpi_serialize_end_of_block(serializer);

  /* TCP window */
  ndpi_serialize_string_uint32(serializer, "c_to_s_init_win", flow->c_to_s_init_win);
  ndpi_serialize_string_uint32(serializer, "s_to_c_init_win", flow->s_to_c_init_win);

  json_str = ndpi_serializer_get_buffer(serializer, &json_str_len);
  if (json_str == NULL || json_str_len == 0)
  {
    printf("ERROR: nDPI serialization failed\n");
    exit(-1);
  }

  fprintf(serialization_fp, "%.*s\n", (int)json_str_len, json_str);
}
