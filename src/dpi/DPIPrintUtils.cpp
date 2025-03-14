#include <netinet/ip.h>
#include <math.h>
#include <float.h> /* FLT_EPSILON */

#include "DPIPrintUtils.hpp"

FILE* csv_fp = NULL;
u_int8_t verbose = 0;
bool enable_flow_stats = false;
bool enable_payload_analyzer = false;
FILE* serialization_fp = NULL; /**< for TLV,CSV,JSON export */
u_int8_t quiet_mode = 0;
u_int8_t stats_flag = 0;
u_int8_t live_capture = 0;
u_int8_t num_threads = 1;
u_int32_t risks_found = 0;
struct ndpi_stats cumulative_stats;
struct port_stats* srcStats = NULL;
struct port_stats* dstStats = NULL;
int dump_fpc_stats = 0;
int enable_malloc_bins = 0;
u_int8_t dump_internal_stats = 0;
u_int8_t enable_doh_dot_detection = 0;
u_int8_t num_bin_clusters = 0;
struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];
struct timeval pcap_start = {0, 0};
struct timeval pcap_end = {0, 0};

static u_int32_t flows_with_risks = 0;
static u_int32_t risk_stats[NDPI_MAX_RISK] = { 0 };
static struct flow_info *all_flows;
static u_int32_t num_flows;
static struct receiver* receivers = NULL;
static struct receiver* topReceivers = NULL;
static struct single_flow_info* scannerHosts = NULL;
static float doh_max_distance = 35.5;

DPIHandleHolder dpi_handle_holder;

// struct to add more statitcs in function printFlowStats
typedef struct hash_stats{
  char* domain_name;
  int occurency;       /* how many time domain name occury in the flow */
  UT_hash_handle hh;   /* hashtable to collect the stats */
} hash_stats;

struct port_stats {
  u_int32_t port; /* we'll use this field as the key */
  u_int32_t num_pkts, num_bytes;
  u_int32_t num_flows;
  u_int32_t num_addr; /*number of distinct IP addresses */
  u_int32_t cumulative_addr; /*cumulative some of IP addresses */
  addr_node *addr_tree; /* tree of distinct IP addresses */
  struct info_pair top_ip_addrs[MAX_NUM_IP_ADDRESS];
  u_int8_t hasTopHost; /* as boolean flag */
  u_int32_t top_host;  /* host that is contributed to > 95% of traffic */
  u_int8_t version;    /* top host's ip version */
  char proto[16];      /* application level protocol of top host */
  UT_hash_handle hh;   /* makes this structure hashable */
};

void freeIpTree(addr_node *root)
{
  if (root == NULL)
    return;

  freeIpTree(root->left);
  freeIpTree(root->right);
  ndpi_free(root);
}

char* format_traffic(float numBits, int bits, char *buf)
{
  char unit;

  if (bits)
  {
    unit = 'b';
  }
  else
  {
    unit = 'B';
  }

  if (numBits < 1024)
  {
    ndpi_snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  }
  else if (numBits < (1024*1024))
  {
    ndpi_snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  }
  else
  {
    float tmpMBits = ((float)numBits)/(1024*1024);

    if (tmpMBits < 1024)
    {
      ndpi_snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    }
    else
    {
      tmpMBits /= 1024;

      if (tmpMBits < 1024)
      {
        ndpi_snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      }
      else
      {
        ndpi_snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return buf;
}

void deleteReceivers(struct receiver *rcvrs)
{
  struct receiver *current, *tmp;

  HASH_ITER(hh, rcvrs, current, tmp)
  {
    HASH_DEL(rcvrs, current);
    ndpi_free(current);
  }
}

void deletePortsStats(struct port_stats *stats)
{
  struct port_stats *current_port, *tmp;

  HASH_ITER(hh, stats, current_port, tmp)
  {
    HASH_DEL(stats, current_port);
    freeIpTree(current_port->addr_tree);
    ndpi_free(current_port);
  }
}

char* formatPackets(float numPkts, char *buf)
{
  if (numPkts < 1000)
  {
    ndpi_snprintf(buf, 32, "%.2f", numPkts);
  }
  else if (numPkts < (1000*1000))
  {
    ndpi_snprintf(buf, 32, "%.2f K", numPkts/1000);
  }
  else
  {
    numPkts /= (1000*1000);
    ndpi_snprintf(buf, 32, "%.2f M", numPkts);
  }

  return buf;
}

void node_print_known_proto_walker(
  const void *node,
  ndpi_VISIT which,
  int depth,
  void *user_data)
{
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  (void)depth;

  if ((flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN))
  {
    return;
  }
  
  if ((which == ndpi_preorder) || (which == ndpi_leaf))
  {
    /* Avoid walking the same node multiple times */
    all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
    num_flows++;
  }
}

void node_print_unknown_proto_walker(
  const void *node,
  ndpi_VISIT which,
  int depth,
  void *user_data)
{
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  (void)depth;

  if ((flow->detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (flow->detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN))
  {
    return;
  }

  if ((which == ndpi_preorder) || (which == ndpi_leaf))
  {
    /* Avoid walking the same node multiple times */
    all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
    num_flows++;
  }
}

void node_flow_risk_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
  struct ndpi_flow_info *f = *(struct ndpi_flow_info**)node;

  (void)depth;
  (void)user_data;

  if ((which == ndpi_preorder) || (which == ndpi_leaf))
  {
    /* Avoid walking the same node multiple times */
    if (f->risk)
    {
      flows_with_risks++;

      for (u_int j = 0; j < NDPI_MAX_RISK; j++)
      {
        ndpi_risk_enum r = (ndpi_risk_enum)j;

        if (NDPI_ISSET_BIT(f->risk, r))
        {
          risks_found++, risk_stats[r]++;
        }
      }
    }
  }
}

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

void print_risk_stats()
{
  if (!quiet_mode)
  {
    for (u_int thread_id = 0; thread_id < num_threads; thread_id++)
    {
      for (u_int i = 0; i < NUM_ROOTS; i++)
      {
        ndpi_twalk(
          dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
          node_flow_risk_walker,
          &thread_id);
      }
    }

    if (risks_found)
    {
      printf("\nRisk stats [found %u (%.1f %%) flows with risks]:\n",
        flows_with_risks,
        (100. * flows_with_risks) / (float)cumulative_stats.ndpi_flow_count);

      for (u_int i = 0; i < NDPI_MAX_RISK; i++)
      {
        ndpi_risk_enum r = (ndpi_risk_enum)i;

        if (risk_stats[r] != 0)
        {
          printf("\t%-40s %5u [%4.01f %%]\n", ndpi_risk2str(r), risk_stats[r],
            (float)(risk_stats[r]*100) / (float)risks_found);
        }
      }

      printf("\n\tNOTE: as one flow can have multiple risks set, the sum of the\n"
             "\t      last column can exceed the number of flows with risks.\n");
      printf("\n\n");
    }
  }
}

int hash_stats_sort_to_print(void *_a, void *_b)
{
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (b->occurency - a->occurency);
}

int hash_stats_sort_to_order(void *_a, void *_b)
{
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (a->occurency - b->occurency);
}

int cmp_flows(const void *_a, const void *_b)
{
  struct ndpi_flow_info *fa = ((struct flow_info*)_a)->flow;
  struct ndpi_flow_info *fb = ((struct flow_info*)_b)->flow;
  uint64_t a_size = fa->src2dst_bytes + fa->dst2src_bytes;
  uint64_t b_size = fb->src2dst_bytes + fb->dst2src_bytes;
  if (a_size != b_size)
    return a_size < b_size ? 1 : -1;

  // copy from ndpi_workflow_node_cmp();

  if (fa->ip_version < fb->ip_version ) return(-1); else { if (fa->ip_version > fb->ip_version ) return(1); }
  if (fa->protocol   < fb->protocol   ) return(-1); else { if (fa->protocol   > fb->protocol   ) return(1); }
  if (htonl(fa->src_ip)   < htonl(fb->src_ip)  ) return(-1); else { if (htonl(fa->src_ip)   > htonl(fb->src_ip)  ) return(1); }
  if (htons(fa->src_port) < htons(fb->src_port)) return(-1); else { if (htons(fa->src_port) > htons(fb->src_port)) return(1); }
  if (htonl(fa->dst_ip)   < htonl(fb->dst_ip)  ) return(-1); else { if (htonl(fa->dst_ip)   > htonl(fb->dst_ip)  ) return(1); }
  if (htons(fa->dst_port) < htons(fb->dst_port)) return(-1); else { if (htons(fa->dst_port) > htons(fb->dst_port)) return(1); }
  if (fa->vlan_id < fb->vlan_id) return(-1); else { if (fa->vlan_id > fb->vlan_id) return(1); }
  return(0);
}

u_int check_bin_doh_similarity(struct ndpi_bin *bin, float *similarity)
{
  float lowest_similarity = 9999999999.0f;

  for (u_int i = 0; i < NUM_DOH_BINS; i++)
  {
    *similarity = ndpi_bin_similarity(&doh_ndpi_bins[i], bin, 0, 0);

    if (*similarity < 0) /* Error */
    {
      return 0;
    }

    if (*similarity <= doh_max_distance)
    {
      return 1;
    }

    if (*similarity < lowest_similarity)
    {
      lowest_similarity = *similarity;
    }
    
  }

  *similarity = lowest_similarity;

  return 0;
}

void print_flows_stats()
{
  int thread_id;
  u_int32_t total_flows = 0;
  FILE *out = stdout;

  if (enable_payload_analyzer)
  {
    ndpi_report_payload_stats(out);
  }

  for (thread_id = 0; thread_id < num_threads; thread_id++)
  {
    total_flows += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->num_allocated_flows;
  }

  if ((all_flows = (struct flow_info*)ndpi_malloc(sizeof(struct flow_info)*total_flows)) == NULL)
  {
    fprintf(out, "Fatal error: not enough memory\n");
    exit(-1);
  }

  if (verbose)
  {
    ndpi_host_ja_fingerprints *jaByHostsHashT = NULL; // outer hash table
    ndpi_ja_fingerprints_host *hostByJA4C_ht = NULL;   // for client
    ndpi_ja_fingerprints_host *hostByJA3S_ht = NULL;   // for server
    unsigned int i;
    ndpi_host_ja_fingerprints *jaByHost_element = NULL;
    ndpi_ja_info *info_of_element = NULL;
    ndpi_host_ja_fingerprints *tmp = NULL;
    ndpi_ja_info *tmp2 = NULL;
    unsigned int num_ja4_client;
    unsigned int num_ja3_server;

    fprintf(out, "\n");

    num_flows = 0;
    for (thread_id = 0; thread_id < num_threads; thread_id++)
    {
      for (i = 0; i < NUM_ROOTS; i++)
      {
        ndpi_twalk(
          dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
          node_print_known_proto_walker,
          &thread_id);
      }
    }

    if ((verbose == 2) || (verbose == 3))
    {
      // We are going to print JA4C and JA3S stats
      for (i = 0; i < num_flows; i++)
      {
        ndpi_host_ja_fingerprints *jaByHostFound = NULL;
        ndpi_ja_fingerprints_host *hostByJAFound = NULL;

        //check if this is a ssh-ssl flow
        if (all_flows[i].flow->ssh_tls.ja4_client[0] != '\0')
	{
          //looking if the host is already in the hash table
          HASH_FIND_INT(jaByHostsHashT, &(all_flows[i].flow->src_ip), jaByHostFound);

          //host ip -> ja4c
          if (jaByHostFound == NULL)
	  {
            //adding the new host
            ndpi_host_ja_fingerprints *newHost = (ndpi_host_ja_fingerprints*)ndpi_malloc(
              sizeof(ndpi_host_ja_fingerprints));
            newHost->host_client_info_hasht = NULL;
            newHost->host_server_info_hasht = NULL;
            newHost->ip_string = all_flows[i].flow->src_name;
            newHost->ip = all_flows[i].flow->src_ip;
            newHost->dns_name = all_flows[i].flow->host_server_name;

            ndpi_ja_info *newJA = (ndpi_ja_info*)ndpi_malloc(sizeof(ndpi_ja_info));
            newJA->ja = all_flows[i].flow->ssh_tls.ja4_client;
            newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
            //adding the new ja4c fingerprint
            HASH_ADD_KEYPTR(hh, newHost->host_client_info_hasht,
                            newJA->ja, strlen(newJA->ja), newJA);
            //adding the new host
            HASH_ADD_INT(jaByHostsHashT, ip, newHost);
          }
          else
          {
            //host already in the hash table
            ndpi_ja_info *infoFound = NULL;

            HASH_FIND_STR(jaByHostFound->host_client_info_hasht,
                          all_flows[i].flow->ssh_tls.ja4_client, infoFound);

            if (infoFound == NULL)
	    {
              ndpi_ja_info *newJA = (ndpi_ja_info*)ndpi_malloc(sizeof(ndpi_ja_info));
              newJA->ja = all_flows[i].flow->ssh_tls.ja4_client;
              newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
              HASH_ADD_KEYPTR(hh, jaByHostFound->host_client_info_hasht,
                              newJA->ja, strlen(newJA->ja), newJA);
            }
          }

          // ja4c -> host ip
          HASH_FIND_STR(hostByJA4C_ht, all_flows[i].flow->ssh_tls.ja4_client, hostByJAFound);
          if (hostByJAFound == NULL)
	  {
            ndpi_ip_dns *newHost = (ndpi_ip_dns*)ndpi_malloc(sizeof(ndpi_ip_dns));

            newHost->ip = all_flows[i].flow->src_ip;
            newHost->ip_string = all_flows[i].flow->src_name;
            newHost->dns_name = all_flows[i].flow->host_server_name;

            ndpi_ja_fingerprints_host *newElement = (ndpi_ja_fingerprints_host*)ndpi_malloc(
              sizeof(ndpi_ja_fingerprints_host));
            newElement->ja = all_flows[i].flow->ssh_tls.ja4_client;
            newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
            newElement->ipToDNS_ht = NULL;

            HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
            HASH_ADD_KEYPTR(hh, hostByJA4C_ht, newElement->ja, strlen(newElement->ja),
              newElement);
          }
          else
          {
            ndpi_ip_dns *innerElement = NULL;
            HASH_FIND_INT(hostByJAFound->ipToDNS_ht, &(all_flows[i].flow->src_ip), innerElement);
            if (innerElement == NULL)
	    {
              ndpi_ip_dns *newInnerElement = (ndpi_ip_dns*)ndpi_malloc(sizeof(ndpi_ip_dns));
              newInnerElement->ip = all_flows[i].flow->src_ip;
              newInnerElement->ip_string = all_flows[i].flow->src_name;
              newInnerElement->dns_name = all_flows[i].flow->host_server_name;
              HASH_ADD_INT(hostByJAFound->ipToDNS_ht, ip, newInnerElement);
            }
          }
        }

        if (all_flows[i].flow->ssh_tls.ja3_server[0] != '\0')
	{
          // Looking if the host is already in the hash table
          HASH_FIND_INT(jaByHostsHashT, &(all_flows[i].flow->dst_ip), jaByHostFound);
          if (jaByHostFound == NULL)
	  {
            // Adding the new host in the hash table
            ndpi_host_ja_fingerprints *newHost = (ndpi_host_ja_fingerprints*)ndpi_malloc(
              sizeof(ndpi_host_ja_fingerprints));
            newHost->host_client_info_hasht = NULL;
            newHost->host_server_info_hasht = NULL;
            newHost->ip_string = all_flows[i].flow->dst_name;
            newHost->ip = all_flows[i].flow->dst_ip;
            newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;

            ndpi_ja_info *newJA = (ndpi_ja_info*)ndpi_malloc(sizeof(ndpi_ja_info));
            newJA->ja = all_flows[i].flow->ssh_tls.ja3_server;
            newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
            //adding the new ja3s fingerprint
            HASH_ADD_KEYPTR(hh, newHost->host_server_info_hasht, newJA->ja,
                            strlen(newJA->ja), newJA);
            //adding the new host
            HASH_ADD_INT(jaByHostsHashT, ip, newHost);
          }
	  else
	  {
            //host already in the hashtable
            ndpi_ja_info *infoFound = NULL;
            HASH_FIND_STR(jaByHostFound->host_server_info_hasht,
                          all_flows[i].flow->ssh_tls.ja3_server, infoFound);
            if (infoFound == NULL)
	    {
              ndpi_ja_info *newJA = (ndpi_ja_info*)ndpi_malloc(sizeof(ndpi_ja_info));
              newJA->ja = all_flows[i].flow->ssh_tls.ja3_server;
              newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
              HASH_ADD_KEYPTR(hh, jaByHostFound->host_server_info_hasht,
                              newJA->ja, strlen(newJA->ja), newJA);
            }
          }

          HASH_FIND_STR(hostByJA3S_ht, all_flows[i].flow->ssh_tls.ja3_server, hostByJAFound);
          if (hostByJAFound == NULL)
          {
            ndpi_ip_dns *newHost = (ndpi_ip_dns*)ndpi_malloc(sizeof(ndpi_ip_dns));

            newHost->ip = all_flows[i].flow->dst_ip;
            newHost->ip_string = all_flows[i].flow->dst_name;
            newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;;

            ndpi_ja_fingerprints_host *newElement = (ndpi_ja_fingerprints_host*)ndpi_malloc(sizeof(ndpi_ja_fingerprints_host));
            newElement->ja = all_flows[i].flow->ssh_tls.ja3_server;
            newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
            newElement->ipToDNS_ht = NULL;

            HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
            HASH_ADD_KEYPTR(hh, hostByJA3S_ht, newElement->ja, strlen(newElement->ja),
                            newElement);
          } else {
            ndpi_ip_dns *innerElement = NULL;

            HASH_FIND_INT(hostByJAFound->ipToDNS_ht, &(all_flows[i].flow->dst_ip), innerElement);
            if (innerElement == NULL)
            {
              ndpi_ip_dns *newInnerElement = (ndpi_ip_dns*)ndpi_malloc(sizeof(ndpi_ip_dns));
              newInnerElement->ip = all_flows[i].flow->dst_ip;
              newInnerElement->ip_string = all_flows[i].flow->dst_name;
              newInnerElement->dns_name = all_flows[i].flow->ssh_tls.server_info;
              HASH_ADD_INT(hostByJAFound->ipToDNS_ht, ip, newInnerElement);
            }
          }
        }
      }

      if (jaByHostsHashT)
      {
        ndpi_ja_fingerprints_host *hostByJAElement = NULL;
        ndpi_ja_fingerprints_host *tmp3 = NULL;
        ndpi_ip_dns *innerHashEl = NULL;
        ndpi_ip_dns *tmp4 = NULL;

        if (verbose == 2)
        {
          /* for each host the number of flow with a ja4c fingerprint is printed */
          i = 1;

          fprintf(out, "JA Host Stats: \n");
          fprintf(out, "\t\t IP %-24s \t %-10s \n", "Address", "# JA4C");

          for (jaByHost_element = jaByHostsHashT; jaByHost_element != NULL;
              jaByHost_element = (ndpi_host_ja_fingerprints*)jaByHost_element->hh.next)
          {
            num_ja4_client = HASH_COUNT(jaByHost_element->host_client_info_hasht);
            num_ja3_server = HASH_COUNT(jaByHost_element->host_server_info_hasht);

            if (num_ja4_client > 0)
            {
              fprintf(out, "\t%d\t %-24s \t %-7u\n",
                      i,
                      jaByHost_element->ip_string,
                      num_ja4_client
                      );
              i++;
            }

          }
        }
        else if (verbose == 3)
        {
          int i = 1;
          int againstRepeat;
          ndpi_ja_fingerprints_host *hostByJAElement = NULL;
          ndpi_ja_fingerprints_host *tmp3 = NULL;
          ndpi_ip_dns *innerHashEl = NULL;
          ndpi_ip_dns *tmp4 = NULL;

          //for each host it is printted the JA4C and JA3S, along the server name (if any)
          //and the security status

          fprintf(out, "JA4C/JA3S Host Stats: \n");
          fprintf(out, "\t%-7s %-24s %-44s %s\n", "", "IP", "JA4C", "JA3S");

          //reminder
          //jaByHostsHashT: hash table <ip, (ja, ht_client, ht_server)>
          //jaByHost_element: element of jaByHostsHashT
          //info_of_element: element of the inner hash table of jaByHost_element
          HASH_ITER(hh, jaByHostsHashT, jaByHost_element, tmp)
          {
            num_ja4_client = HASH_COUNT(jaByHost_element->host_client_info_hasht);
            num_ja3_server = HASH_COUNT(jaByHost_element->host_server_info_hasht);
            againstRepeat = 0;
            if (num_ja4_client > 0)
            {
              HASH_ITER(hh, jaByHost_element->host_client_info_hasht, info_of_element, tmp2)
              {
                fprintf(out, "\t%-7d %-24s %s %s\n",
                  i,
                  jaByHost_element->ip_string,
                  info_of_element->ja,
                  print_cipher(info_of_element->unsafe_cipher)
                  );
                againstRepeat = 1;
                i++;
              }
            }

            if (num_ja3_server > 0)
            {
              HASH_ITER(hh, jaByHost_element->host_server_info_hasht, info_of_element, tmp2)
              {
                fprintf(out, "\t%-7d %-24s %-44s %s %s %s%s%s\n",
                  i,
                  jaByHost_element->ip_string,
                  "",
                  info_of_element->ja,
                  print_cipher(info_of_element->unsafe_cipher),
                  jaByHost_element->dns_name[0] ? "[" : "",
                  jaByHost_element->dns_name,
                  jaByHost_element->dns_name[0] ? "]" : ""
                  );
                i++;
              }
            }
          }

          i = 1;

          fprintf(out, "\nIP/JA Distribution:\n");
          fprintf(out, "%-15s %-43s %-26s\n", "", "JA", "IP");
          HASH_ITER(hh, hostByJA4C_ht, hostByJAElement, tmp3)
          {
            againstRepeat = 0;
            HASH_ITER(hh, hostByJAElement->ipToDNS_ht, innerHashEl, tmp4)
            {
              if (againstRepeat == 0)
              {
                fprintf(out, "\t%-7d JA4C %s",
                        i,
                        hostByJAElement->ja
                        );
                fprintf(out, "   %-20s %s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher)
                        );
                againstRepeat = 1;
                i++;
              }
              else
              {
                fprintf(out, "\t%45s", "");
                fprintf(out, "   %-15s %s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher)
                        );
              }
            }
          }

          HASH_ITER(hh, hostByJA3S_ht, hostByJAElement, tmp3)
          {
            againstRepeat = 0;
            HASH_ITER(hh, hostByJAElement->ipToDNS_ht, innerHashEl, tmp4)
            {
              if (againstRepeat == 0)
              {
                fprintf(out, "\t%-7d JA3S %s",
                        i,
                        hostByJAElement->ja
                        );
                fprintf(out, "   %-15s %-10s %s%s%s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher),
                        innerHashEl->dns_name[0] ? "[" : "",
                        innerHashEl->dns_name,
                        innerHashEl->dns_name[0] ? "]" : ""
                        );
                againstRepeat = 1;
                i++;
              } else {
                fprintf(out, "\t%45s", "");
                fprintf(out, "   %-15s %-10s %s%s%s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher),
                        innerHashEl->dns_name[0] ? "[" : "",
                        innerHashEl->dns_name,
                        innerHashEl->dns_name[0] ? "]" : ""
                        );
              }
            }
          }
        }
        fprintf(out, "\n\n");

        //freeing the hash table
        HASH_ITER(hh, jaByHostsHashT, jaByHost_element, tmp)
        {
          HASH_ITER(hh, jaByHost_element->host_client_info_hasht, info_of_element, tmp2)
          {
            if (jaByHost_element->host_client_info_hasht)
              HASH_DEL(jaByHost_element->host_client_info_hasht, info_of_element);
            ndpi_free(info_of_element);
          }
          HASH_ITER(hh, jaByHost_element->host_server_info_hasht, info_of_element, tmp2)
          {
            if (jaByHost_element->host_server_info_hasht)
              HASH_DEL(jaByHost_element->host_server_info_hasht, info_of_element);
            ndpi_free(info_of_element);
          }
          HASH_DEL(jaByHostsHashT, jaByHost_element);
          ndpi_free(jaByHost_element);
        }

        HASH_ITER(hh, hostByJA4C_ht, hostByJAElement, tmp3)
        {
          HASH_ITER(hh, hostByJA4C_ht->ipToDNS_ht, innerHashEl, tmp4)
          {
            if (hostByJAElement->ipToDNS_ht)
              HASH_DEL(hostByJAElement->ipToDNS_ht, innerHashEl);
            ndpi_free(innerHashEl);
          }
          HASH_DEL(hostByJA4C_ht, hostByJAElement);
          ndpi_free(hostByJAElement);
        }

        hostByJAElement = NULL;
        HASH_ITER(hh, hostByJA3S_ht, hostByJAElement, tmp3)
        {
          HASH_ITER(hh, hostByJA3S_ht->ipToDNS_ht, innerHashEl, tmp4)
          {
            if (hostByJAElement->ipToDNS_ht)
              HASH_DEL(hostByJAElement->ipToDNS_ht, innerHashEl);
            ndpi_free(innerHashEl);
          }
          HASH_DEL(hostByJA3S_ht, hostByJAElement);
          ndpi_free(hostByJAElement);
        }
      }
    }

    if (verbose == 4)
    {
      // How long the table could be
      unsigned int len_table_max = 1000;
      // Number of element to delete when the table is full
      int toDelete = 10;
      struct hash_stats *hostsHashT = NULL;
      struct hash_stats *host_iter = NULL;
      struct hash_stats *tmp = NULL;
      int len_max = 0;

      for (i = 0; i < num_flows; i++)
      {
	if (all_flows[i].flow->host_server_name[0] != '\0')
        {
	  int len = strlen(all_flows[i].flow->host_server_name);
	  len_max = ndpi_max(len,len_max);

	  struct hash_stats *hostFound;
	  HASH_FIND_STR(hostsHashT, all_flows[i].flow->host_server_name, hostFound);

	  if (hostFound == NULL)
          {
	    struct hash_stats *newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));
	    newHost->domain_name = all_flows[i].flow->host_server_name;
	    newHost->occurency = 1;
	    if (HASH_COUNT(hostsHashT) == len_table_max)
            {
	      int i = 0;
	      while (i <= toDelete)
              {
		HASH_ITER(hh, hostsHashT, host_iter, tmp)
                {
		  HASH_DEL(hostsHashT,host_iter);
		  free(host_iter);
		  i++;
		}
	      }
	    }

	    HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
	  }
          else
          {
	    hostFound->occurency++;
          }
	}

	if (all_flows[i].flow->ssh_tls.server_info[0] != '\0')
        {
	  int len = strlen(all_flows[i].flow->host_server_name);
	  len_max = ndpi_max(len,len_max);

	  struct hash_stats *hostFound;
	  HASH_FIND_STR(hostsHashT, all_flows[i].flow->ssh_tls.server_info, hostFound);

	  if (hostFound == NULL)
          {
	    struct hash_stats *newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));

	    newHost->domain_name = all_flows[i].flow->ssh_tls.server_info;
	    newHost->occurency = 1;

	    if ((HASH_COUNT(hostsHashT)) == len_table_max)
            {
	      int i = 0;
	      while (i < toDelete)
              {
		HASH_ITER(hh, hostsHashT, host_iter, tmp)
                {
		  HASH_DEL(hostsHashT,host_iter);
		  ndpi_free(host_iter);
		  i++;
		}
	      }
	    }

	    HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
	  }
          else
          {
	    hostFound->occurency++;
          }
	}

	//sort the table by the least occurency
	HASH_SORT(hostsHashT, hash_stats_sort_to_order);
      }

      //sort the table in decreasing order to print
      HASH_SORT(hostsHashT, hash_stats_sort_to_print);

      //print the element of the hash table
      int j;
      HASH_ITER(hh, hostsHashT, host_iter, tmp)
      {
	printf("\t%s", host_iter->domain_name);
	//to print the occurency in aligned column
	int diff = len_max-strlen(host_iter->domain_name);
	for (j = 0; j <= diff+5;j++)
	  printf (" ");
	printf("%d\n",host_iter->occurency);
      }
      printf("%s", "\n\n");

      // Freeing the hash table
      HASH_ITER(hh, hostsHashT, host_iter, tmp)
      {
	HASH_DEL(hostsHashT, host_iter);
	ndpi_free(host_iter);
      }
    }

    // Print all flows stats
    qsort(all_flows, num_flows, sizeof(struct flow_info), cmp_flows);

    if (verbose > 1)
    {
#ifndef DIRECTION_BINS
      struct ndpi_bin* bins = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin) * num_flows);
      u_int16_t* cluster_ids = (u_int16_t*)ndpi_malloc(sizeof(u_int16_t) * num_flows);
      u_int32_t num_flow_bins = 0;
#endif

      for (i = 0; i < num_flows; i++)
      {
#ifndef DIRECTION_BINS
        if (enable_doh_dot_detection)
        {
          /* Discard flows with few packets per direction */
          if ((all_flows[i].flow->src2dst_packets < 10)
             || (all_flows[i].flow->dst2src_packets < 10)
             /* Ignore flows for which we have not seen the beginning */
             )
          {
            goto print_flow;
          }

          if (all_flows[i].flow->protocol == 6 /* TCP */)
          {
            /* Discard flows with no SYN as we need to check ALPN */
            if ((all_flows[i].flow->src2dst_syn_count == 0) || (all_flows[i].flow->dst2src_syn_count == 0))
            {
              goto print_flow;
            }

            if (all_flows[i].flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_TLS)
            {
              if ((all_flows[i].flow->src2dst_packets+all_flows[i].flow->dst2src_packets) < 40)
              {
                goto print_flow; /* Too few packets for TLS negotiation etc */
              }
            }
          }
        }

        if (bins && cluster_ids)
        {
          u_int j;
          u_int8_t not_empty;

          if (enable_doh_dot_detection)
          {
            not_empty = 0;

            /* Check if bins are empty (and in this case discard it) */
            for (j=0; j<all_flows[i].flow->payload_len_bin.num_bins; j++)
            {
              if (all_flows[i].flow->payload_len_bin.u.bins8[j] != 0)
              {
                not_empty = 1;
                break;
              }
            }
          }
          else
          {
            not_empty = 1;
          }

          if (not_empty)
          {
            memcpy(&bins[num_flow_bins], &all_flows[i].flow->payload_len_bin, sizeof(struct ndpi_bin));
            ndpi_normalize_bin(&bins[num_flow_bins]);
            num_flow_bins++;
          }
        }
#endif

      print_flow:
        print_flow(i+1, all_flows[i].flow, all_flows[i].thread_id);
      }

#ifndef DIRECTION_BINS
      if (bins && cluster_ids && (num_bin_clusters > 0) && (num_flow_bins > 0))
      {
        char buf[64];
        u_int j;
        struct ndpi_bin *centroids;

        if ((centroids = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_bin_clusters)) != NULL)
        {
          for (i=0; i<num_bin_clusters; i++)
          {
            ndpi_init_bin(
              &centroids[i],
              ndpi_bin_family32, //< Use 32 bit to avoid overlaps
              bins[0].num_bins);
          }

          ndpi_cluster_bins(bins, num_flow_bins, num_bin_clusters, cluster_ids, centroids);

          fprintf(out, "\n"
		  "\tBin clusters\n"
		  "\t------------\n");

          for (j = 0; j < num_bin_clusters; j++)
          {
            u_int16_t num_printed = 0;
            float max_similarity = 0;

            for (i = 0; i < num_flow_bins; i++)
            {
              float similarity, s;

              if (cluster_ids[i] != j)
              {
                continue;
              }

              if (num_printed == 0)
              {
                fprintf(out, "\tCluster %u [", j);
                print_bin(out, NULL, &centroids[j]);
                fprintf(out, "]\n");
              }

              fprintf(out, "\t%u\t%-10s\t%s:%u <-> %s:%u\t[",
                i,
                ndpi_protocol2name(dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct,
                                   all_flows[i].flow->detected_protocol, buf, sizeof(buf)),
                all_flows[i].flow->src_name,
                ntohs(all_flows[i].flow->src_port),
                all_flows[i].flow->dst_name,
                ntohs(all_flows[i].flow->dst_port));

              print_bin(out, NULL, &bins[i]);
              fprintf(out, "][similarity: %f]",
                (similarity = ndpi_bin_similarity(&centroids[j], &bins[i], 0, 0)));

              if (all_flows[i].flow->host_server_name[0] != '\0')
              {
                fprintf(out, "[%s]", all_flows[i].flow->host_server_name);
              }

              if (enable_doh_dot_detection)
              {
                if (((all_flows[i].flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_TLS)
                    || (all_flows[i].flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_TLS)
                    || (all_flows[i].flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_DOH_DOT)
                    )
                   && all_flows[i].flow->ssh_tls.advertised_alpns /* ALPN */
                   )
                {
                  if (check_bin_doh_similarity(&bins[i], &s))
                  {
                    fprintf(out, "[DoH (%f distance)]", s);
                  }
                  else
                  {
                    fprintf(out, "[NO DoH (%f distance)]", s);
                  }
                }
                else
                {
                  if (all_flows[i].flow->ssh_tls.advertised_alpns == NULL)
                  {
                    fprintf(out, "[NO DoH check: missing ALPN]");
                  }
                }
              }

              fprintf(out, "\n");
              num_printed++;
              if (similarity > max_similarity) max_similarity = similarity;
            }

            if (num_printed)
            {
              fprintf(out, "\tMax similarity: %f\n", max_similarity);
              fprintf(out, "\n");
            }
          }

          for (i=0; i<num_bin_clusters; i++)
            ndpi_free_bin(&centroids[i]);

          ndpi_free(centroids);
        }
      }

      if (bins)
      {
        ndpi_free(bins);
      }

      if (cluster_ids)
      {
        ndpi_free(cluster_ids);
      }
#endif
    }

    num_flows = 0;
    for (int thread_id = 0; thread_id < num_threads; thread_id++)
    {
      if (dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0] > 0 ||
        (dump_fpc_stats &&
          dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter[0] > 0))
      {
        for (i = 0; i < NUM_ROOTS; i++)
        {
          ndpi_twalk(
            dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
            node_print_unknown_proto_walker,
            &thread_id);
        }
      }
    }

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmp_flows);

    for (i=0; i<num_flows; i++)
    {
      print_flow(i+1, all_flows[i].flow, all_flows[i].thread_id);
    }
  }
  else if (csv_fp != NULL)
  {
    unsigned int i;

    num_flows = 0;
    for (thread_id = 0; thread_id < num_threads; thread_id++)
    {
      for (int i=0; i < NUM_ROOTS; i++)
      {
        ndpi_twalk(
          dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
          node_print_known_proto_walker,
          &thread_id);
      }
    }

    for (i = 0; i < num_flows; i++)
    {
      print_flow(i+1, all_flows[i].flow, all_flows[i].thread_id);
    }
  }

  /*
  if (serialization_fp != NULL &&
      serialization_format != ndpi_serialization_format_unknown)
  {
    unsigned int i;

    num_flows = 0;
    for (int thread_id = 0; thread_id < num_threads; thread_id++)
    {
      for (i = 0; i < NUM_ROOTS; i++)
      {
        ndpi_twalk(
          dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
          node_print_known_proto_walker,
          &thread_id);
        ndpi_twalk(
          dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
          node_print_unknown_proto_walker,
          &thread_id);
      }
    }

    for (i = 0; i < num_flows; i++)
    {
      print_flowSerialized(all_flows[i].flow);
    }
  }
  */

  ndpi_free(all_flows);
}

void deleteScanners(struct single_flow_info *scanners)
{
  struct single_flow_info *s, *tmp;
  struct port_flow_info *p, *tmp2;

  HASH_ITER(hh, scanners, s, tmp)
  {
    HASH_ITER(hh, s->ports, p, tmp2)
    {
      if (s->ports) HASH_DEL(s->ports, p);
      ndpi_free(p);
    }
    HASH_DEL(scanners, s);
    ndpi_free(s);
  }
}

int info_pair_cmp(const void *_a, const void *_b)
{
  struct info_pair *a = (struct info_pair *)_a;
  struct info_pair *b = (struct info_pair *)_b;

  return b->count - a->count;
}

void print_port_stats(struct port_stats *stats)
{
  struct port_stats *s, *tmp;
  char addr_name[48];
  int i = 0;

  HASH_ITER(hh, stats, s, tmp)
  {
    i++;
    printf("\t%2d\tPort %5u\t[%u IP address(es)/%u flows/%u pkts/%u bytes]\n\t\tTop IP Stats:\n",
      i, s->port, s->num_addr, s->num_flows, s->num_pkts, s->num_bytes);

    qsort(&s->top_ip_addrs[0], MAX_NUM_IP_ADDRESS, sizeof(struct info_pair), info_pair_cmp);

    for (int j = 0; j < MAX_NUM_IP_ADDRESS; j++)
    {
      if (s->top_ip_addrs[j].count != 0)
      {
        if (s->top_ip_addrs[j].version == IPVERSION)
	{
          inet_ntop(AF_INET, &(s->top_ip_addrs[j].addr), addr_name, sizeof(addr_name));
        }
	else
	{
          inet_ntop(AF_INET6, &(s->top_ip_addrs[j].addr),  addr_name, sizeof(addr_name));
        }

        printf("\t\t%-36s ~ %.2f%%\n", addr_name,
          ((s->top_ip_addrs[j].count) * 100.0) / s->cumulative_addr);
      }
    }

    printf("\n");
    if (i >= 10)
    {
      break;
    }
  }
}

int port_stats_sort(void *_a, void *_b)
{
  struct port_stats *a = (struct port_stats*)_a;
  struct port_stats *b = (struct port_stats*)_b;

  if (b->num_pkts == 0 && a->num_pkts == 0)
    return(b->num_flows - a->num_flows);

  return(b->num_pkts - a->num_pkts);
}

char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len)
{
  char unit = 'B';

  if (howMuch < 1024)
  {
    ndpi_snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
  }
  else if (howMuch < (1024*1024))
  {
    ndpi_snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch) / 1024, unit);
  }
  else
  {
    float tmpGB = ((float)howMuch) / (1024*1024);

    if (tmpGB < 1024)
    {
      ndpi_snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
    }
    else
    {
      tmpGB /= 1024;

      ndpi_snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
    }
  }

  return buf;
}

void print_results(u_int64_t processing_time_usec, u_int64_t setup_time_usec)
{
  u_int32_t avg_pkt_size = 0;
  char buf[32];
  long long unsigned int breed_stats_pkts[NUM_BREEDS] = { 0 };
  long long unsigned int breed_stats_bytes[NUM_BREEDS] = { 0 };
  long long unsigned int breed_stats_flows[NUM_BREEDS] = { 0 };

  ::memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for (int thread_id = 0; thread_id < num_threads; thread_id++)
  {
    if (dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0 &&
      dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0)
    {
      continue;
    }

    for (int i = 0; i < NUM_ROOTS; i++)
    {
      ndpi_twalk(
        dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
        node_proto_guess_walker,
        &thread_id);
    }

    // Stats aggregation
    cumulative_stats.guessed_flow_protocols += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols;
    cumulative_stats.raw_packet_count += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.raw_packet_count;
    cumulative_stats.ip_packet_count += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.ip_packet_count;
    cumulative_stats.total_wire_bytes += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes;
    cumulative_stats.total_ip_bytes += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.total_ip_bytes;
    cumulative_stats.total_discarded_bytes += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.total_discarded_bytes;

    for (int i = 0; i < ndpi_get_num_supported_protocols(
      dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct); i++)
    {
      cumulative_stats.protocol_counter[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter[i];
      cumulative_stats.protocol_counter_bytes[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[i];
      cumulative_stats.protocol_flows[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_flows[i];

      cumulative_stats.fpc_protocol_counter[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter[i];
      cumulative_stats.fpc_protocol_counter_bytes[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter_bytes[i];
      cumulative_stats.fpc_protocol_flows[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_flows[i];
    }

    cumulative_stats.ndpi_flow_count += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
    cumulative_stats.flow_count[0] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.flow_count[0];
    cumulative_stats.flow_count[1] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.flow_count[1];
    cumulative_stats.flow_count[2] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.flow_count[2];
    cumulative_stats.tcp_count   += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.tcp_count;
    cumulative_stats.udp_count   += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.udp_count;
    cumulative_stats.mpls_count  += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.mpls_count;
    cumulative_stats.pppoe_count += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
    cumulative_stats.vlan_count  += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.vlan_count;
    cumulative_stats.fragmented_count += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
    for (int i = 0; i < sizeof(cumulative_stats.packet_len) /
      sizeof(cumulative_stats.packet_len[0]); i++)
    {
      cumulative_stats.packet_len[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
    }

    cumulative_stats.max_packet_len += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.max_packet_len;

    cumulative_stats.dpi_packet_count[0] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[0];
    cumulative_stats.dpi_packet_count[1] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[1];
    cumulative_stats.dpi_packet_count[2] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[2];

    for (int i = 0; i < sizeof(cumulative_stats.flow_confidence) /
      sizeof(cumulative_stats.flow_confidence[0]); i++)
    {
      cumulative_stats.flow_confidence[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.flow_confidence[i];
    }

    for (int i = 0; i < sizeof(cumulative_stats.fpc_flow_confidence) /
      sizeof(cumulative_stats.fpc_flow_confidence[0]); i++)
    {
      cumulative_stats.fpc_flow_confidence[i] += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_flow_confidence[i];
    }

    cumulative_stats.num_dissector_calls += dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls;

    // LRU caches
    for (int i = 0; i < NDPI_LRUCACHE_MAX; i++)
    {
      struct ndpi_lru_cache_stats s;
      int scope;
      char param[64];

      snprintf(param, sizeof(param), "lru.%s.scope", ndpi_lru_cache_idx_to_name((lru_cache_type)i));

      if (ndpi_get_config(
        dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
        NULL,
        param,
        buf,
        sizeof(buf)) != NULL)
      {
        scope = atoi(buf);
	if (scope == NDPI_LRUCACHE_SCOPE_LOCAL ||
          (scope == NDPI_LRUCACHE_SCOPE_GLOBAL && thread_id == 0))
        {
          ndpi_get_lru_cache_stats(
            dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->g_ctx,
            dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
            (lru_cache_type)i,
            &s);
          cumulative_stats.lru_stats[i].n_insert += s.n_insert;
          cumulative_stats.lru_stats[i].n_search += s.n_search;
          cumulative_stats.lru_stats[i].n_found += s.n_found;
	}
      }
    }

    // Automas
    for (int i = 0; i < NDPI_AUTOMA_MAX; i++)
    {
      struct ndpi_automa_stats s;
      ndpi_get_automa_stats(
        dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
        (automa_type)i,
        &s);
      cumulative_stats.automa_stats[i].n_search += s.n_search;
      cumulative_stats.automa_stats[i].n_found += s.n_found;
    }

    // Patricia trees
    for (int i = 0; i < NDPI_PTREE_MAX; i++)
    {
      struct ndpi_patricia_tree_stats s;
      ndpi_get_patricia_stats(
        dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
        (ptree_type)i,
        &s);
      cumulative_stats.patricia_stats[i].n_search += s.n_search;
      cumulative_stats.patricia_stats[i].n_found += s.n_found;
    }
  }

  if (cumulative_stats.total_wire_bytes == 0)
    goto free_stats;

  if (!quiet_mode)
  {
    printf("\nnDPI Memory statistics:\n");
    printf("\tnDPI Memory (once):      %-13s\n",
      formatBytes(ndpi_get_ndpi_detection_module_size(), buf, sizeof(buf)));
    printf("\tFlow Memory (per flow):  %-13s\n",
      formatBytes(ndpi_detection_get_sizeof_ndpi_flow_struct(), buf, sizeof(buf)));
    //printf("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
    //printf("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));
    printf("\tSetup Time:              %lu msec\n", (unsigned long)(setup_time_usec/1000));
    printf("\tPacket Processing Time:  %lu msec\n", (unsigned long)(processing_time_usec/1000));

    printf("\nTraffic statistics:\n");
    printf("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
           (long long unsigned int)cumulative_stats.total_wire_bytes);
    printf("\tDiscarded bytes:       %-13llu\n",
           (long long unsigned int)cumulative_stats.total_discarded_bytes);
    printf("\tIP packets:            %-13llu of %llu packets total\n",
           (long long unsigned int)cumulative_stats.ip_packet_count,
           (long long unsigned int)cumulative_stats.raw_packet_count);
    /* In order to prevent Floating point exception in case of no traffic*/
    if (cumulative_stats.total_ip_bytes && cumulative_stats.raw_packet_count)
    {
      avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count);
    }
    printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
           (long long unsigned int)cumulative_stats.total_ip_bytes,avg_pkt_size);
    printf("\tUnique flows:          %-13u\n", cumulative_stats.ndpi_flow_count);
    printf("\tTCP Packets:           %-13lu\n", (unsigned long)cumulative_stats.tcp_count);
    printf("\tUDP Packets:           %-13lu\n", (unsigned long)cumulative_stats.udp_count);
    printf("\tVLAN Packets:          %-13lu\n", (unsigned long)cumulative_stats.vlan_count);
    printf("\tMPLS Packets:          %-13lu\n", (unsigned long)cumulative_stats.mpls_count);
    printf("\tPPPoE Packets:         %-13lu\n", (unsigned long)cumulative_stats.pppoe_count);
    printf("\tFragmented Packets:    %-13lu\n", (unsigned long)cumulative_stats.fragmented_count);
    printf("\tMax Packet size:       %-13u\n",   cumulative_stats.max_packet_len);
    printf("\tPacket Len < 64:       %-13lu\n", (unsigned long)cumulative_stats.packet_len[0]);
    printf("\tPacket Len 64-128:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[1]);
    printf("\tPacket Len 128-256:    %-13lu\n", (unsigned long)cumulative_stats.packet_len[2]);
    printf("\tPacket Len 256-1024:   %-13lu\n", (unsigned long)cumulative_stats.packet_len[3]);
    printf("\tPacket Len 1024-1500:  %-13lu\n", (unsigned long)cumulative_stats.packet_len[4]);
    printf("\tPacket Len > 1500:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[5]);

    if (processing_time_usec > 0)
    {
      char buf[32], buf1[32], when[64];
      float t = (float)(cumulative_stats.ip_packet_count*1000000) / (float)processing_time_usec;
      float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000) / (float)processing_time_usec;
      float traffic_duration;
      struct tm result;

      if (live_capture)
      {
        traffic_duration = processing_time_usec;
      }
      else
      {
        traffic_duration = ((u_int64_t)pcap_end.tv_sec*1000000 + pcap_end.tv_usec) -
          ((u_int64_t)pcap_start.tv_sec*1000000 + pcap_start.tv_usec);
      }

      printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), format_traffic(b, 1, buf1));

      if (traffic_duration != 0)
      {
	t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
	b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;
      }
      else
      {
	t = 0;
	b = 0;
      }

      localtime_r(&pcap_start.tv_sec, &result);
      strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
      printf("\tAnalysis begin:        %s\n", when);
      localtime_r(&pcap_end.tv_sec, &result);
      strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
      printf("\tAnalysis end:          %s\n", when);
      printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), format_traffic(b, 1, buf1));
      printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
    }

    if (cumulative_stats.guessed_flow_protocols)
    {
      printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);
    }
    
    if (cumulative_stats.flow_count[0])
    {
      printf("\tDPI Packets (TCP):     %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[0],
	     cumulative_stats.dpi_packet_count[0] / (float)cumulative_stats.flow_count[0]);
    }

    if (cumulative_stats.flow_count[1])
    {
      printf("\tDPI Packets (UDP):     %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[1],
	     cumulative_stats.dpi_packet_count[1] / (float)cumulative_stats.flow_count[1]);
    }

    if (cumulative_stats.flow_count[2])
    {
      printf("\tDPI Packets (other):   %-13llu (%.2f pkts/flow)\n",
	(long long unsigned int)cumulative_stats.dpi_packet_count[2],
	cumulative_stats.dpi_packet_count[2] / (float)cumulative_stats.flow_count[2]);
    }

    for (int i = 0; i < sizeof(cumulative_stats.flow_confidence)/sizeof(cumulative_stats.flow_confidence[0]); i++)
    {
      if (cumulative_stats.flow_confidence[i] != 0)
      {
	printf("\tConfidence: %-10s %-13llu (flows)\n", ndpi_confidence_get_name((ndpi_confidence_t)i),
	  (long long unsigned int)cumulative_stats.flow_confidence[i]);
      }
    }

    if (dump_fpc_stats)
    {
      for (int i = 0; i < sizeof(cumulative_stats.fpc_flow_confidence) /
        sizeof(cumulative_stats.fpc_flow_confidence[0]); i++)
      {
        if (cumulative_stats.fpc_flow_confidence[i] != 0)
        {
          printf(
            "\tFPC Confidence: %-10s %-13llu (flows)\n",
            ndpi_fpc_confidence_get_name((ndpi_fpc_confidence_t)i),
            (long long unsigned int)cumulative_stats.fpc_flow_confidence[i]);
        }
      }
    }

    if (dump_internal_stats)
    {
      char buf[1024];

      if (cumulative_stats.ndpi_flow_count)
      {
	printf("\tNum dissector calls:   %-13llu (%.2f diss/flow)\n",
	       (long long unsigned int)cumulative_stats.num_dissector_calls,
	       cumulative_stats.num_dissector_calls / (float)cumulative_stats.ndpi_flow_count);
      }

      printf("\tLRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
      printf("\tLRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
      printf("\tLRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_found);
      printf("\tLRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
      printf("\tLRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_found);
      printf("\tLRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
      printf("\tLRU cache fpc_dns:    %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_found);

      printf("\tAutoma host:          %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_found);
      printf("\tAutoma domain:        %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
      printf("\tAutoma tls cert:      %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
      printf("\tAutoma risk mask:     %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
      printf("\tAutoma common alpns:  %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

      printf("\tPatricia risk mask:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
      printf("\tPatricia risk mask IPv6: %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
      printf("\tPatricia risk:        %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_found);
      printf("\tPatricia risk IPv6:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_found);
      printf("\tPatricia protocols:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
      printf("\tPatricia protocols IPv6: %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

      /*
      if (enable_malloc_bins)
      {
	printf("\tData-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
      }
      */
    }
  }

  if (!quiet_mode)
  {
    printf("\n\nDetected protocols:\n");
  }

  for (int i = 0; i <= ndpi_get_num_supported_protocols(
    dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct); i++)
  {
    ndpi_protocol_breed_t breed = ndpi_get_proto_breed(
      dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct,
      ndpi_map_ndpi_id_to_user_proto_id(
        dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct, i));

    if (cumulative_stats.protocol_counter[i] > 0 ||
       (dump_fpc_stats && cumulative_stats.fpc_protocol_counter[i] > 0))
    {
      breed_stats_bytes[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];
      breed_stats_pkts[breed] += (long long unsigned int)cumulative_stats.protocol_counter[i];
      breed_stats_flows[breed] += (long long unsigned int)cumulative_stats.protocol_flows[i];

      if (!quiet_mode)
      {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
          "flows: %-13u",
          ndpi_get_proto_name(
            dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct,
            ndpi_map_ndpi_id_to_user_proto_id(
              dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct, i)),
          (long long unsigned int)cumulative_stats.protocol_counter[i],
          (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
          cumulative_stats.protocol_flows[i]);

	if (dump_fpc_stats)
        {
	  printf(" FPC packets: %-13llu FPC bytes: %-13llu "
            "FPC flows: %-13u",
            (long long unsigned int)cumulative_stats.fpc_protocol_counter[i],
            (long long unsigned int)cumulative_stats.fpc_protocol_counter_bytes[i],
            cumulative_stats.fpc_protocol_flows[i]);

	  if (cumulative_stats.protocol_counter[i] != cumulative_stats.fpc_protocol_counter[i] ||
	    cumulative_stats.protocol_counter_bytes[i] != cumulative_stats.fpc_protocol_counter_bytes[i] ||
	    cumulative_stats.protocol_flows[i] != cumulative_stats.fpc_protocol_flows[i])
          {
	    printf("(*)");
          }
	}

	printf("\n");
      }
    }
  }

  if (!quiet_mode && dump_fpc_stats)
  {
    printf("\n\tNOTE: protocols with different standard and FPC statistics are marked\n");
  }

  if (!quiet_mode)
  {
    printf("\n\nProtocol statistics:\n");

    for (int i = 0; i < NUM_BREEDS; i++)
    {
      if (breed_stats_pkts[i] > 0)
      {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13llu\n",
	       ndpi_get_proto_breed_name((ndpi_protocol_breed_t)i),
	       breed_stats_pkts[i], breed_stats_bytes[i], breed_stats_flows[i]);
      }
    }
  }

  print_risk_stats();
  print_flows_stats();

  if (stats_flag || verbose == 3)
  {
    HASH_SORT(srcStats, port_stats_sort);
    HASH_SORT(dstStats, port_stats_sort);
  }

  if (verbose == 3)
  {
    printf("\n\nSource Ports Stats:\n");
    print_port_stats(srcStats);

    printf("\nDestination Ports Stats:\n");
    print_port_stats(dstStats);
  }

 free_stats:
  if (scannerHosts)
  {
    deleteScanners(scannerHosts);
    scannerHosts = NULL;
  }

  if (receivers)
  {
    deleteReceivers(receivers);
    receivers = NULL;
  }

  if (topReceivers)
  {
    deleteReceivers(topReceivers);
    topReceivers = NULL;
  }

  if (srcStats)
  {
    deletePortsStats(srcStats);
    srcStats = NULL;
  }

  if (dstStats)
  {
    deletePortsStats(dstStats);
    dstStats = NULL;
  }
}
