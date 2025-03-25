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
