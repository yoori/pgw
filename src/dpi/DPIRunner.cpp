#include <ndpi/ndpi_config.h>

#include <sched.h>

#include "ndpi_api.h"
#include <uthash.h>
#include <ahocorasick.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <float.h> /* FLT_EPSILON */
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>
#include <list>

#include "ReaderUtil.hpp"
#include "PacketProcessor.hpp"
#include "Config.hpp"
#include "DPIRunner.hpp"

dpi::PacketProcessorPtr packet_processor;

#define ntohl64(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl( ((uint32_t)(x >> 32)) ) )
#define htonl64(x) ntohl64(x)


#define HEURISTICS_CODE 1

/** Client parameters **/

std::shared_ptr<dpi::Config> config;
std::list<std::string> str_holders;
const char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */

#ifndef USE_DPDK
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
#endif
static FILE *results_file           = NULL;
static char *results_path           = NULL;
static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path */
static char *_customCategoryFilePath= NULL; /**< Custom categories file path  */
static char *_maliciousJA4Path      = NULL; /**< Malicious JA4 signatures */
static char *_maliciousSHA1Path     = NULL; /**< Malicious SSL certificate SHA1 fingerprints */
static char *_riskyDomainFilePath   = NULL; /**< Risky domain files */
static char *_domain_suffixes       = NULL; /**< Domain suffixes file */
static char *_categoriesDirPath     = NULL; /**< Directory containing domain files */
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
static FILE *csv_fp                 = NULL; /**< for CSV export */
static FILE *serialization_fp       = NULL; /**< for TLV,CSV,JSON export */
static ndpi_serialization_format serialization_format = ndpi_serialization_format_unknown;
static char* domain_to_check = NULL;
static char* ip_port_to_check = NULL;
static u_int8_t ignore_vlanid = 0;
FILE *fingerprint_fp         = NULL; /**< for flow fingerprint export */
#ifdef __linux__
static char *bind_mask = NULL;
#endif
#define MAX_FARGS 64
static char* fargv[MAX_FARGS];
static int fargc = 0;
static int dump_fpc_stats = 0;

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../nDPI-custom/ndpiReader_defs.c"
#endif

/** User preferences **/
char *addr_dump_path = NULL;
u_int8_t enable_realtime_output = 0, enable_payload_analyzer = 0, num_bin_clusters = 0, extcap_exit = 0;
u_int8_t verbose = 0, enable_flow_stats = 0;
bool do_load_lists = false;

struct cfg {
  char *proto;
  char *param;
  char *value;
};
#define MAX_NUM_CFGS 32
static struct cfg cfgs[MAX_NUM_CFGS];
static int num_cfgs = 0;

int reader_log_level = 0;
char *_disabled_protocols = NULL;
static u_int8_t stats_flag = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 24 /* 8 is enough for most protocols, Signal and SnapchatCall require more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int32_t risk_stats[NDPI_MAX_RISK] = { 0 }, risks_found = 0, flows_with_risks = 0;
static struct ndpi_stats cumulative_stats;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static struct timeval startup_time, begin, end;
#ifdef __linux__
static int core_affinity[MAX_NUM_READER_THREADS];
#endif
static struct timeval pcap_start = { 0, 0}, pcap_end = { 0, 0 };
#ifndef USE_DPDK
static struct bpf_program bpf_code;
#endif
static struct bpf_program *bpf_cfilter = NULL;
/** Detection parameters **/
//static time_t capture_for = 0;
//static time_t capture_until = 0;
static u_int32_t num_flows;

extern u_int8_t enable_doh_dot_detection;
extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection, max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;
u_int8_t dump_internal_stats;

static struct ndpi_bin malloc_bins;
static int enable_malloc_bins = 0;
static int max_malloc_bins = 14;
int malloc_size_stats = 0;

int monitoring_enabled;

struct flow_info {
  struct ndpi_flow_info *flow;
  u_int16_t thread_id;
};

static struct flow_info *all_flows;

struct info_pair {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
};

typedef struct node_a {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
  struct node_a *left, *right;
}addr_node;

// struct to add more statitcs in function printFlowStats
typedef struct hash_stats{
  char* domain_name;
  int occurency;       /* how many time domain name occury in the flow */
  UT_hash_handle hh;   /* hashtable to collect the stats */
}hash_stats;


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

struct port_stats *srcStats = NULL, *dstStats = NULL;

// struct to hold count of flows received by destination ports
struct port_flow_info {
  u_int32_t port; /* key */
  u_int32_t num_flows;
  UT_hash_handle hh;
};

// struct to hold single packet tcp flows sent by source ip address
struct single_flow_info {
  u_int32_t saddr; /* key */
  u_int8_t version; /* IP version */
  struct port_flow_info *ports;
  u_int32_t tot_flows;
  UT_hash_handle hh;
};

struct single_flow_info *scannerHosts = NULL;

// struct to hold top receiver hosts
struct receiver {
  u_int32_t addr; /* key */
  u_int8_t version; /* IP version */
  u_int32_t num_pkts;
  UT_hash_handle hh;
};

struct receiver *receivers = NULL, *topReceivers = NULL;

#define WIRESHARK_NTOP_MAGIC 0x19680924
#define WIRESHARK_METADATA_SIZE		192
#define WIRESHARK_FLOW_RISK_INFO_SIZE	128

#define WIRESHARK_METADATA_SERVERNAME	0x01
#define WIRESHARK_METADATA_JA4C		0x02
#define WIRESHARK_METADATA_TLS_HEURISTICS_MATCHING_FINGERPRINT	0x03

struct ndpi_packet_tlv {
  u_int16_t type;
  u_int16_t length;
  unsigned char data[];
};

PACK_ON
struct ndpi_packet_trailer {
  u_int32_t magic; /* WIRESHARK_NTOP_MAGIC */
  ndpi_master_app_protocol proto;
  char name[16];
  u_int8_t flags;
  ndpi_risk flow_risk;
  u_int16_t flow_score;
  u_int16_t flow_risk_info_len;
  char flow_risk_info[WIRESHARK_FLOW_RISK_INFO_SIZE];
  /* TLV of attributes. Having a max and fixed size for all the metadata
     is not efficient but greatly improves detection of the trailer by Wireshark */
  u_int16_t metadata_len;
  unsigned char metadata[WIRESHARK_METADATA_SIZE];
} PACK_OFF;

static pcap_dumper_t *extcap_dumper = NULL;
static pcap_t *extcap_fifo_h = NULL;
static char extcap_buf[65536 + sizeof(struct ndpi_packet_trailer)];
static char *extcap_capture_fifo    = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t)-1;
static int do_extcap_capture = 0;
static int extcap_add_crc = 0;

// struct associated to a workflow for a thread
struct reader_thread {
  struct ndpi_workflow *workflow;
  pthread_t pthread;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};

// array for every thread created for a flow
struct DPIHandleHolder
{
  struct Info
  {
    struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];
  };

  using InfoPtr = std::shared_ptr<Info>;

  std::mutex lock;
  InfoPtr info;
};

DPIHandleHolder dpi_handle_holder;

// ID tracking
typedef struct ndpi_id {
  u_int8_t ip[4];                   // Ip address
  struct ndpi_id_struct *ndpi_id;  // nDpi worker structure
} ndpi_id_t;

// used memory counters
static u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
#ifdef USE_DPDK
static int dpdk_port_id = 0, dpdk_run_capture = 1;
#endif

void test_lib(); /* Forward */

void ndpi_report_payload_stats(FILE *out);
extern int parse_proto_name_list(char *str, NDPI_PROTOCOL_BITMASK *bitmask,
				 int inverted_logic);
extern u_int8_t is_ndpi_proto(struct ndpi_flow_info *flow, u_int16_t id);


u_int32_t reader_slot_malloc_bins(u_int64_t v)
{
  int i;

  /* 0-2,3-4,5-8,9-16,17-32,33-64,65-128,129-256,257-512,513-1024,1025-2048,2049-4096,4097-8192,8193- */
  for (i=0; i < max_malloc_bins - 1; i++)
    if ((1ULL << (i + 1)) >= v)
      return i;
  return i;
}

void* ndpi_malloc_wrapper(size_t size)
{
  current_ndpi_memory += size;

  if (current_ndpi_memory > max_ndpi_memory)
    max_ndpi_memory = current_ndpi_memory;

  if (enable_malloc_bins && malloc_size_stats)
    ndpi_inc_bin(&malloc_bins, reader_slot_malloc_bins(size), 1);

  return malloc(size); // Don't change to ndpi_malloc !!!!!
}

void free_wrapper(void *freeable)
{
  free(freeable); /* Don't change to ndpi_free !!!!! */
}


#define NUM_DOH_BINS 2

static struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];

static u_int8_t doh_centroids[NUM_DOH_BINS][PLEN_NUM_BINS] = {
  { 23,25,3,0,26,0,0,0,0,0,0,0,0,0,2,0,0,15,3,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
  { 35,30,21,0,0,0,2,4,0,0,5,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }
};

static float doh_max_distance = 35.5;

void init_doh_bins()
{
  for (u_int i = 0; i < NUM_DOH_BINS; i++)
  {
    ndpi_init_bin(&doh_ndpi_bins[i], ndpi_bin_family8, PLEN_NUM_BINS);
    ndpi_free_bin(&doh_ndpi_bins[i]);
    //< Hack: we use static bins (see below), so we need to free the dynamic ones just allocated
    doh_ndpi_bins[i].u.bins8 = doh_centroids[i];
  }
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

void ndpi_check_host_string_match(char *testChar)
{
  ndpi_protocol_match_result match = {
    NDPI_PROTOCOL_UNKNOWN,
    NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED
  };
  int  testRes;
  char appBufStr[64];
  ndpi_protocol detected_protocol;
  struct ndpi_detection_module_struct *ndpi_str;
  NDPI_PROTOCOL_BITMASK all;

  if (!testChar)
    return;

  ndpi_str = ndpi_init_detection_module(NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
  ndpi_finalize_initialization(ndpi_str);

  testRes = ndpi_match_string_subprotocol(ndpi_str,
    testChar, strlen(testChar), &match);

  if (testRes)
  {
    ::memset(&detected_protocol, 0, sizeof(ndpi_protocol));

    detected_protocol.proto.app_protocol = match.protocol_id;
    detected_protocol.proto.master_protocol = 0;
    detected_protocol.category = match.protocol_category;

    ndpi_protocol2name(ndpi_str, detected_protocol, appBufStr, sizeof(appBufStr));

    printf("Match Found for string [%s] -> P(%d) B(%d) C(%d) => %s %s %s\n",
      testChar, match.protocol_id, match.protocol_breed,
      match.protocol_category,
      appBufStr,
      ndpi_get_proto_breed_name(match.protocol_breed ),
      ndpi_category_get_name(ndpi_str, match.protocol_category));
  }
  else
  {
    printf("Match NOT Found for string: %s\n\n", testChar );
  }
  
  ndpi_exit_detection_module(ndpi_str);
}

char const *
ndpi_cfg_error2string(ndpi_cfg_error const err)
{
  switch (err)
  {
  case NDPI_CFG_INVALID_CONTEXT:
    return "Invalid context";
  case NDPI_CFG_NOT_FOUND:
    return "Configuration not found";
  case NDPI_CFG_INVALID_PARAM:
    return "Invalid configuration parameter";
  case NDPI_CFG_CONTEXT_ALREADY_INITIALIZED:
    return "Configuration context already initialized";
  case NDPI_CFG_CALLBACK_ERROR:
    return "Configuration callback error";
  case NDPI_CFG_OK:
    return "Success";
  }

  return "Unknown";
}

void ndpi_check_ip_match(char* testChar)
{
  struct ndpi_detection_module_struct *ndpi_str;
  u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;
  u_int16_t port = 0;
  char *saveptr, *ip_str, *port_str;
  struct in_addr addr;
  char appBufStr[64];
  ndpi_protocol detected_protocol;
  int i;
  ndpi_cfg_error rc;
  NDPI_PROTOCOL_BITMASK all;

  if (!testChar)
    return;

  ndpi_str = ndpi_init_detection_module(NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  if (_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_str, _protoFilePath);

  for (i = 0; i < num_cfgs; i++)
  {
    rc = ndpi_set_config(ndpi_str, cfgs[i].proto, cfgs[i].param, cfgs[i].value);

    if (rc != NDPI_CFG_OK)
    {
      fprintf(stderr, "Error setting config [%s][%s][%s]: %s (%d)\n",
	      (cfgs[i].proto != NULL ? cfgs[i].proto : ""),
	      cfgs[i].param, cfgs[i].value, ndpi_cfg_error2string(rc), rc);
      exit(-1);
    }
  }

  ndpi_finalize_initialization(ndpi_str);

  ip_str = strtok_r(testChar, ":", &saveptr);
  if (!ip_str)
  {
    return;
  }

  addr.s_addr = inet_addr(ip_str);
  port_str = strtok_r(NULL, "\n", &saveptr);
  if (port_str)
  {
    port = atoi(port_str);
  }

  ret = ndpi_network_port_ptree_match(ndpi_str, &addr, htons(port));

  if (ret != NDPI_PROTOCOL_UNKNOWN)
  {
    memset(&detected_protocol, 0, sizeof(ndpi_protocol));
    detected_protocol.proto.app_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, ret);

    ndpi_protocol2name(
      ndpi_str, detected_protocol, appBufStr,
      sizeof(appBufStr));

    printf("Match Found for IP %s, port %d -> %s (%d)\n",
      ip_str, port, appBufStr, detected_protocol.proto.app_protocol);
  }
  else
  {
    printf("Match NOT Found for IP: %s\n", testChar);
  }

  ndpi_exit_detection_module(ndpi_str);
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

/**
 * @brief Set main components necessary to the detection
 */
void setup_detection(
  DPIHandleHolder::Info& dpi_handle_info,
  u_int16_t thread_id,
  pcap_t * pcap_handle,
  struct ndpi_global_context *g_ctx);

/**
 * @brief Get flow byte distribution mean and variance
 */
void
flowGetBDMeanandVariance(struct ndpi_flow_info* flow)
{
  FILE *out = results_file ? results_file : stdout;
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

/**
 * @brief Print help instructions
 */
void help(u_int long_help)
{
  printf("dpi_server "
#ifndef USE_DPDK
         "-i <file|device> "
#endif
         "[-f <filter>][-s <duration>][-m <duration>][-b <num bin clusters>]\n"
         "          [-p <protos>][-l <loops> [-q][-d][-h][-H][-D][-e <len>][-E <path>][-t][-v <level>]\n"
         "          [-n <threads>][-N <path>][-w <file>][-c <file>][-C <file>][-j <file>][-x <file>]\n"
         "          [-r <file>][-R][-j <file>][-S <file>][-T <num>][-U <num>] [-x <domain>]\n"
         "          [-a <mode>][-B proto_list][-L <domain suffixes>]\n\n"
         "Usage:\n"
         "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
         "                            | device for live capture (comma-separated list)\n"
         "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
         "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
         "  -m <duration>             | Split analysis duration in <duration> max seconds\n"
         "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
         "  -l <num loops>            | Number of detection loops (test only)\n"
	 "  -L <domain suffixes>      | Domain suffixes (e.g. ../lists/public_suffix_list.dat)\n"
         "  -n <num threads>          | Number of threads. Default: number of interfaces in -i.\n"
         "                            | Ignored with pcap files.\n"
	 "  -N <path>                 | Address cache dump/restore pathxo.\n"
         "  -b <num bin clusters>     | Number of bin clusters\n"
         "  -k <file>                 | Specify a file to write serialized detection results\n"
         "  -K <format>               | Specify the serialization format for `-k'\n"
         "                            | Valid formats are tlv, csv or json (default)\n"
#ifdef __linux__
         "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
         "  -a <mode>                 | Generates option values for GUIs\n"
         "                            | 0 - List known protocols\n"
         "                            | 1 - List known categories\n"
         "                            | 2 - List known risks\n"
         "  -d                        | Disable protocol guess (by ip and by port) and use only DPI.\n"
	 "                            | It is a shortcut to --cfg=dpi.guess_on_giveup,0\n"
         "  -e <len>                  | Min human readeable string match len. Default %u\n"
         "  -q                        | Quiet mode\n"
         "  -F                        | Enable flow stats\n"
         "  -t                        | Dissect GTP/TZSP tunnels\n"
         "  -P <a>:<b>:<c>:<d>:<e>    | Enable payload analysis:\n"
         "                            | <a> = min pattern len to search\n"
         "                            | <b> = max pattern len to search\n"
         "                            | <c> = max num packets per flow\n"
         "                            | <d> = max packet payload dissection\n"
         "                            | <d> = max num reported payloads\n"
         "                            | Default: %u:%u:%u:%u:%u\n"
         "  -c <path>                 | Load custom categories from the specified file\n"
         "  -C <path>                 | Write output in CSV format on the specified file\n"
	 "  -E <path>                 | Write flow fingerprints on the specified file\n"
         "  -r <path>                 | Load risky domain file\n"
         "  -R                        | Print detected realtime protocols\n"
         "  -j <path>                 | Load malicious JA4 fingeprints\n"
         "  -S <path>                 | Load malicious SSL certificate SHA1 fingerprints\n"
	 "  -G <dir>                  | Bind domain names to categories loading files from <dir>\n"
         "  -w <path>                 | Write test output on the specified file. This is useful for\n"
         "                            | testing purposes in order to compare results across runs\n"
         "  -h                        | This help\n"
         "  -H                        | This help plus some information about supported protocols/risks\n"
         "  -v <1|2|3|4>              | Verbose 'unknown protocol' packet print.\n"
         "                            | 1 = verbose\n"
         "                            | 2 = very verbose\n"
         "                            | 3 = port stats\n"
         "                            | 4 = hash stats\n"
         "  -V <0-4>                  | nDPI logging level\n"
         "                            | 0 - error, 1 - trace, 2 - debug, 3 - extra debug\n"
         "                            | >3 - extra debug + log enabled for all protocols (i.e. '-u all')\n"
         "  -u all|proto|num[,...]    | Enable logging only for such protocol(s)\n"
         "                            | If this flag is present multiple times (directly, or via '-V'),\n"
         "                            | only the last instance will be considered\n"
         "  -B all|proto|num[,...]    | Disable such protocol(s). By defaul all protocols are enabled\n"
         "  -T <num>                  | Max number of TCP processed packets before giving up [default: %u]\n"
         "  -U <num>                  | Max number of UDP processed packets before giving up [default: %u]\n"
         "  -D                        | Enable DoH traffic analysis based on content (no DPI)\n"
         "  -x <domain>               | Check domain name [Test only]\n"
         "  -I                        | Ignore VLAN id for flow hash calculation\n"
         "  -A                        | Dump internal statistics (LRU caches / Patricia trees / Ahocarasick automas / ...\n"
         "  -M                        | Memory allocation stats on data-path (only by the library).\n"
	 "                            | It works only on single-thread configuration\n"
         "  --openvp_heuristics       | Enable OpenVPN heuristics.\n"
         "                            | It is a shortcut to --cfg=openvpn,dpi.heuristics,0x01\n"
         "  --tls_heuristics          | Enable TLS heuristics.\n"
         "                            | It is a shortcut to --cfg=tls,dpi.heuristics,0x07\n"
         "  --cfg=proto,param,value   | Configure the specific attribute of this protocol\n"
         "  --dump-fpc-stats          | Print FPC statistics\n"
         ,
         human_readeable_string_len,
         min_pattern_len, max_pattern_len, max_num_packets_per_flow, max_packet_payload_dissection,
         max_num_reported_top_payloads, max_num_tcp_dissected_pkts, max_num_udp_dissected_pkts);

  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  if (_protoFilePath != NULL)
  {
    ndpi_load_protocols_file(ndpi_str, _protoFilePath);
  }
  
  ndpi_finalize_initialization(ndpi_str);

  printf("\nProtocols configuration parameters:\n");
  ndpi_dump_config(ndpi_str, stdout);

#ifndef WIN32
  printf("\nExcap (wireshark) options:\n"
         "  --extcap-interfaces\n"
         "  --extcap-version\n"
         "  --extcap-dlts\n"
         "  --extcap-interface <name>\n"
         "  --extcap-config\n"
         "  --capture\n"
         "  --extcap-capture-filter <filter>\n"
         "  --fifo <path to file or pipe>\n"
         "  --ndpi-proto-filter <protocol>\n"
	 );
#endif

  if (long_help)
  {
    printf("\n\n"
	   "Size of nDPI Flow structure:      %u\n"
           "Size of nDPI Flow protocol union: %zu\n",
           ndpi_detection_get_sizeof_ndpi_flow_struct(),
           sizeof(((struct ndpi_flow_struct *)0)->protos));

    printf("\n\nnDPI supported protocols:\n");
    printf("%3s %8s %-22s %-10s %-8s %-12s %-18s %-31s %-31s \n",
	   "Id", "Userd-id", "Protocol", "Layer_4", "Nw_Proto", "Breed", "Category","Def UDP Port/s","Def TCP Port/s");
    num_threads = 1;

    ndpi_dump_protocols(ndpi_str, stdout);

    printf("\n\nnDPI supported risks:\n");
    ndpi_dump_risks_score(stdout);
  }

  ndpi_exit_detection_module(ndpi_str);

  exit(!long_help);
}


#define OPTLONG_VALUE_CFG		3000
#define OPTLONG_VALUE_OPENVPN_HEURISTICS	3001
#define OPTLONG_VALUE_TLS_HEURISTICS		3002
#define OPTLONG_VALUE_CONF                      3003
#define OPTLONG_VALUE_FPC_STATS                 3004

static struct option longopts[] = {
  /* mandatory extcap options */
  { "extcap-interfaces", no_argument, NULL, '0'},
  { "extcap-version", optional_argument, NULL, '1'},
  { "extcap-dlts", no_argument, NULL, '2'},
  { "extcap-interface", required_argument, NULL, '3'},
  { "extcap-config", no_argument, NULL, '4'},
  { "capture", no_argument, NULL, '5'},
  { "extcap-capture-filter", required_argument, NULL, '6'},
  { "fifo", required_argument, NULL, '7'},
  { "ndpi-proto-filter", required_argument, NULL, '9'},

  /* ndpiReader options */
  { "enable-protocol-guess", no_argument, NULL, 'd'},
  { "categories", required_argument, NULL, 'c'},
  { "csv-dump", required_argument, NULL, 'C'},
  { "interface", optional_argument, NULL, 'i'},
  { "filter", required_argument, NULL, 'f'},
  { "flow-stats", required_argument, NULL, 'F'},
  { "cpu-bind", required_argument, NULL, 'g'},
  { "load-categories", required_argument, NULL, 'G'},
  { "loops", required_argument, NULL, 'l'},
  { "domain-suffixes", required_argument, NULL, 'L'},
  { "num-threads", required_argument, NULL, 'n'},
  { "address-cache-dump", required_argument, NULL, 'N'},
  { "ignore-vlanid", no_argument, NULL, 'I'},

  { "protos", required_argument, NULL, 'p'},
  { "capture-duration", required_argument, NULL, 's'},
  { "decode-tunnels", no_argument, NULL, 't'},
  { "revision", no_argument, NULL, 'r'},
  { "verbose", required_argument, NULL, 'v'},
  { "version", no_argument, NULL, 'r'},
  { "ndpi-log-level", required_argument, NULL, 'V'},
  { "dbg-proto", required_argument, NULL, 'u'},
  { "help", no_argument, NULL, 'h'},
  { "long-help", no_argument, NULL, 'H'},
  { "serialization-outfile", required_argument, NULL, 'k'},
  { "serialization-format", required_argument, NULL, 'K'},
  { "payload-analysis", required_argument, NULL, 'P'},
  { "result-path", required_argument, NULL, 'w'},
  { "quiet", no_argument, NULL, 'q'},

  { "cfg", required_argument, NULL, OPTLONG_VALUE_CFG},
  { "openvpn_heuristics", no_argument, NULL, OPTLONG_VALUE_OPENVPN_HEURISTICS},
  { "tls_heuristics", no_argument, NULL, OPTLONG_VALUE_TLS_HEURISTICS},
  { "conf", required_argument, NULL, OPTLONG_VALUE_CONF},
  { "dump-fpc-stats", no_argument, NULL, OPTLONG_VALUE_FPC_STATS},

  { "config", optional_argument, NULL, 'y'},

  {0, 0, 0, 0}
};

static const char* longopts_short = "a:Ab:B:e:E:c:C:dDFf:g:G:i:Ij:k:K:S:hHp:pP:l:L:r:Rs:tu:v:V:n:rp:x:X:w:q0123:456:7:89:m:MN:T:U:y:";

void extcap_interfaces()
{
  printf("extcap {version=%s}{help=https://github.com/ntop/nDPI/tree/dev/wireshark}\n", ndpi_revision());
  printf("interface {value=ndpi}{display=nDPI interface}\n");

  extcap_exit = 1;
}

void extcap_dlts()
{
  u_int dlts_number = DLT_EN10MB;
  printf("dlt {number=%u}{name=%s}{display=%s}\n", dlts_number, "ndpi", "nDPI Interface");
  extcap_exit = 1;
}

struct ndpi_proto_sorter
{
  int id;
  char name[32];
};

int cmp_proto(const void *_a, const void *_b)
{
  struct ndpi_proto_sorter *a = (struct ndpi_proto_sorter*)_a;
  struct ndpi_proto_sorter *b = (struct ndpi_proto_sorter*)_b;

  return(strcmp(a->name, b->name));
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

void extcap_config()
{
  int argidx = 0;

  struct ndpi_proto_sorter *protos;
  u_int ndpi_num_supported_protocols;
  ndpi_proto_defaults_t *proto_defaults;
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);

  if (!ndpi_str)
  {
    exit(0);
  }

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  ndpi_finalize_initialization(ndpi_str);

  ndpi_num_supported_protocols = ndpi_get_ndpi_num_supported_protocols(ndpi_str);
  proto_defaults = ndpi_get_proto_defaults(ndpi_str);

  /* -i <interface> */
  printf("arg {number=%d}{call=-i}{display=Capture Interface}{type=string}{group=Live Capture}"
         "{tooltip=The interface name}\n", argidx++);

  printf("arg {number=%d}{call=-i}{display=Pcap File to Analyze}{type=fileselect}{mustexist=true}{group=Pcap}"
         "{tooltip=The pcap file to analyze (if the interface is unspecified)}\n", argidx++);

  protos = (struct ndpi_proto_sorter*)ndpi_malloc(
    sizeof(struct ndpi_proto_sorter) * ndpi_num_supported_protocols);
  if (!protos)
  {
    exit(0);
  }

  printf("arg {number=%d}{call=--ndpi-proto-filter}{display=nDPI Protocol Filter}{type=selector}{group=Options}"
         "{tooltip=nDPI Protocol to be filtered}\n", argidx);

  printf("value {arg=%d}{value=%d}{display=%s}{default=true}\n", argidx, (u_int32_t)-1, "No nDPI filtering");

  for (int i = 0; i < (int)ndpi_num_supported_protocols; ++i)
  {
    protos[i].id = i;
    ndpi_snprintf(protos[i].name, sizeof(protos[i].name), "%s", proto_defaults[i].protoName);
  }

  qsort(protos, ndpi_num_supported_protocols, sizeof(struct ndpi_proto_sorter), cmp_proto);

  for (int i = 0; i < (int)ndpi_num_supported_protocols; ++i)
  {
    printf("value {arg=%d}{value=%d}{display=%s (%d)}{default=false}{enabled=true}\n", argidx, protos[i].id,
           protos[i].name, protos[i].id);
  }

  ndpi_free(protos);
  argidx++;

  printf("arg {number=%d}{call=--openvpn_heuristics}{display=Enable Obfuscated OpenVPN heuristics}"
	 "{tooltip=Enable Obfuscated OpenVPN heuristics}{type=boolflag}{group=Options}\n", argidx++);
  printf("arg {number=%d}{call=--tls_heuristics}{display=Enable Obfuscated TLS heuristics}"
	 "{tooltip=Enable Obfuscated TLS heuristics}{type=boolflag}{group=Options}\n", argidx++);

  ndpi_exit_detection_module(ndpi_str);

  extcap_exit = 1;
}

void extcap_capture(int datalink_type)
{
  if ((extcap_fifo_h = pcap_open_dead(datalink_type, 16384 /* MTU */)) == NULL)
  {
    fprintf(stderr, "Error pcap_open_dead");
    return;
  }

  if ((extcap_dumper = pcap_dump_open(extcap_fifo_h,
    extcap_capture_fifo)) == NULL)
  {
    fprintf(stderr, "Unable to open the pcap dumper on %s", extcap_capture_fifo);
    return;
  }
}

void printCSVHeader()
{
  if (!csv_fp) return;

  fprintf(csv_fp, "#flow_id|protocol|first_seen|last_seen|duration|src_ip|src_port|dst_ip|dst_port|ndpi_proto_num|ndpi_proto|proto_by_ip|server_name_sni|");
  fprintf(csv_fp, "c_to_s_pkts|c_to_s_bytes|c_to_s_goodput_bytes|s_to_c_pkts|s_to_c_bytes|s_to_c_goodput_bytes|");
  fprintf(csv_fp, "data_ratio|str_data_ratio|c_to_s_goodput_ratio|s_to_c_goodput_ratio|");

  /* IAT (Inter Arrival Time) */
  fprintf(csv_fp, "iat_flow_min|iat_flow_avg|iat_flow_max|iat_flow_stddev|");
  fprintf(csv_fp, "iat_c_to_s_min|iat_c_to_s_avg|iat_c_to_s_max|iat_c_to_s_stddev|");
  fprintf(csv_fp, "iat_s_to_c_min|iat_s_to_c_avg|iat_s_to_c_max|iat_s_to_c_stddev|");

  /* Packet Length */
  fprintf(csv_fp, "pktlen_c_to_s_min|pktlen_c_to_s_avg|pktlen_c_to_s_max|pktlen_c_to_s_stddev|");
  fprintf(csv_fp, "pktlen_s_to_c_min|pktlen_s_to_c_avg|pktlen_s_to_c_max|pktlen_s_to_c_stddev|");

  /* TCP flags */
  fprintf(csv_fp, "cwr|ece|urg|ack|psh|rst|syn|fin|");

  fprintf(csv_fp, "c_to_s_cwr|c_to_s_ece|c_to_s_urg|c_to_s_ack|c_to_s_psh|c_to_s_rst|c_to_s_syn|c_to_s_fin|");

  fprintf(csv_fp, "s_to_c_cwr|s_to_c_ece|s_to_c_urg|s_to_c_ack|s_to_c_psh|s_to_c_rst|s_to_c_syn|s_to_c_fin|");

  /* TCP window */
  fprintf(csv_fp, "c_to_s_init_win|s_to_c_init_win|");

  /* Flow info */
  fprintf(csv_fp, "server_info|");
  fprintf(csv_fp, "tls_version|quic_version|");
  fprintf(csv_fp, "ja3s|");
  fprintf(csv_fp, "advertised_alpns|negotiated_alpn|tls_supported_versions|");
#if 0
  fprintf(csv_fp, "tls_issuerDN|tls_subjectDN|");
#endif
  fprintf(csv_fp, "ssh_client_hassh|ssh_server_hassh|flow_info|plen_bins|http_user_agent");

  if (enable_flow_stats)
  {
    fprintf(csv_fp, "|byte_dist_mean|byte_dist_std|entropy|total_entropy");
  }

  fprintf(csv_fp, "\n");
}

int parse_three_strings(char *param, char **s1, char **s2, char **s3)
{
  char *saveptr, *tmp_str, *s1_str, *s2_str = NULL, *s3_str;
  int num_commas;
  unsigned int i;

  tmp_str = ndpi_strdup(param);
  if (tmp_str)
  {
    // First parameter might be missing
    num_commas = 0;
    for (i = 0; i < strlen(tmp_str); i++)
    {
      if (tmp_str[i] == ',')
        num_commas++;
    }

    if (num_commas == 1)
    {
      s1_str = NULL;
      s2_str = strtok_r(tmp_str, ",", &saveptr);
    }
    else if (num_commas == 2)
    {
      s1_str = strtok_r(tmp_str, ",", &saveptr);
      if (s1_str)
      {
        s2_str = strtok_r(NULL, ",", &saveptr);
      }
    }
    else
    {
      ndpi_free(tmp_str);
      return -1;
    }

    if (s2_str)
    {
      s3_str = strtok_r(NULL, ",", &saveptr);
      if (s3_str)
      {
        *s1 = ndpi_strdup(s1_str);
        *s2 = ndpi_strdup(s2_str);
        *s3 = ndpi_strdup(s3_str);
        ndpi_free(tmp_str);
        if (!s1 || !s2 || !s3)
        {
          ndpi_free(s1);
          ndpi_free(s2);
          ndpi_free(s3);
          return -1;
        }
        return 0;
      }
    }
  }
  ndpi_free(tmp_str);
  return -1;
}

int reader_add_cfg(const char *proto, const char *param, const char *value, int dup)
{
  if (num_cfgs >= MAX_NUM_CFGS)
  {
    printf("Too many parameter! [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
    return -1;
  }
  cfgs[num_cfgs].proto = const_cast<char*>(dup ? ndpi_strdup(proto) : proto);
  cfgs[num_cfgs].param = const_cast<char*>(dup ? ndpi_strdup(param) : param);
  cfgs[num_cfgs].value = const_cast<char*>(dup ? ndpi_strdup(value) : value);
  num_cfgs++;
  return 0;
}

void parse_parameters(int argc, char **argv)
{
  enable_doh_dot_detection = 0;
  dump_internal_stats = 0;
  num_bin_clusters = 32;
  human_readeable_string_len = 5;
  do_load_lists = false;
  ignore_vlanid = 0;
  _maliciousJA4Path = NULL;
  _maliciousSHA1Path = NULL;
  bpfFilter = NULL;
  std::string config_path;

  int option_idx = 0;
  int opt;
  char *s1, *s2, *s3;

  while((opt = getopt_long(argc, argv, longopts_short, longopts, &option_idx)) != EOF)
  {
    switch (opt)
    {
    case 'y':
      config_path = optarg;
      break;

    case 'd':
      if (reader_add_cfg(NULL, "dpi.guess_on_giveup", "0", 1) == 1)
      {
        printf("Invalid parameter [%s] [num:%d/%d]\n", optarg, num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    case 'i':
    case '3':
      _pcap_file[0] = optarg;
      break;

    case 'm':
      pcap_analysis_duration = atol(optarg);
      break;

    case 'g':
      bind_mask = optarg;
      break;

    case 'G':
      _categoriesDirPath = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'L':
      _domain_suffixes = optarg;
      break;

    case 'n':
      num_threads = atoi(optarg);
      break;

    case 'N':
      addr_dump_path = optarg;
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 'c':
      _customCategoryFilePath = optarg;
      break;

    case 'C':
      errno = 0;
      if ((csv_fp = fopen(optarg, "w")) == NULL)
        {
          printf("Unable to write on CSV file %s: %s\n", optarg, strerror(errno));
          exit(1);
        }
      break;

    case 'r':
      _riskyDomainFilePath = optarg;
      break;

    case 'R':
      enable_realtime_output =1;
      break;

    /*
    case 's':
      capture_for = atoi(optarg);
      capture_until = capture_for + time(NULL);
      break;
    */

    case 't':
      decode_tunnels = 1;
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'V':
      {
        char buf[12];
        int log_level;
        const char *errstrp;

        /* (Internals) log levels are 0-3, but ndpiReader allows 0-4, where with 4
           we also enable all protocols */
        log_level = ndpi_strtonum(optarg, NDPI_LOG_ERROR, NDPI_LOG_DEBUG_EXTRA + 1, &errstrp, 10);
        if (errstrp != NULL)
        {
          printf("Invalid log level %s: %s\n", optarg, errstrp);
          exit(1);
        }

        if (log_level > NDPI_LOG_DEBUG_EXTRA)
        {
          log_level = NDPI_LOG_DEBUG_EXTRA;
          if (reader_add_cfg("all", "log", "enable", 1) == 1)
          {
            printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
            exit(1);
          }
        }
        snprintf(buf, sizeof(buf), "%d", log_level);
        if (reader_add_cfg(NULL, "log.level", buf, 1) == 1)
        {
          printf("Invalid log level [%s] [num:%d/%d]\n", buf, num_cfgs, MAX_NUM_CFGS);
          exit(1);
        }
        reader_log_level = log_level;
        break;
      }

    case 'u':
      {
        char *n;
        char *str = ndpi_strdup(optarg);
        int inverted_logic;

        /* Reset any previous call to this knob */
        if (reader_add_cfg("all", "log", "disable", 1) == 1)
        {
          printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
          exit(1);
        }

        for (n = strtok(str, ","); n && *n; n = strtok(NULL, ","))
        {
          inverted_logic = 0;
          if (*n == '-')
          {
            inverted_logic = 1;
            n++;
          }
          if (reader_add_cfg(n, "log", inverted_logic ? "disable" : "enable", 1) == 1)
          {
            printf("Invalid parameter [%s] [num:%d/%d]\n", n, num_cfgs, MAX_NUM_CFGS);
            exit(1);
          }
        }
        ndpi_free(str);
        break;
      }

    case 'B':
      ndpi_free(_disabled_protocols);
      _disabled_protocols = ndpi_strdup(optarg);
      break;

    case 'h':
      help(0);
      break;

    case 'H':
      help(1);
      break;

    case 'F':
      enable_flow_stats = 1;
      break;

    case 'P':
      {
        int _min_pattern_len, _max_pattern_len,
          _max_num_packets_per_flow, _max_packet_payload_dissection,
          _max_num_reported_top_payloads;

        enable_payload_analyzer = 1;
        if (sscanf(optarg, "%d:%d:%d:%d:%d", &_min_pattern_len, &_max_pattern_len,
                  &_max_num_packets_per_flow,
                  &_max_packet_payload_dissection,
                  &_max_num_reported_top_payloads) == 5)
        {
          min_pattern_len = _min_pattern_len, max_pattern_len = _max_pattern_len;
          max_num_packets_per_flow = _max_num_packets_per_flow, max_packet_payload_dissection = _max_packet_payload_dissection;
          max_num_reported_top_payloads = _max_num_reported_top_payloads;
          if (min_pattern_len > max_pattern_len) min_pattern_len = max_pattern_len;
          if (min_pattern_len < 2)               min_pattern_len = 2;
          if (max_pattern_len > 16)              max_pattern_len = 16;
          if (max_num_packets_per_flow == 0)     max_num_packets_per_flow = 1;
          if (max_packet_payload_dissection < 4) max_packet_payload_dissection = 4;
          if (max_num_reported_top_payloads == 0) max_num_reported_top_payloads = 1;
        }
        else
        {
          printf("Invalid -P format. Ignored\n");
          help(0);
        }
      }
      break;

    case 'M':
      enable_malloc_bins = 1;
      ndpi_init_bin(&malloc_bins, ndpi_bin_family64, max_malloc_bins);
      break;

    case 'k':
      errno = 0;
      if ((serialization_fp = fopen(optarg, "w")) == NULL)
      {
        printf("Unable to write on serialization file %s: %s\n", optarg, strerror(errno));
        exit(1);
      }
      break;

    case 'K':
      if (strcasecmp(optarg, "tlv") == 0 && strlen(optarg) == 3)
      {
        serialization_format = ndpi_serialization_format_tlv;
      }
      else if (strcasecmp(optarg, "csv") == 0 && strlen(optarg) == 3)
      {
        serialization_format = ndpi_serialization_format_csv;
      }
      else if (strcasecmp(optarg, "json") == 0 && strlen(optarg) == 4)
      {
        serialization_format = ndpi_serialization_format_json;
      }
      else
      {
        printf("Unknown serialization format. Valid values are: tlv,csv,json\n");
        exit(1);
      }
      break;

    case 'w':
      results_path = ndpi_strdup(optarg);
      if ((results_file = fopen(results_path, "w")) == NULL)
      {
        printf("Unable to write in file %s: quitting\n", results_path);
        exit(1);
      }
      break;

    case 'q':
      quiet_mode = 1;
      if (reader_add_cfg(NULL, "log.level", "0", 1) == 1)
      {
        printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      reader_log_level = 0;
      break;

    case OPTLONG_VALUE_OPENVPN_HEURISTICS:
      if (reader_add_cfg("openvpn", "dpi.heuristics", "0x01", 1) == 1)
      {
        printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    case OPTLONG_VALUE_TLS_HEURISTICS:
      if (reader_add_cfg("tls", "dpi.heuristics", "0x07", 1) == 1)
      {
        printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    case OPTLONG_VALUE_FPC_STATS:
      dump_fpc_stats = 1;
      break;

    case OPTLONG_VALUE_CONF:
      {
        FILE *fd;
        char buffer[512], *line, *saveptr;
        int len, saved_optind, initial_fargc;

        fd = fopen(optarg, "r");
        if (fd == NULL)
        {
          printf("Error opening: %s\n", optarg);
          exit(1);
        }

        if (fargc == 0)
        {
          fargv[0] = ndpi_strdup(argv[0]);
          fargc = 1;
        }
        initial_fargc = fargc;

        while(1)
        {
          line = fgets(buffer, sizeof(buffer), fd);

          if (line == NULL)
            break;

          len = strlen(line);

          if ((len <= 1) || (line[0] == '#'))
            continue;

          line[len - 1] = '\0';

          fargv[fargc] = ndpi_strdup(strtok_r(line, " \t", &saveptr));
          while(fargc < MAX_FARGS && fargv[fargc] != NULL)
          {
            fargc++;
            fargv[fargc] = ndpi_strdup(strtok_r(NULL, " \t", &saveptr));
          }

          if (fargc == MAX_FARGS)
          {
            printf("Too many arguments\n");
            exit(1);
          }
        }

        /* Recursive call to getopt_long() */
        saved_optind = optind;
        optind = initial_fargc;
        parse_parameters(fargc, fargv);
        optind = saved_optind;

        fclose(fd);
      }
      break;

      /* Extcap */
    case '0':
      extcap_interfaces();
      break;

    case '1':
      printf("extcap {version=%s}\n", ndpi_revision());
      break;

    case '2':
      extcap_dlts();
      break;

    case '4':
      extcap_config();
      break;

#ifndef USE_DPDK
    case '5':
      do_extcap_capture = 1;
      break;
#endif

    case '7':
      extcap_capture_fifo = ndpi_strdup(optarg);
      break;

    case '9':
      {
        struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
        NDPI_PROTOCOL_BITMASK all;

        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
        ndpi_finalize_initialization(ndpi_str);

        extcap_packet_filter = ndpi_get_proto_by_name(ndpi_str, optarg);
        if (extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN) extcap_packet_filter = atoi(optarg);

        ndpi_exit_detection_module(ndpi_str);
        break;
      }

    case 'T':
      max_num_tcp_dissected_pkts = atoi(optarg);
      /* If we enable that, allow at least 3WHS + 1 "real" packet */
      if (max_num_tcp_dissected_pkts != 0 && max_num_tcp_dissected_pkts < 4) max_num_tcp_dissected_pkts = 4;
      break;

    case 'x':
      domain_to_check = optarg;
      break;

    case 'X':
      ip_port_to_check = optarg;
      break;

    case 'U':
      max_num_udp_dissected_pkts = atoi(optarg);
      break;

    case OPTLONG_VALUE_CFG:
      if (parse_three_strings(optarg, &s1, &s2, &s3) == -1 ||
         reader_add_cfg(s1, s2, s3, 0) == -1)
      {
        printf("Invalid parameter [%s] [num:%d/%d]\n", optarg, num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    default:

      help(0);
      break;
    }
  }
}

/**
 * @brief Option parser
 */
void parse_options(int argc, char **argv)
{
  char *__pcap_file = NULL;
  int thread_id;
#ifdef __linux__
  u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif

  parse_parameters(argc, argv);

  if (serialization_fp == NULL && serialization_format != ndpi_serialization_format_unknown)
  {
    printf("Serializing detection results to a file requires command line arguments `-k'\n");
    exit(1);
  }

  if (serialization_fp != NULL && serialization_format == ndpi_serialization_format_unknown)
  {
    serialization_format = ndpi_serialization_format_json;
  }

  if (extcap_exit)
  {
    exit(0);
  }

  if (do_extcap_capture)
  {
    quiet_mode = 1;
  }

  if (!domain_to_check && !ip_port_to_check)
  {
    if (_pcap_file[0] == NULL)
      help(0);

    if (strchr(_pcap_file[0], ','))
    {
      num_threads = 0;
      Gears::StringManip::SplitComma splitter{Gears::SubString(_pcap_file[0])};
      Gears::SubString token;
      while (splitter.get_token(token) && num_threads < MAX_NUM_READER_THREADS)
      {
        str_holders.emplace_back(token.str());
        _pcap_file[num_threads++] = str_holders.back().c_str();
      }
    }
    else
    {
      if (num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
      for (thread_id = 1; thread_id < num_threads; thread_id++)
        _pcap_file[thread_id] = _pcap_file[0];
    }

    if (num_threads > 1 && enable_malloc_bins == 1)
    {
      printf("Memory profiling ('-M') is incompatible with multi-thread enviroment");
      exit(1);
    }
  }

  for (thread_id = 0; thread_id < num_threads; thread_id++)
    core_affinity[thread_id] = -1;

  if (num_cores > 1 && bind_mask != NULL)
  {
    char *core_id = strtok(bind_mask, ":");
    thread_id = 0;

    while(core_id != NULL && thread_id < num_threads)
    {
      core_affinity[thread_id++] = atoi(core_id) % num_cores;
      core_id = strtok(NULL, ":");
    }
  }
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

/* ********************************** */

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

/**
 * @brief Print the flow
 */
void print_flow(u_int32_t id, struct ndpi_flow_info *flow, u_int16_t thread_id)
{
  FILE *out = results_file ? results_file : stdout;
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

static void print_flowSerialized(struct ndpi_flow_info *flow)
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

/**
 * @brief Unknown Proto Walker
 */
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

/**
 * @brief Known Proto Walker
 */
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

/**
 * @brief Proto Guess Walker
 */
void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data), proto, fpc_proto;

  (void)depth;

  if (flow == NULL)
  {
    return;
  }
  
  if ((which == ndpi_preorder) || (which == ndpi_leaf))
  {
    // Avoid walking the same node multiple times
    if ((!flow->detection_completed) && flow->ndpi_flow)
    {
      u_int8_t proto_guessed;

      malloc_size_stats = 1;
      flow->detected_protocol = ndpi_detection_giveup(
        dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct,
        flow->ndpi_flow, &proto_guessed);
      malloc_size_stats = 0;

      if (proto_guessed)
      {
        dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols++;
      }
    }

    process_ndpi_collected_info(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow, flow);

    proto = flow->detected_protocol.proto.app_protocol ? flow->detected_protocol.proto.app_protocol :
      flow->detected_protocol.proto.master_protocol;
    proto = ndpi_map_user_proto_id_to_ndpi_id(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct, proto);

    fpc_proto = flow->fpc.proto.app_protocol ? flow->fpc.proto.app_protocol : flow->fpc.proto.master_protocol;
    fpc_proto = ndpi_map_user_proto_id_to_ndpi_id(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct, fpc_proto);

    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto] += flow->src2dst_packets + flow->dst2src_packets;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[proto] += flow->src2dst_bytes + flow->dst2src_bytes;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.flow_confidence[flow->confidence]++;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls += flow->num_dissector_calls;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter[fpc_proto] += flow->src2dst_packets + flow->dst2src_packets;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter_bytes[fpc_proto] += flow->src2dst_bytes + flow->dst2src_bytes;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_flows[fpc_proto]++;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_flow_confidence[flow->fpc.confidence]++;
  }
}

void updateScanners(
  struct single_flow_info **scanners, u_int32_t saddr,
  u_int8_t version, u_int32_t dport)
{
  struct single_flow_info *f;
  struct port_flow_info *p;

  HASH_FIND_INT(*scanners, (int *)&saddr, f);

  if (f == NULL)
  {
    f = (struct single_flow_info*)ndpi_malloc(sizeof(struct single_flow_info));
    if (!f) return;
    f->saddr = saddr;
    f->version = version;
    f->tot_flows = 1;
    f->ports = NULL;

    p = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));

    if (!p)
    {
      ndpi_free(f);
      return;
    }
    else
    {
      p->port = dport, p->num_flows = 1;
    }

    HASH_ADD_INT(f->ports, port, p);
    HASH_ADD_INT(*scanners, saddr, f);
  }
  else
  {
    struct port_flow_info *pp;
    f->tot_flows++;

    HASH_FIND_INT(f->ports, (int *)&dport, pp);

    if (pp == NULL)
    {
      pp = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));
      if (!pp) return;
      pp->port = dport, pp->num_flows = 1;

      HASH_ADD_INT(f->ports, port, pp);
    }
    else
    {
      pp->num_flows++;
    }
  }
}

int updateIpTree(
  u_int32_t key, u_int8_t version,
  addr_node **vrootp, const char *proto)
{
  addr_node *q;
  addr_node **rootp = vrootp;

  if (rootp == (addr_node **)0)
  {
    return 0;
  }

  while(*rootp != (addr_node *)0)
  {
    /* Knuth's T1: */
    if ((version == (*rootp)->version) && (key == (*rootp)->addr))
    {
      /* T2: */
      return ++((*rootp)->count);
    }

    rootp = (key < (*rootp)->addr) ?
      &(*rootp)->left :                /* T3: follow left branch */
      &(*rootp)->right;                /* T4: follow right branch */
  }

  q = (addr_node *) ndpi_malloc(sizeof(addr_node));        /* T5: key not found */
  if (q != (addr_node *)0)
  {
    /* make new node */
    *rootp = q;                                        /* link new node to old */

    q->addr = key;
    q->version = version;
    strncpy(q->proto, proto, sizeof(q->proto) - 1);
    q->proto[sizeof(q->proto) - 1] = '\0';
    q->count = UPDATED_TREE;
    q->left = q->right = (addr_node *)0;

    return q->count;
  }

  return(0);
}

void freeIpTree(addr_node *root)
{
  if (root == NULL)
    return;

  freeIpTree(root->left);
  freeIpTree(root->right);
  ndpi_free(root);
}

void updateTopIpAddress(
  u_int32_t addr, u_int8_t version, const char *proto,
  int count, struct info_pair top[], int size)
{
  struct info_pair pair;
  int min = count;
  int update = 0;
  int min_i = 0;
  int i;

  if (count == 0) return;

  pair.addr = addr;
  pair.version = version;
  pair.count = count;
  strncpy(pair.proto, proto, sizeof(pair.proto) - 1);
  pair.proto[sizeof(pair.proto) - 1] = '\0';

  for (i=0; i<size; i++)
  {
    /* if the same ip with a bigger
       count just update it     */
    if (top[i].addr == addr)
    {
      top[i].count = count;
      return;
    }
    /* if array is not full yet
       add it to the first empty place */
    if (top[i].count == 0)
    {
      top[i] = pair;
      return;
    }
  }

  /* if bigger than the smallest one, replace it */
  for (i=0; i<size; i++)
  {
    if (top[i].count < count && top[i].count < min)
    {
      min = top[i].count;
      min_i = i;
      update = 1;
    }
  }

  if (update)
    top[min_i] = pair;
}

static void updatePortStats(struct port_stats **stats, u_int32_t port,
  u_int32_t addr, u_int8_t version,
  u_int32_t num_pkts, u_int32_t num_bytes,
  const char *proto)
{
  struct port_stats *s = NULL;
  int count = 0;

  HASH_FIND_INT(*stats, &port, s);
  if (s == NULL)
  {
    s = (struct port_stats*)ndpi_calloc(1, sizeof(struct port_stats));
    if (!s) return;

    s->port = port, s->num_pkts = num_pkts, s->num_bytes = num_bytes;
    s->num_addr = 1, s->cumulative_addr = 1; s->num_flows = 1;

    updateTopIpAddress(addr, version, proto, 1, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);

    s->addr_tree = (addr_node *) ndpi_malloc(sizeof(addr_node));
    if (!s->addr_tree)
    {
      ndpi_free(s);
      return;
    }

    s->addr_tree->addr = addr;
    s->addr_tree->version = version;
    strncpy(s->addr_tree->proto, proto, sizeof(s->addr_tree->proto) - 1);
    s->addr_tree->proto[sizeof(s->addr_tree->proto) - 1] = '\0';
    s->addr_tree->count = 1;
    s->addr_tree->left = NULL;
    s->addr_tree->right = NULL;

    HASH_ADD_INT(*stats, port, s);
  }
  else
  {
    count = updateIpTree(addr, version, &(*s).addr_tree, proto);

    if (count == UPDATED_TREE) s->num_addr++;

    if (count)
    {
      s->cumulative_addr++;
      updateTopIpAddress(addr, version, proto, count, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);
    }

    s->num_pkts += num_pkts, s->num_bytes += num_bytes, s->num_flows++;
  }
}

/* @brief heuristic choice for receiver stats */
int acceptable(u_int32_t num_pkts)
{
  return num_pkts > 5;
}

int receivers_sort_asc(void *_a, void *_b)
{
  struct receiver *a = (struct receiver *)_a;
  struct receiver *b = (struct receiver *)_b;

  return(a->num_pkts - b->num_pkts);
}

/*@brief removes first (size - max) elements from hash table.
 * hash table is ordered in ascending order.
 */
struct receiver* cutBackTo(struct receiver **rcvrs, u_int32_t size, u_int32_t max)
{
  struct receiver *r, *tmp;
  int i = 0;
  int count;

  if (size < max) //return the original table
    return *rcvrs;

  count = size - max;

  HASH_ITER(hh, *rcvrs, r, tmp)
  {
    if (i++ == count)
      return r;
    HASH_DEL(*rcvrs, r);
    ndpi_free(r);
  }

  return(NULL);

}

/*@brief merge first table to the second table.
 * if element already in the second table
 *  then updates its value
 * else adds it to the second table
 */
void mergeTables(struct receiver **primary, struct receiver **secondary)
{
  struct receiver *r, *s, *tmp;

  HASH_ITER(hh, *primary, r, tmp)
  {
    HASH_FIND_INT(*secondary, (int *)&(r->addr), s);
    if (s == NULL)
    {
      s = (struct receiver *)ndpi_malloc(sizeof(struct receiver));
      if (!s) return;

      s->addr = r->addr;
      s->version = r->version;
      s->num_pkts = r->num_pkts;

      HASH_ADD_INT(*secondary, addr, s);
    }
    else
      s->num_pkts += r->num_pkts;

    HASH_DEL(*primary, r);
    ndpi_free(r);
  }
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

/* *********************************************** */
/* implementation of: https://jeroen.massar.ch/presentations/files/FloCon2010-TopK.pdf
 *
 * if (table1.size < max1 || acceptable) {
 *    create new element and add to the table1
 *    if (table1.size > max2) {
 *      cut table1 back to max1
 *      merge table 1 to table2
 *      if (table2.size > max1)
 *        cut table2 back to max1
 *    }
 * }
 * else
 *   update table1
 */
void updateReceivers(
  struct receiver** rcvrs,
  u_int32_t dst_addr,
  u_int8_t version,
  u_int32_t num_pkts,
  struct receiver** topRcvrs)
{
  struct receiver *r;
  u_int32_t size;
  int a;

  HASH_FIND_INT(*rcvrs, (int *)&dst_addr, r);
  if (r == NULL)
  {
    if (((size = HASH_COUNT(*rcvrs)) < MAX_TABLE_SIZE_1)
       || ((a = acceptable(num_pkts)) != 0))
    {
      r = (struct receiver *)ndpi_malloc(sizeof(struct receiver));
      if (!r) return;

      r->addr = dst_addr;
      r->version = version;
      r->num_pkts = num_pkts;

      HASH_ADD_INT(*rcvrs, addr, r);

      if ((size = HASH_COUNT(*rcvrs)) > MAX_TABLE_SIZE_2)
      {
        HASH_SORT(*rcvrs, receivers_sort_asc);
        *rcvrs = cutBackTo(rcvrs, size, MAX_TABLE_SIZE_1);
        mergeTables(rcvrs, topRcvrs);

        if ((size = HASH_COUNT(*topRcvrs)) > MAX_TABLE_SIZE_1)
        {
          HASH_SORT(*topRcvrs, receivers_sort_asc);
          *topRcvrs = cutBackTo(topRcvrs, size, MAX_TABLE_SIZE_1);
        }

        *rcvrs = NULL;
      }
    }
  }
  else
  {
    r->num_pkts += num_pkts;
  }
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

static void port_stats_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
  if ((which == ndpi_preorder) || (which == ndpi_leaf))
  {
    // Avoid walking the same node multiple times
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *(int *)user_data;
    u_int16_t sport, dport;
    char proto[16];

    (void)depth;

    sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);

    /* get app level protocol */
    if (flow->detected_protocol.proto.master_protocol)
    {
      ndpi_protocol2name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                         flow->detected_protocol, proto, sizeof(proto));
    }
    else
    {
      strncpy(proto, ndpi_get_proto_name(dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                         flow->detected_protocol.proto.app_protocol),sizeof(proto) - 1);
      proto[sizeof(proto) - 1] = '\0';
    }

    if (flow->protocol == IPPROTO_TCP
       && (flow->src2dst_packets == 1) && (flow->dst2src_packets == 0))
    {
      updateScanners(&scannerHosts, flow->src_ip, flow->ip_version, dport);
    }

    updateReceivers(&receivers, flow->dst_ip, flow->ip_version,
                    flow->src2dst_packets, &topReceivers);

    updatePortStats(&srcStats, sport, flow->src_ip, flow->ip_version,
                    flow->src2dst_packets, flow->src2dst_bytes, proto);

    updatePortStats(&dstStats, dport, flow->dst_ip, flow->ip_version,
                    flow->dst2src_packets, flow->dst2src_bytes, proto);
  }
}

void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if (dpi_handle_holder.info->ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if ((which == ndpi_preorder) || (which == ndpi_leaf))
  {
    // Avoid walking the same node multiple times
    if (flow->last_seen_ms + MAX_IDLE_TIME < dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->last_time)
    {
      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);
      if (verbose == 3)
        port_stats_walker(node, which, depth, user_data);

      if ((flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
        undetected_flows_deleted = 1;

      ndpi_flow_info_free_data(flow);

      /* adding to a queue (we can't delete it from the tree inline ) */
      dpi_handle_holder.info->ndpi_thread_info[thread_id].idle_flows[dpi_handle_holder.info->ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}

int is_realtime_protocol(ndpi_protocol proto)
{
  static u_int16_t const realtime_protos[] = {
    NDPI_PROTOCOL_YOUTUBE,
    NDPI_PROTOCOL_YOUTUBE_UPLOAD,
    NDPI_PROTOCOL_TIKTOK,
    NDPI_PROTOCOL_GOOGLE,
    NDPI_PROTOCOL_GOOGLE_CLASSROOM,
    NDPI_PROTOCOL_GOOGLE_CLOUD,
    NDPI_PROTOCOL_GOOGLE_DOCS,
    NDPI_PROTOCOL_GOOGLE_DRIVE,
    NDPI_PROTOCOL_GOOGLE_MAPS,
    NDPI_PROTOCOL_GOOGLE_SERVICES
  };
  u_int16_t i;

  for (i = 0; i < NDPI_ARRAY_LENGTH(realtime_protos); i++)
  {
    if (proto.proto.app_protocol == realtime_protos[i]
        || proto.proto.master_protocol == realtime_protos[i])
      {
	return 1;
      }
  }

  return 0;
}

void dump_realtime_protocol(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow)
{
  FILE *out = results_file ? results_file : stdout;
  char srcip[70], dstip[70];
  char ip_proto[64], app_name[64];
  char date[64];
  int ret = is_realtime_protocol(flow->detected_protocol);
  time_t firsttime = flow->first_seen_ms;
  struct tm result;

  if (ndpi_gmtime_r(&firsttime, &result) != NULL)
  {
    strftime(date, sizeof(date), "%d.%m.%y %H:%M:%S", &result);
  }
  else
  {
    snprintf(date, sizeof(date), "%s", "Unknown");
  }

  if (flow->ip_version == 4)
  {
    inet_ntop(AF_INET, &flow->src_ip, srcip, sizeof(srcip));
    inet_ntop(AF_INET, &flow->dst_ip, dstip, sizeof(dstip));
  }
  else
  {
    snprintf(srcip, sizeof(srcip), "[%s]", flow->src_name);
    snprintf(dstip, sizeof(dstip), "[%s]", flow->dst_name);
  }

  ndpi_protocol2name(workflow->ndpi_struct, flow->detected_protocol, app_name, sizeof(app_name));

  if (ret == 1)
  {
    fprintf(out, "Detected Realtime protocol %s --> [%s] %s:%d <--> %s:%d app=%s <%s>\n",
            date, ndpi_get_ip_proto_name(flow->protocol, ip_proto, sizeof(ip_proto)),
            srcip, ntohs(flow->src_port), dstip, ntohs(flow->dst_port),
            app_name, flow->human_readeable_string_buffer);
  }
}

void on_protocol_discovered(
  struct ndpi_workflow* workflow,
  struct ndpi_flow_info* flow,
  void* /*userdata*/)
{
  if (enable_realtime_output != 0)
    dump_realtime_protocol(workflow, flow);
}

void setup_detection(
  DPIHandleHolder::Info& dpi_handle_info,
  u_int16_t thread_id,
  pcap_t* pcap_handle,
  struct ndpi_global_context *g_ctx)
{
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  struct ndpi_workflow_prefs prefs;
  int i, ret;
  ndpi_cfg_error rc;

  memset(&prefs, 0, sizeof(prefs));
  prefs.decode_tunnels = decode_tunnels;
  prefs.num_roots = NUM_ROOTS;
  prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
  prefs.quiet_mode = quiet_mode;
  prefs.ignore_vlanid = ignore_vlanid;

  memset(
    &dpi_handle_info.ndpi_thread_info[thread_id],
    0,
    sizeof(dpi_handle_info.ndpi_thread_info[thread_id]));
  dpi_handle_info.ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(
    &prefs,
    pcap_handle,
    1,
    serialization_format,
    g_ctx);

  /* Protocols to enable/disable. Default: everything is enabled */
  NDPI_BITMASK_SET_ALL(enabled_bitmask);
  if (_disabled_protocols != NULL)
  {
    if (parse_proto_name_list(_disabled_protocols, &enabled_bitmask, 1))
      exit(-1);
  }

  if (_categoriesDirPath)
  {
    int failed_files = ndpi_load_categories_dir(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      _categoriesDirPath);
    if (failed_files < 0)
    {
      fprintf(stderr, "Failed to parse all *.list files in: %s\n", _categoriesDirPath);
      exit(-1);
    }
  }

  if (_domain_suffixes)
  {
    ndpi_load_domain_suffixes(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      _domain_suffixes);
  }

  if (_riskyDomainFilePath)
  {
    ndpi_load_risk_domain_file(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      _riskyDomainFilePath);
  }

  if (_maliciousJA4Path)
  {
    ndpi_load_malicious_ja4_file(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      _maliciousJA4Path);
  }

  if (_maliciousSHA1Path)
  {
    ndpi_load_malicious_sha1_file(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      _maliciousSHA1Path);
  }

  if (_customCategoryFilePath)
  {
    char *label = strrchr(_customCategoryFilePath, '/');

    if (label != NULL)
      label = &label[1];
    else
      label = _customCategoryFilePath;

    int failed_lines = ndpi_load_categories_file(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      _customCategoryFilePath,
      label);
    if (failed_lines < 0)
    {
      fprintf(stderr, "Failed to parse custom categories file: %s\n", _customCategoryFilePath);
      exit(-1);
    }
  }

  dpi_handle_info.ndpi_thread_info[thread_id].workflow->g_ctx = g_ctx;

  ndpi_workflow_set_flow_callback(
    dpi_handle_info.ndpi_thread_info[thread_id].workflow,
    on_protocol_discovered,
    NULL);

  /* Make sure to load lists before finalizing the initialization */
  ndpi_set_protocol_detection_bitmask2(
    dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
    &enabled_bitmask);

  if (_protoFilePath != NULL)
  {
    ndpi_load_protocols_file(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      _protoFilePath);
  }

  ndpi_set_config(
    dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
    NULL,
    "tcp_ack_payload_heuristic",
    "enable");

  for (i = 0; i < num_cfgs; i++)
  {
    rc = ndpi_set_config(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      cfgs[i].proto,
      cfgs[i].param,
      cfgs[i].value);

    if (rc != NDPI_CFG_OK)
    {
      fprintf(stderr, "Error setting config [%s][%s][%s]: %s (%d)\n",
	      (cfgs[i].proto != NULL ? cfgs[i].proto : ""),
	      cfgs[i].param, cfgs[i].value, ndpi_cfg_error2string(rc), rc);
      exit(-1);
    }
  }

  if (enable_doh_dot_detection)
  {
    ndpi_set_config(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      "tls",
      "application_blocks_tracking",
      "enable");
  }

  if (addr_dump_path != NULL)
  {
    ndpi_cache_address_restore(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      addr_dump_path,
      0);
  }

  ret = ndpi_finalize_initialization(
    dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct);

  if (ret != 0)
  {
    fprintf(stderr, "Error ndpi_finalize_initialization: %d\n", ret);
    exit(-1);
  }

  char buf[16];
  if (ndpi_get_config(
        dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
        "stun",
        "monitoring",
        buf,
        sizeof(buf)) != NULL)
  {
    if (atoi(buf))
    {
      monitoring_enabled = 1;
    }
  }
}

void terminate_detection(
  DPIHandleHolder::Info& dpi_handle_info,
  u_int16_t thread_id)
{
  ndpi_workflow_free(dpi_handle_info.ndpi_thread_info[thread_id].workflow);
  dpi_handle_info.ndpi_thread_info[thread_id].workflow = NULL;
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

int port_stats_sort(void *_a, void *_b)
{
  struct port_stats *a = (struct port_stats*)_a;
  struct port_stats *b = (struct port_stats*)_b;

  if (b->num_pkts == 0 && a->num_pkts == 0)
    return(b->num_flows - a->num_flows);

  return(b->num_pkts - a->num_pkts);
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

int hash_stats_sort_to_order(void *_a, void *_b)
{
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (a->occurency - b->occurency);
}

int hash_stats_sort_to_print(void *_a, void *_b)
{
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (b->occurency - a->occurency);
}

void print_flows_stats()
{
  int thread_id;
  u_int32_t total_flows = 0;
  FILE *out = results_file ? results_file : stdout;

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

    for (thread_id = 0; thread_id < num_threads; thread_id++)
    {
      if (dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter[
        0 //< 0 = Unknown
        ] > 0)
      {
        fprintf(out, "\n\nUndetected flows:%s\n",
          undetected_flows_deleted ? " (expired flows are not listed below)" : "");
        break;
      }
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

  ndpi_free(all_flows);
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

      if (verbose == 3 || stats_flag)
      {
        ndpi_twalk(
          dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
          port_stats_walker,
          &thread_id);
      }
    }

    /* Stats aggregation */
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
    printf("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
    printf("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));
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

      if (enable_malloc_bins)
      {
	printf("\tData-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
      }
    }
  }

  if (results_file)
  {
    if (cumulative_stats.guessed_flow_protocols)
    {
      fprintf(results_file, "Guessed flow protos:\t%u\n\n", cumulative_stats.guessed_flow_protocols);
    }

    if (cumulative_stats.flow_count[0])
    {
      fprintf(results_file, "DPI Packets (TCP):\t%llu\t(%.2f pkts/flow)\n",
        (long long unsigned int)cumulative_stats.dpi_packet_count[0],
        cumulative_stats.dpi_packet_count[0] / (float)cumulative_stats.flow_count[0]);
    }

    if (cumulative_stats.flow_count[1])
    {
      fprintf(results_file, "DPI Packets (UDP):\t%llu\t(%.2f pkts/flow)\n",
        (long long unsigned int)cumulative_stats.dpi_packet_count[1],
        cumulative_stats.dpi_packet_count[1] / (float)cumulative_stats.flow_count[1]);
    }

    if (cumulative_stats.flow_count[2])
    {
      fprintf(results_file, "DPI Packets (other):\t%llu\t(%.2f pkts/flow)\n",
        (long long unsigned int)cumulative_stats.dpi_packet_count[2],
        cumulative_stats.dpi_packet_count[2] / (float)cumulative_stats.flow_count[2]);
    }

    for (int i = 0; i < sizeof(cumulative_stats.flow_confidence) /
      sizeof(cumulative_stats.flow_confidence[0]); i++)
    {
      if (cumulative_stats.flow_confidence[i] != 0)
      {
	fprintf(results_file, "Confidence %-17s: %llu (flows)\n",
          ndpi_confidence_get_name((ndpi_confidence_t)i),
          (long long unsigned int)cumulative_stats.flow_confidence[i]);
      }
    }

    if (dump_fpc_stats)
    {
      for (int i = 0; i < sizeof(cumulative_stats.fpc_flow_confidence) /
        sizeof(cumulative_stats.fpc_flow_confidence[0]); ++i)
      {
        if (cumulative_stats.fpc_flow_confidence[i] != 0)
        {
          fprintf(
	    results_file, "FPC Confidence %-17s: %llu (flows)\n",
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
	fprintf(results_file, "Num dissector calls: %llu (%.2f diss/flow)\n",
          (long long unsigned int)cumulative_stats.num_dissector_calls,
          cumulative_stats.num_dissector_calls / (float)cumulative_stats.ndpi_flow_count);
      }

      fprintf(results_file, "LRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
      fprintf(results_file, "LRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
      fprintf(results_file, "LRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_search,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_found);
      fprintf(results_file, "LRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
      fprintf(results_file, "LRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_search,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_found);
      fprintf(results_file, "LRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
      fprintf(results_file, "LRU cache fpc_dns:    %llu/%llu/%llu (insert/search/found)\n",
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_insert,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_search,
        (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_found);

      fprintf(results_file, "Automa host:          %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_search,
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_found);
      fprintf(results_file, "Automa domain:        %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
      fprintf(results_file, "Automa tls cert:      %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
      fprintf(results_file, "Automa risk mask:     %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
      fprintf(results_file, "Automa common alpns:  %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
        (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

      fprintf(results_file, "Patricia risk mask:   %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
      fprintf(results_file, "Patricia risk mask IPv6: %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
      fprintf(results_file, "Patricia risk:        %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_search,
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_found);
      fprintf(results_file, "Patricia risk IPv6:   %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_search,
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_found);
      fprintf(results_file, "Patricia protocols:   %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
      fprintf(results_file, "Patricia protocols IPv6: %llu/%llu (search/found)\n",
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
        (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

      if (enable_malloc_bins)
      {
        fprintf(results_file, "Data-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
      }
    }

    fprintf(results_file, "\n");
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

      if (results_file)
      {
	fprintf(results_file, "%s\t%llu\t%llu\t%u",
          ndpi_get_proto_name(
            dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct,
            ndpi_map_ndpi_id_to_user_proto_id(
              dpi_handle_holder.info->ndpi_thread_info[0].workflow->ndpi_struct, i)),
          (long long unsigned int)cumulative_stats.protocol_counter[i],
          (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
          cumulative_stats.protocol_flows[i]);

	if (dump_fpc_stats)
	{
	  fprintf(results_file, "\t%llu\t%llu\t%u",
            (long long unsigned int)cumulative_stats.fpc_protocol_counter[i],
            (long long unsigned int)cumulative_stats.fpc_protocol_counter_bytes[i],
            cumulative_stats.fpc_protocol_flows[i]);

	  if (cumulative_stats.protocol_counter[i] != cumulative_stats.fpc_protocol_counter[i] ||
	     cumulative_stats.protocol_counter_bytes[i] != cumulative_stats.fpc_protocol_counter_bytes[i] ||
	     cumulative_stats.protocol_flows[i] != cumulative_stats.fpc_protocol_flows[i])
          {
	    fprintf(results_file, "\t(*)");
          }
	}

	fprintf(results_file, "\n");
      }

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

  if (results_file)
  {
    fprintf(results_file, "\n");
    for (int i = 0; i < NUM_BREEDS; i++)
    {
      if (breed_stats_pkts[i] > 0)
      {
	fprintf(results_file, "%-20s %13llu %-13llu %-13llu\n",
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

void break_pcap_loop(DPIHandleHolder::Info& dpi_handle_info, u_int16_t thread_id)
{
  if (dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
  {
    printf("break pcap loop %u\n", thread_id);
    pcap_breakloop(dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle);
  }
}

void sigproc(int sig)
{
  static int called = 0;

  (void)sig;

  if (called)
  {
    return;
  }

  called = 1;
  shutdown_app = 1;

  DPIHandleHolder::InfoPtr dpi_handle_info;

  {
    std::unique_lock lock{dpi_handle_holder.lock};
    dpi_handle_info = dpi_handle_holder.info; //< Don't reset ptr - now code isn't ready.
  }

  if (dpi_handle_info)
  {
    for (int thread_id = 0; thread_id < num_threads; thread_id++)
    {
      break_pcap_loop(*dpi_handle_info, thread_id);
    }
  }
}


int get_next_pcap_file_from_playlist(
  u_int16_t thread_id,
  char filename[],
  u_int32_t filename_len)
{
  if (playlist_fp[thread_id] == NULL)
  {
    if ((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
    {
      return -1;
    }
  }

 next_line:
  if (fgets(filename, filename_len, playlist_fp[thread_id]))
  {
    int l = strlen(filename);
    if (filename[0] == '\0' || filename[0] == '#')
    {
      goto next_line;
    }

    if (filename[l-1] == '\n')
    {
      filename[l-1] = '\0';
    }

    return 0;
  }
  else
  {
    fclose(playlist_fp[thread_id]);
    playlist_fp[thread_id] = NULL;
    return -1;
  }
}

void configure_pcap_handle(pcap_t * pcap_handle)
{
  if (!pcap_handle)
    return;

  if (bpfFilter != NULL)
  {
    if (!bpf_cfilter)
    {
      if (pcap_compile(pcap_handle, &bpf_code, bpfFilter, 1, 0xFFFFFF00) < 0)
      {
	printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
	return;
      }
      bpf_cfilter = &bpf_code;
    }

    if (pcap_setfilter(pcap_handle, bpf_cfilter) < 0)
    {
      printf("pcap_setfilter error: '%s'\n", pcap_geterr(pcap_handle));
    }
    else
    {
      printf("Successfully set BPF filter to '%s'\n", bpfFilter);
    }
  }
}

/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
static pcap_t* open_pcap_file_or_device(u_int16_t thread_id, const u_char* pcap_file)
{
  u_int snaplen = 1536;
  int promisc = 1;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t* pcap_handle = NULL;

  // Trying to open the interface
  if ((pcap_handle = pcap_open_live(
    (char*)pcap_file,
    snaplen,
    promisc,
    500,
    pcap_error_buffer)) == NULL)
  {
    //capture_for = 0;
    //capture_until = 0;

    live_capture = 0;
    num_threads = 1; //< Open pcap files in single threads mode

    // Trying to open a pcap file
    if ((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL)
    {
      char filename[256] = "";

      if (strstr((char*)pcap_file, (char*)".pcap"))
      {
        throw dpi::DPIRunner::Exception(
          std::string("Could not open pcap file: ") + pcap_error_buffer);
      }
      // Trying to open as a playlist as last attempt
      else if (get_next_pcap_file_from_playlist(thread_id, filename, sizeof(filename)) != 0 ||
	(pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) == NULL)
      {
	/* This probably was a bad interface name, printing a generic error */
        throw dpi::DPIRunner::Exception(
          std::string("Could not open interface '") +
          filename + "': " + pcap_error_buffer);
      }
      else
      {
	if (!quiet_mode)
	  printf("Reading packets from playlist %s...\n", pcap_file);
      }
    }
    else
    {
      if (!quiet_mode)
	printf("Reading packets from pcap file %s...\n", pcap_file);
    }
  }
  else
  {
    live_capture = 1;

    if (!quiet_mode)
    {
      std::cout << "[TRACE] Capturing live traffic from device " << pcap_file << std::endl;
    }
  }

  configure_pcap_handle(pcap_handle);

  /*
  if (capture_for > 0)
  {
    if (!quiet_mode)
    {
      printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);
    }
  }
  */

  return pcap_handle;
}

void ndpi_process_packet(
  u_char* args,
  const struct pcap_pkthdr* header,
  const u_char* packet)
{
  u_int16_t thread_id = *((u_int16_t*)args);

  // Allocate an exact size buffer to check overflows
  uint8_t* packet_checked = (uint8_t*)ndpi_malloc(header->caplen);

  if (packet_checked == NULL)
  {
    return;
  }

  ::memcpy(packet_checked, packet, header->caplen);

  DPIHandleHolder::Info& dpi_handle_info = *dpi_handle_holder.info;

  ndpi_risk flow_risk;
  struct ndpi_flow_info* flow;
  struct ndpi_proto p = ndpi_workflow_process_packet(
    dpi_handle_info.ndpi_thread_info[thread_id].workflow,
    header,
    packet_checked,
    &flow_risk,
    &flow);

  if (!pcap_start.tv_sec)
  {
    pcap_start.tv_sec = header->ts.tv_sec;
    pcap_start.tv_usec = header->ts.tv_usec;
  }

  pcap_end.tv_sec = header->ts.tv_sec;
  pcap_end.tv_usec = header->ts.tv_usec;

  packet_processor->process_packet(
    dpi_handle_info.ndpi_thread_info[thread_id].workflow,
    flow,
    header);

  // Idle flows cleanup
  if (live_capture)
  {
    if (dpi_handle_info.ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD <
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->last_time)
    {
      // Scan for idle flows
      ndpi_twalk(
	dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_flows_root[
          dpi_handle_info.ndpi_thread_info[thread_id].idle_scan_idx],
        node_idle_scan_walker,
        &thread_id);

      // Remove idle flows (unfortunately we cannot do this inline)
      while (dpi_handle_info.ndpi_thread_info[thread_id].num_idle_flows > 0)
      {
	// search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) -
        // here flows are the node of a b-tree
	ndpi_tdelete(
          dpi_handle_info.ndpi_thread_info[thread_id].idle_flows[
            --dpi_handle_info.ndpi_thread_info[thread_id].num_idle_flows],
          &dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_flows_root[
            dpi_handle_info.ndpi_thread_info[thread_id].idle_scan_idx],
          ndpi_workflow_node_cmp);

        // free the memory associated to idle flow in "idle_flows" - (see struct reader thread)
        ndpi_free_flow_info_half(
          dpi_handle_info.ndpi_thread_info[thread_id].idle_flows[
            dpi_handle_info.ndpi_thread_info[thread_id].num_idle_flows]);
        ndpi_free(
          dpi_handle_info.ndpi_thread_info[thread_id].idle_flows[
            dpi_handle_info.ndpi_thread_info[thread_id].num_idle_flows]);
      }

      if (++dpi_handle_info.ndpi_thread_info[thread_id].idle_scan_idx ==
        dpi_handle_info.ndpi_thread_info[thread_id].workflow->prefs.num_roots)
      {
	dpi_handle_info.ndpi_thread_info[thread_id].idle_scan_idx = 0;
      }

      dpi_handle_info.ndpi_thread_info[thread_id].last_idle_scan_time =
        dpi_handle_info.ndpi_thread_info[thread_id].workflow->last_time;
    }
  }

  if (extcap_dumper && (
    extcap_packet_filter == (u_int16_t)-1 ||
    p.proto.app_protocol == extcap_packet_filter ||
    p.proto.master_protocol == extcap_packet_filter)
  )
  {
    struct pcap_pkthdr h;
    u_int32_t *crc, delta = sizeof(struct ndpi_packet_trailer);
    struct ndpi_packet_trailer *trailer;
    u_int16_t cli_score, srv_score;

    memcpy(&h, header, sizeof(h));

    if (extcap_add_crc)
    {
      delta += 4; /* ethernet trailer */
    }

    if (h.caplen > (sizeof(extcap_buf) - delta))
    {
      printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
      h.caplen = sizeof(extcap_buf) - delta;
    }

    trailer = (struct ndpi_packet_trailer*)&extcap_buf[h.caplen];
    memcpy(extcap_buf, packet, h.caplen);
    memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
    trailer->magic = htonl(WIRESHARK_NTOP_MAGIC);
    if (flow)
    {
      trailer->flags = flow->current_pkt_from_client_to_server;
      trailer->flags |= (flow->detection_completed << 2);
    }
    else
    {
      trailer->flags = 0 | (2 << 2);
    }
    trailer->flow_risk = htonl64(flow_risk);
    trailer->flow_score = htons(ndpi_risk2score(flow_risk, &cli_score, &srv_score));
    trailer->flow_risk_info_len = ntohs(WIRESHARK_FLOW_RISK_INFO_SIZE);
    if (flow && flow->risk_str)
    {
      ::strncpy(trailer->flow_risk_info, flow->risk_str, sizeof(trailer->flow_risk_info));
    }
    trailer->flow_risk_info[sizeof(trailer->flow_risk_info) - 1] = '\0';
    trailer->proto.master_protocol = htons(p.proto.master_protocol);
    trailer->proto.app_protocol = htons(p.proto.app_protocol);
    ndpi_protocol2name(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_struct,
      p,
      trailer->name,
      sizeof(trailer->name));

    // Metadata are (all) available in `flow` only after nDPI completed its work!
    // We export them only once
    // TODO: boundary check. Right now there is always enough room, but we should check it if we are
    // going to extend the list of the metadata exported
    trailer->metadata_len = ntohs(WIRESHARK_METADATA_SIZE);
    struct ndpi_packet_tlv *tlv = (struct ndpi_packet_tlv *)trailer->metadata;
    int tot_len = 0;

    if (flow && flow->detection_completed == 1)
    {
      if (flow->host_server_name[0] != '\0')
      {
        tlv->type = ntohs(WIRESHARK_METADATA_SERVERNAME);
        tlv->length = ntohs(sizeof(flow->host_server_name));
        memcpy(tlv->data, flow->host_server_name, sizeof(flow->host_server_name));
        /* TODO: boundary check */
        tot_len += 4 + htons(tlv->length);
        tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
      }

      if (flow->ssh_tls.ja4_client[0] != '\0')
      {
        tlv->type = ntohs(WIRESHARK_METADATA_JA4C);
        tlv->length = ntohs(sizeof(flow->ssh_tls.ja4_client));
        memcpy(tlv->data, flow->ssh_tls.ja4_client, sizeof(flow->ssh_tls.ja4_client));
        /* TODO: boundary check */
        tot_len += 4 + htons(tlv->length);
        tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
      }

      if (flow->ssh_tls.obfuscated_heur_matching_set.pkts[0] != 0)
      {
        tlv->type = ntohs(WIRESHARK_METADATA_TLS_HEURISTICS_MATCHING_FINGERPRINT);
        tlv->length = ntohs(sizeof(struct ndpi_tls_obfuscated_heuristic_matching_set));
        struct ndpi_tls_obfuscated_heuristic_matching_set *s =  (struct ndpi_tls_obfuscated_heuristic_matching_set *)tlv->data;
        s->bytes[0] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[0]);
        s->bytes[1] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[1]);
        s->bytes[2] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[2]);
        s->bytes[3] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[3]);
        s->pkts[0] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[0]);
        s->pkts[1] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[1]);
        s->pkts[2] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[2]);
        s->pkts[3] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[3]);
        /* TODO: boundary check */
        tot_len += 4 + htons(tlv->length);
        tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
      }

      flow->detection_completed = 2;
      //< Avoid exporting metadata again.
      // If we really want to have the metadata on Wireshark for *all*
      // the future packets of this flow, simply remove that assignment
    }

    // Last: padding
    tlv->type = 0;
    tlv->length = ntohs(WIRESHARK_METADATA_SIZE - tot_len - 4);
    // The remaining bytes are already set to 0

    if (extcap_add_crc)
    {
      crc = (uint32_t*)&extcap_buf[h.caplen + sizeof(struct ndpi_packet_trailer)];
      *crc = ndpi_crc32((const void*)extcap_buf, h.caplen + sizeof(struct ndpi_packet_trailer), 0);
    }
    h.caplen += delta;
    h.len += delta;

    pcap_dump((u_char*)extcap_dumper, &h, (const u_char *)extcap_buf);
    pcap_dump_flush(extcap_dumper);
  }

  // Check for buffer changes
  if (::memcmp(packet, packet_checked, header->caplen) != 0)
  {
    printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen [thread_id=%u, packetId=%lu, caplen=%u]\n",
      thread_id,
      (unsigned long)dpi_handle_info.ndpi_thread_info[thread_id].workflow->stats.raw_packet_count,
      header->caplen);
  }

  if ((u_int32_t)(pcap_end.tv_sec-pcap_start.tv_sec) > pcap_analysis_duration)
  {
    u_int64_t processing_time_usec, setup_time_usec;

    gettimeofday(&end, NULL);
    processing_time_usec = (u_int64_t)end.tv_sec*1000000 + end.tv_usec -
      ((u_int64_t)begin.tv_sec*1000000 + begin.tv_usec);
    setup_time_usec = (u_int64_t)begin.tv_sec*1000000 + begin.tv_usec -
      ((u_int64_t)startup_time.tv_sec*1000000 + startup_time.tv_usec);

    print_results(processing_time_usec, setup_time_usec);

    for (unsigned int i = 0;
      i < dpi_handle_info.ndpi_thread_info[thread_id].workflow->prefs.num_roots; ++i)
    {
      ndpi_tdestroy(
        dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
        ndpi_flow_info_freer);
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

      ::memset(
        &dpi_handle_info.ndpi_thread_info[thread_id].workflow->stats,
        0,
        sizeof(struct ndpi_stats));
    }

    ::memcpy(&begin, &end, sizeof(begin));
    ::memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
  }

  // Leave the free as last statement to avoid crashes when ndpi_detection_giveup()
  // is called above by print_results()
  if (packet_checked)
  {
    ndpi_free(packet_checked);
    packet_checked = NULL;
  }
}

/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
void run_pcap_loop(DPIHandleHolder::Info& dpi_handle_info, u_int16_t thread_id)
{
  if (!shutdown_app && (
    dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle != NULL))
  {
    int datalink_type = pcap_datalink(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle);

    /* When using as extcap interface, the output/dumper pcap must have the same datalink
       type of the input traffic [to be able to use, for example, input pcaps with
       Linux "cooked" capture encapsulation (i.e. captured with "any" interface...) where
       there isn't an ethernet header]
    */
    if (do_extcap_capture)
    {
      extcap_capture(datalink_type);
      if (datalink_type == DLT_EN10MB)
      {
        extcap_add_crc = 1;
      }
    }

    if (!ndpi_is_datalink_supported(datalink_type))
    {
      printf("Unsupported datalink %d. Skip pcap\n", datalink_type);
      return;
    }

    int ret = pcap_loop(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle,
      -1,
      &ndpi_process_packet,
      (u_char*)&thread_id);

    if (ret == -1)
    {
      printf(
        "Error while reading pcap file: '%s'\n",
        pcap_geterr(dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle));
    }
  }
}

/**
 * @brief Process a running thread
 */
void* processing_thread(void* _thread_id)
{
  long int thread_id = (long int)_thread_id;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];

  DPIHandleHolder::InfoPtr dpi_handle_info_ptr;

  {
    std::unique_lock lock{dpi_handle_holder.lock};
    dpi_handle_info_ptr = dpi_handle_holder.info;
  }

  if (!dpi_handle_info_ptr)
  {
    return nullptr;
  }

  DPIHandleHolder::Info& dpi_handle_info = *dpi_handle_info_ptr;

#if defined(__linux__) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
  if (core_affinity[thread_id] >= 0)
  {
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_affinity[thread_id], &cpuset);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
    {
      fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
    }
    else if (!quiet_mode)
    {
      printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
    }
  }
  else
#endif
  if (!quiet_mode)
  {
    printf("Running thread %ld...\n", thread_id);
  }

 pcap_loop:
  run_pcap_loop(dpi_handle_info, thread_id);

  if (dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle)
  {
    pcap_close(dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle);
  }

  dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle = NULL;

  if (playlist_fp[thread_id] != NULL)
  {
    // playlist: read next file
    char filename[256];

    if (get_next_pcap_file_from_playlist(thread_id, filename, sizeof(filename)) == 0 && (
      dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle =
        pcap_open_offline(filename, pcap_error_buffer)) != NULL)
    {
      configure_pcap_handle(dpi_handle_info.ndpi_thread_info[thread_id].workflow->pcap_handle);
      goto pcap_loop;
    }
  }

  if (bpf_cfilter)
  {
    pcap_freecode(bpf_cfilter);
    bpf_cfilter = NULL;
  }

  return NULL;
}

void main_loop()
{
  u_int64_t processing_time_usec, setup_time_usec;
  struct ndpi_global_context *g_ctx;

  set_ndpi_malloc(ndpi_malloc_wrapper);
  set_ndpi_free(free_wrapper);
  set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

#ifndef USE_GLOBAL_CONTEXT
  // ndpiReader works even if libnDPI has been compiled without global context support,
  // but you can't configure any cache with global scope
  g_ctx = NULL;
#else
  g_ctx = ndpi_global_init();
  if (!g_ctx)
  {
    fprintf(stderr, "Error ndpi_global_init\n");
    exit(-1);
  }
#endif

  DPIHandleHolder::InfoPtr dpi_handle_info = std::make_shared<DPIHandleHolder::Info>();

  ::memset(
    dpi_handle_info->ndpi_thread_info,
    0,
    sizeof(dpi_handle_info->ndpi_thread_info));

  for (long thread_id = 0; thread_id < num_threads; ++thread_id)
  {
    pcap_t *cap;
    cap = open_pcap_file_or_device(thread_id, (const u_char*)_pcap_file[thread_id]);
    setup_detection(*dpi_handle_info, thread_id, cap, g_ctx);
  }

  // publish
  {
    std::unique_lock lock{dpi_handle_holder.lock};
    dpi_handle_holder.info = dpi_handle_info;
  }
  
  gettimeofday(&begin, NULL);

  int status;

  // Running processing threads
  for (long thread_id = 0; thread_id < num_threads; thread_id++)
  {
    status = pthread_create(
      &dpi_handle_info->ndpi_thread_info[thread_id].pthread,
      NULL,
      processing_thread,
      (void*)thread_id);

    if (status != 0)
    {
      fprintf(stderr, "error on create %ld thread\n", thread_id);
      exit(-1);
    }
  }

  // Waiting for completion
  for (long thread_id = 0; thread_id < num_threads; thread_id++)
  {
    void *thd_res;

    status = pthread_join(
      dpi_handle_info->ndpi_thread_info[thread_id].pthread,
      &thd_res);

    if (status != 0)
    {
      fprintf(stderr, "error on join %ld thread\n", thread_id);
      exit(-1);
    }

    if (thd_res != NULL)
    {
      fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
      exit(-1);
    }
  }

  gettimeofday(&end, NULL);
  processing_time_usec = (u_int64_t)end.tv_sec*1000000 + end.tv_usec -
    ((u_int64_t)begin.tv_sec*1000000 + begin.tv_usec);
  setup_time_usec = (u_int64_t)begin.tv_sec*1000000 + begin.tv_usec -
    ((u_int64_t)startup_time.tv_sec*1000000 + startup_time.tv_usec);

  /* Printing cumulative results */
  print_results(processing_time_usec, setup_time_usec);

  for (long thread_id = 0; thread_id < num_threads; thread_id++)
  {
    if (dpi_handle_info->ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
    {
      pcap_close(dpi_handle_info->ndpi_thread_info[thread_id].workflow->pcap_handle);
    }

    terminate_detection(*dpi_handle_info, thread_id);
  }

  ndpi_global_deinit(g_ctx);
}

void bpf_filter_port_array_init(int array[], int size)
{
  for (int i = 0; i<size; i++)
  {
    array[i] = INIT_VAL;
  }
}

void bpf_filter_host_array_init(const char *array[48], int size)
{
  for (int i = 0; i<size; i++)
  {
    array[i] = NULL;
  }
}

void bpf_filter_host_array_add(const char *filter_array[48], int size, const char *host)
{
  for (int i = 0; i < size; ++i)
  {
    if (filter_array[i] != NULL && strcmp(filter_array[i], host) == 0)
    {
      return;
    }

    if (filter_array[i] == NULL)
    {
      filter_array[i] = host;
      return;
    }
  }

  fprintf(stderr, "bpf_filter_host_array_add: max array size is reached!\n");
  exit(-1);
}


void bpf_filter_port_array_add(int filter_array[], int size, int port)
{
  for (int i = 0; i < size; ++i)
  {
    if (filter_array[i] == port)
    {
      return;
    }

    if (filter_array[i] == INIT_VAL)
    {
      filter_array[i] = port;
      return;
    }
  }

  fprintf(stderr,"bpf_filter_port_array_add: max array size is reached!\n");
  exit(-1);
}

namespace dpi
{
  DPIRunner::DPIRunner(
    std::string_view config_path,
    PacketProcessorPtr packet_processor)
    : config_path_(config_path),
      packet_processor_(std::move(packet_processor))
  {}

  void DPIRunner::run_()
  {
    std::string_view config_path = config_path_;

    // read config
    int i;

    if (ndpi_get_api_version() != NDPI_API_VERSION)
    {
      throw Exception(
        "nDPI Library version mismatch: please make sure "
        "this code and the nDPI library are in sync");
    }

    gettimeofday(&startup_time, NULL);

    config = std::make_shared<dpi::Config>(
      !config_path.empty() ? dpi::Config::read(config_path) : dpi::Config());

    if (!config->pcap_file.empty())
    {
      _pcap_file[0] = config->pcap_file.c_str();
    }
    else if (!config->interface.empty())
    {
      _pcap_file[0] = config->interface.c_str();
    }

    char* argv[] = {0};
    parse_options(0, argv);

    if (enable_doh_dot_detection)
    {
      init_doh_bins();

      // Clusters are not really used in DoH/DoT detection, but because of how
      // the code has been written, we need to enable also clustering feature
      if (num_bin_clusters == 0)
      {
        num_bin_clusters = 1;
      }
    }

    if (!quiet_mode)
    {
      const char* gcrypt_ver = ndpi_get_gcrypt_version();
      if (gcrypt_ver)
      {
        std::cout << "Using libgcrypt version " << gcrypt_ver << std::endl;
      }
    }

    signal(SIGINT, sigproc);

    main_loop();

    if (results_path)
    {
      ndpi_free(results_path);
    }

    if (results_file)
    {
      fclose(results_file);
    }

    if (extcap_dumper)
    {
      pcap_dump_close(extcap_dumper);
    }

    if (extcap_fifo_h)
    {
      pcap_close(extcap_fifo_h);
    }

    if (enable_malloc_bins)
    {
      ndpi_free_bin(&malloc_bins);
    }

    if (csv_fp)
    {
      fclose(csv_fp);
    }

    if (fingerprint_fp)
    {
      fclose(fingerprint_fp);
    }

    ndpi_free(_disabled_protocols);

    for (i = 0; i < num_cfgs; i++)
    {
      ndpi_free(cfgs[i].proto);
      ndpi_free(cfgs[i].param);
      ndpi_free(cfgs[i].value);
    }

    for (i = 0; i < fargc; i++)
    {
      ndpi_free(fargv[i]);
    }
  }

  void
  DPIRunner::activate_object()
  {
    packet_processor = packet_processor_;
    thread_.reset(new std::thread(&DPIRunner::run_, this));
    Gears::SimpleActiveObject::activate_object();
  }

  void
  DPIRunner::deactivate_object()
  {
    Gears::SimpleActiveObject::deactivate_object();
    if (thread_)
    {
      sigproc(SIGINT);
    }
  }

  void
  DPIRunner::wait_object()
  {
    if(thread_)
    {
      thread_->join();
      thread_.reset();
    }

    Gears::SimpleActiveObject::deactivate_object();
    Gears::SimpleActiveObject::wait_object();
  }
}
