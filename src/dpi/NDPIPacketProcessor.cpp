#include <ndpi/ndpi_config.h>

#include <sched.h>

#include "ndpi_api.h"
#include <uthash.h>
#include <ahocorasick.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
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

#include <gears/CompositeActiveObject.hpp>

#include "NetInterfaceProcessor.hpp"
#include "ReaderUtil.hpp"
#include "PacketProcessor.hpp"
#include "Config.hpp"
#include "NDPIPacketProcessor.hpp"
#include "DPIPrintUtils.hpp"
#include "DPIUtils.hpp"

//dpi::PacketProcessorPtr packet_processor;

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

static char *results_path           = NULL;
//static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path */
static char *_customCategoryFilePath= NULL; /**< Custom categories file path  */
static char *_maliciousJA4Path      = NULL; /**< Malicious JA4 signatures */
static char *_maliciousSHA1Path     = NULL; /**< Malicious SSL certificate SHA1 fingerprints */
static char *_riskyDomainFilePath   = NULL; /**< Risky domain files */
static char *_domain_suffixes       = NULL; /**< Domain suffixes file */
static char *_categoriesDirPath     = NULL; /**< Directory containing domain files */
static u_int8_t undetected_flows_deleted = 0;
static ndpi_serialization_format serialization_format = ndpi_serialization_format_unknown;
static char* domain_to_check = NULL;
static char* ip_port_to_check = NULL;
static u_int8_t ignore_vlanid = 0;
FILE* fingerprint_fp = NULL; /**< for flow fingerprint export */

#ifdef __linux__
static char* bind_mask = NULL;
#endif
#define MAX_FARGS 64
static char* fargv[MAX_FARGS];
static int fargc = 0;

/** User preferences **/
char* addr_dump_path = NULL;
u_int8_t enable_realtime_output = 0;
u_int8_t extcap_exit = 0;
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
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 24 /* 8 is enough for most protocols, Signal and SnapchatCall require more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0;
static struct timeval startup_time, begin, end;

#ifdef __linux__
static int core_affinity[MAX_NUM_READER_THREADS];
#endif
#ifndef USE_DPDK
static struct bpf_program bpf_code;
#endif

extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection, max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;

static struct ndpi_bin malloc_bins;
static int max_malloc_bins = 14;
int malloc_size_stats = 0;

int monitoring_enabled;

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
struct ndpi_packet_trailer
{
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

// ID tracking
typedef struct ndpi_id {
  u_int8_t ip[4];                   // Ip address
  struct ndpi_id_struct *ndpi_id;  // nDpi worker structure
} ndpi_id_t;

// used memory counters
static u_int32_t current_ndpi_memory = 0;
static u_int32_t max_ndpi_memory = 0;

#ifdef USE_DPDK
static int dpdk_port_id = 0, dpdk_run_capture = 1;
#endif

extern int parse_proto_name_list(
  char *str,
  NDPI_PROTOCOL_BITMASK *bitmask,
  int inverted_logic);

extern u_int8_t is_ndpi_proto(
  struct ndpi_flow_info *flow, u_int16_t id);

u_int32_t reader_slot_malloc_bins(u_int64_t v)
{
  /* 0-2,3-4,5-8,9-16,17-32,33-64,65-128,129-256,257-512,513-1024,1025-2048,2049-4096,4097-8192,8193- */
  int i = 0;

  for (; i < max_malloc_bins - 1; i++)
  {
    if ((1ULL << (i + 1)) >= v)
    {
      return i;
    }
  }

  return i;
}

void* ndpi_malloc_wrapper(size_t size)
{
  current_ndpi_memory += size;

  if (current_ndpi_memory > max_ndpi_memory)
  {
    max_ndpi_memory = current_ndpi_memory;
  }

  if (enable_malloc_bins && malloc_size_stats)
  {
    ndpi_inc_bin(&malloc_bins, reader_slot_malloc_bins(size), 1);
  }

  return malloc(size); // Don't change to ndpi_malloc !!!!!
}

void free_wrapper(void *freeable)
{
  free(freeable); /* Don't change to ndpi_free !!!!! */
}

static u_int8_t doh_centroids[NUM_DOH_BINS][PLEN_NUM_BINS] = {
  { 23,25,3,0,26,0,0,0,0,0,0,0,0,0,2,0,0,15,3,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
  { 35,30,21,0,0,0,2,4,0,0,5,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }
};

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
  //bpfFilter = NULL;
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

void node_proto_guess_walker(
  const void *node, ndpi_VISIT which, int depth, void *user_data)
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
    // avoid walking the same node multiple times
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
    proto = ndpi_map_user_proto_id_to_ndpi_id(
      dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct, proto);

    fpc_proto = flow->fpc.proto.app_protocol ? flow->fpc.proto.app_protocol : flow->fpc.proto.master_protocol;
    fpc_proto = ndpi_map_user_proto_id_to_ndpi_id(
      dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->ndpi_struct, fpc_proto);

    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto] +=
      flow->src2dst_packets + flow->dst2src_packets;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[proto] +=
      flow->src2dst_bytes + flow->dst2src_bytes;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.flow_confidence[flow->confidence]++;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls +=
      flow->num_dissector_calls;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter[fpc_proto] +=
      flow->src2dst_packets + flow->dst2src_packets;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter_bytes[fpc_proto] +=
      flow->src2dst_bytes + flow->dst2src_bytes;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_flows[fpc_proto]++;
    dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->stats.fpc_flow_confidence[flow->fpc.confidence]++;
  }
}

int acceptable(u_int32_t num_pkts)
{
  return num_pkts > 5;
}

void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
  struct ndpi_flow_info* flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if (dpi_handle_holder.info->ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET)
    // TODO optimise with a budget-based walk
  {
    return;
  }

  if ((which == ndpi_preorder) || (which == ndpi_leaf))
  {
    // Avoid walking the same node multiple times
    if (flow->last_seen_ms + MAX_IDLE_TIME < dpi_handle_holder.info->ndpi_thread_info[thread_id].workflow->last_time)
    {
      // update stats
      node_proto_guess_walker(node, which, depth, user_data);

      if ((flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN) &&
        !undetected_flows_deleted)
      {
        undetected_flows_deleted = 1;
      }

      ndpi_flow_info_free_data(flow);

      // adding to a queue (we can't delete it from the tree inline)
      dpi_handle_holder.info->ndpi_thread_info[thread_id].idle_flows[
        dpi_handle_holder.info->ndpi_thread_info[thread_id].num_idle_flows++] = flow;
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
  FILE* out = stdout;
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
      date,
      ndpi_get_ip_proto_name(flow->protocol, ip_proto, sizeof(ip_proto)),
      srcip,
      ntohs(flow->src_port), dstip, ntohs(flow->dst_port),
      app_name,
      flow->human_readeable_string_buffer);
  }
}

void on_protocol_discovered(
  struct ndpi_workflow* workflow,
  struct ndpi_flow_info* flow,
  void* /*userdata*/)
{
  if (enable_realtime_output != 0)
  {
    dump_realtime_protocol(workflow, flow);
  }
}

void bpf_filter_port_array_init(int array[], int size)
{
  for (int i = 0; i < size; i++)
  {
    array[i] = INIT_VAL;
  }
}

void bpf_filter_host_array_init(const char *array[48], int size)
{
  for (int i = 0; i < size; i++)
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

  exit(-1);
}

namespace dpi
{
  NDPIPacketProcessor::NDPIPacketProcessor(
    std::string_view config_path,
    PacketProcessorPtr packet_processor,
    int datalink_type)
    : config_path_(config_path),
      packet_processor_(std::move(packet_processor)),
      datalink_type_(datalink_type)
  {
    init_();
    init_ndpi_();
  }

  NDPIPacketProcessor::~NDPIPacketProcessor() noexcept
  {
    clear_ndpi_();
    clear_();
  }

  bool NDPIPacketProcessor::process_packet(
    const struct pcap_pkthdr* header,
    const void* packet,
    UserSessionPacketProcessor::Direction direction)
  {
    return process_packet_(0, header, packet, direction);
  }

  bool NDPIPacketProcessor::process_packet_(
    unsigned int thread_id,
    const struct pcap_pkthdr* header,
    const void* packet,
    UserSessionPacketProcessor::Direction direction)
  {
    // allocate an exact size buffer to check overflows
    uint8_t* packet_checked = (uint8_t*)ndpi_malloc(header->caplen);

    if (packet_checked == NULL)
    {
      return true;
    }

    ::memcpy(packet_checked, packet, header->caplen);

    DPIHandleHolder::Info& dpi_handle_info = *dpi_handle_holder_.info;

    ndpi_risk flow_risk;
    struct ndpi_flow_info* flow;
    struct ndpi_proto p = ndpi_workflow_process_packet(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow,
      header,
      packet_checked,
      &flow_risk,
      &flow,
      datalink_type_);

    if (!pcap_start.tv_sec)
    {
      pcap_start.tv_sec = header->ts.tv_sec;
      pcap_start.tv_usec = header->ts.tv_usec;
    }

    pcap_end.tv_sec = header->ts.tv_sec;
    pcap_end.tv_usec = header->ts.tv_usec;

    bool res = packet_processor_->process_packet(
      dpi_handle_info.ndpi_thread_info[thread_id].workflow,
      flow,
      header,
      direction);

    // Idle flows cleanup
    if (::live_capture)
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
        delta += 4; // ethernet trailer
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
          // TODO: boundary check
          tot_len += 4 + htons(tlv->length);
          tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
        }

        if (flow->ssh_tls.ja4_client[0] != '\0')
        {
          tlv->type = ntohs(WIRESHARK_METADATA_JA4C);
          tlv->length = ntohs(sizeof(flow->ssh_tls.ja4_client));
          memcpy(tlv->data, flow->ssh_tls.ja4_client, sizeof(flow->ssh_tls.ja4_client));
          // TODO: boundary check
          tot_len += 4 + htons(tlv->length);
          tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
        }

        if (flow->ssh_tls.obfuscated_heur_matching_set.pkts[0] != 0)
        {
          tlv->type = ntohs(WIRESHARK_METADATA_TLS_HEURISTICS_MATCHING_FINGERPRINT);
          tlv->length = ntohs(sizeof(struct ndpi_tls_obfuscated_heuristic_matching_set));
          struct ndpi_tls_obfuscated_heuristic_matching_set* s =
            (struct ndpi_tls_obfuscated_heuristic_matching_set *)tlv->data;
          s->bytes[0] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[0]);
          s->bytes[1] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[1]);
          s->bytes[2] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[2]);
          s->bytes[3] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[3]);
          s->pkts[0] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[0]);
          s->pkts[1] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[1]);
          s->pkts[2] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[2]);
          s->pkts[3] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[3]);
          // TODO: boundary check
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

    /*
    if (!res)
    {
      std::cout << "BLOCK PACKET ON NDPI" << std::endl;
    }
    */

    return res;
  }

  void
  NDPIPacketProcessor::set_datalink_type(int datalink_type)
  {
    datalink_type_ = datalink_type;
  }

  void NDPIPacketProcessor::init_()
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
  }

  void NDPIPacketProcessor::init_ndpi_()
  {
    set_ndpi_malloc(ndpi_malloc_wrapper);
    set_ndpi_free(free_wrapper);
    set_ndpi_flow_malloc(NULL);
    set_ndpi_flow_free(NULL);

#ifndef USE_GLOBAL_CONTEXT
    // ndpiReader works even if libnDPI has been compiled without global context support,
    // but you can't configure any cache with global scope
    g_ctx_ = NULL;
#else
    g_ctx_ = ndpi_global_init();
    if (!g_ctx_)
    {
      fprintf(stderr, "Error ndpi_global_init\n");
      exit(-1);
    }
#endif

    DPIHandleHolder::InfoPtr dpi_handle_info =
      std::make_shared<DPIHandleHolder::Info>();

    ::memset(
      dpi_handle_info->ndpi_thread_info,
      0,
      sizeof(dpi_handle_info->ndpi_thread_info));

    dpi_handle_holder_.info = dpi_handle_info;

    setup_detection_(*dpi_handle_info, 0 /*thread_id*/, g_ctx_);
  }

  void NDPIPacketProcessor::clear_ndpi_()
  {
    terminate_detection_(*dpi_handle_holder_.info, 0 /*thread_id*/);

    ndpi_global_deinit(g_ctx_);
  }

  void NDPIPacketProcessor::setup_detection_(
    DPIHandleHolder::Info& dpi_handle_info,
    u_int16_t thread_id,
    struct ndpi_global_context* g_ctx)
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
      1,
      serialization_format,
      g_ctx);

    // Protocols to enable/disable. Default: everything is enabled
    NDPI_BITMASK_SET_ALL(enabled_bitmask);
    if (_disabled_protocols != NULL)
    {
      if (parse_proto_name_list(_disabled_protocols, &enabled_bitmask, 1))
      {
        exit(-1);
      }
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
      char* label = strrchr(_customCategoryFilePath, '/');

      if (label != NULL)
      {
        label = &label[1];
      }
      else
      {
        label = _customCategoryFilePath;
      }

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

    // make sure to load lists before finalizing the initialization
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

  void NDPIPacketProcessor::terminate_detection_(
    DPIHandleHolder::Info& dpi_handle_info,
    u_int16_t thread_id)
  {
    ndpi_workflow_free(dpi_handle_info.ndpi_thread_info[thread_id].workflow);
    dpi_handle_info.ndpi_thread_info[thread_id].workflow = NULL;
  }

  void NDPIPacketProcessor::clear_()
  {
    if (results_path)
    {
      ndpi_free(results_path);
    }

    if (enable_malloc_bins)
    {
      ndpi_free_bin(&malloc_bins);
    }

    if (fingerprint_fp)
    {
      fclose(fingerprint_fp);
    }

    ndpi_free(_disabled_protocols);
  }
}
