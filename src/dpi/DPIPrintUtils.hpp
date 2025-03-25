#pragma once

#include <unistd.h>
#include <memory>
#include <mutex>

#include <ndpi/ndpi_config.h>
#include "ndpi_api.h"

#include <gears/ActiveObject.hpp>

#include "ReaderUtil.hpp"

extern FILE* csv_fp;
extern u_int8_t verbose;
extern bool enable_flow_stats;
extern bool enable_payload_analyzer;
extern FILE* serialization_fp; /**< for TLV,CSV,JSON export */
extern u_int8_t quiet_mode;
extern u_int8_t stats_flag;
extern u_int8_t live_capture;
extern u_int8_t num_threads;
extern u_int32_t risks_found;
extern struct port_stats* srcStats;
extern struct port_stats* dstStats;
extern struct ndpi_stats cumulative_stats;
extern int dump_fpc_stats;
extern int enable_malloc_bins;
extern u_int8_t dump_internal_stats;
extern u_int8_t enable_doh_dot_detection;
extern u_int8_t num_bin_clusters;
extern struct timeval pcap_start;
extern struct timeval pcap_end;

#define NUM_DOH_BINS 2

extern struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];

struct info_pair {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
};

struct flow_info {
  struct ndpi_flow_info *flow;
  u_int16_t thread_id;
};

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

// struct to hold top receiver hosts
struct receiver {
  u_int32_t addr; /* key */
  u_int8_t version; /* IP version */
  u_int32_t num_pkts;
  UT_hash_handle hh;
};

typedef struct node_a {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
  struct node_a *left, *right;
} addr_node;

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
  std::shared_ptr<Gears::ActiveObject> interrupter;
};

//extern DPIHandleHolder dpi_handle_holder;

void flowGetBDMeanandVariance(struct ndpi_flow_info* flow);

void print_bin(FILE *fout, const char *label, struct ndpi_bin *b);

const char* print_cipher(ndpi_cipher_weakness c);

double ndpi_flow_get_byte_count_entropy(
  const uint32_t byte_count[256],
  unsigned int num_bytes);

void print_flowSerialized(struct ndpi_flow_info* flow);

void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data);

void ndpi_report_payload_stats(FILE *out);
