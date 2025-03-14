#pragma once

#include <unistd.h>
#include <memory>
#include <mutex>

#include <ndpi/ndpi_config.h>
#include "ndpi_api.h"

#include "ReaderUtil.hpp"

extern FILE* csv_fp;
extern u_int8_t verbose;
extern u_int8_t enable_flow_stats;
extern u_int8_t enable_payload_analyzer;
extern FILE* serialization_fp; /**< for TLV,CSV,JSON export */

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

extern DPIHandleHolder dpi_handle_holder;

void print_flow(u_int32_t id, struct ndpi_flow_info *flow, u_int16_t thread_id);

void flowGetBDMeanandVariance(struct ndpi_flow_info* flow);

void print_bin(FILE *fout, const char *label, struct ndpi_bin *b);

const char* print_cipher(ndpi_cipher_weakness c);

void print_ndpi_address_port_list_file(FILE *out, const char *label, ndpi_address_port_list *list);

double ndpi_flow_get_byte_count_entropy(
  const uint32_t byte_count[256],
  unsigned int num_bytes);

void print_flowSerialized(struct ndpi_flow_info* flow);
