
void tel_gateway_initialize(
  const char* config_path,
  int config_path_len);

void tel_gateway_load(void);

void tel_gateway_unload(void);

bool tel_gateway_process_request(
  const char* called_station_id_buf,
  int called_station_id_len,
  uint32_t framed_ip_address,
  uint32_t nas_ip_address
  );
