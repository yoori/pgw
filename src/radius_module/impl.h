
void tel_gateway_initialize(
  const char* config_path,
  int config_path_len);

void tel_gateway_load(void);

void tel_gateway_unload(void);

bool tel_gateway_process_request(
  const char* called_station_id_buf,
  int called_station_id_len,
  uint32_t framed_address,
  uint32_t nas_address,
  const char* imsi_buf,
  uint8_t rat_type,
  const char* mcc_mnc,
  uint8_t tz,
  uint32_t sgsn_address,
  uint32_t access_network_charging_address,
  uint32_t charging_id,
  const char* gprs_negotiated_qos_profile
  );
