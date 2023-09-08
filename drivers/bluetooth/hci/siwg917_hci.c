/*
 * Copyright (c) 2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/bluetooth/hci_driver.h>
#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/sys/util.h>

#include "sl_wifi.h"
#include "ble_config.h"

#include "rsi_ble.h"
#include "rsi_ble_common_config.h"
#include "rsi_common_apis.h"
#include "rsi_rom_rng.h"

#define LOG_LEVEL CONFIG_BT_HCI_DRIVER_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(bt_hci_driver_siwg917);

static const sl_wifi_device_configuration_t config = {
	.boot_option = LOAD_NWP_FW,
	.mac_address = NULL,
	.band = SL_SI91X_WIFI_BAND_2_4GHZ,
	.region_code = US,
	.boot_config = {
		.oper_mode = SL_SI91X_CLIENT_MODE,
		.coex_mode = SL_SI91X_WLAN_BLE_MODE,
		.feature_bit_map = (SL_SI91X_FEAT_WPS_DISABLE | RSI_FEATURE_BIT_MAP),
		.tcp_ip_feature_bit_map =
			(RSI_TCP_IP_FEATURE_BIT_MAP | SL_SI91X_TCP_IP_FEAT_EXTENSION_VALID),
		.custom_feature_bit_map =
			(SL_SI91X_FEAT_CUSTOM_FEAT_EXTENTION_VALID | RSI_CUSTOM_FEATURE_BIT_MAP),
		.ext_custom_feature_bit_map = ((RSI_EXT_CUSTOM_FEATURE_BIT_MAP) |
					       (SL_SI91X_EXT_FEAT_BT_CUSTOM_FEAT_ENABLE)),
		.bt_feature_bit_map = (RSI_BT_FEATURE_BITMAP),
		.ext_tcp_ip_feature_bit_map =
			(RSI_EXT_TCPIP_FEATURE_BITMAP | SL_SI91X_CONFIG_FEAT_EXTENTION_VALID),
		.ble_feature_bit_map =
			((SL_SI91X_BLE_MAX_NBR_PERIPHERALS(RSI_BLE_MAX_NBR_PERIPHERALS) |
			  SL_SI91X_BLE_MAX_NBR_CENTRALS(RSI_BLE_MAX_NBR_CENTRALS) |
			  SL_SI91X_BLE_MAX_NBR_ATT_SERV(RSI_BLE_MAX_NBR_ATT_SERV) |
			  SL_SI91X_BLE_MAX_NBR_ATT_REC(RSI_BLE_MAX_NBR_ATT_REC)) |
			 SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID |
			 SL_SI91X_BLE_PWR_INX(RSI_BLE_PWR_INX) |
			 SL_SI91X_BLE_PWR_SAVE_OPTIONS(RSI_BLE_PWR_SAVE_OPTIONS) |
			 SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE),
		.ble_ext_feature_bit_map = ((SL_SI91X_BLE_NUM_CONN_EVENTS(RSI_BLE_NUM_CONN_EVENTS) |
					     SL_SI91X_BLE_NUM_REC_BYTES(RSI_BLE_NUM_REC_BYTES))),
		.config_feature_bit_map =
			(SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | RSI_CONFIG_FEATURE_BITMAP)}};

#if defined(CONFIG_BT_BREDR)
#error "siwg917 bt hci driver currently doesn't support CONFIG_BT_BREDR"
/* #define LMP_FEAT_PAGES_COUNT	3 */
#else
#define LMP_FEAT_PAGES_COUNT	1
#endif
#define BT_FEAT_SET(feat, page, octet, bit)		feat[page][octet] |=  BIT(bit)
#define BT_FEAT_SET_LE(feat)				BT_FEAT_SET(feat, 0, 4, 6)
#define BT_FEAT_SET_BREDR(feat)				BT_FEAT_SET(feat, 0, 4, 5)

#define BT_CMD_SET(commands, octet, bit)		commands[octet] |=  BIT(bit)
#define BT_CMD_LE_Rand(commands)			BT_CMD_SET(commands, 27, 7)

#define BT_LE_FEAT_SET(feat, bit)			feat[(bit) >> 3] |= BIT((bit) & 7)

struct bt_siwg917_data {
	uint8_t	features[LMP_FEAT_PAGES_COUNT][8];
	uint8_t le_features[8];
	uint8_t	commands[64];
	uint8_t states[8];
	rsi_ble_req_adv_t *ble_adv_params;
	rsi_ble_req_scan_t *ble_scan_params;
} __packed;

struct bt_siwg917_cb {
	rsi_ble_on_adv_report_event_t ble_on_adv_report_event;
	rsi_ble_on_connect_t ble_on_conn_status_event;
	rsi_ble_on_disconnect_t ble_on_disconnect_event;
	rsi_ble_on_le_ping_payload_timeout_t ble_on_le_ping_time_expired_event;
	rsi_ble_on_phy_update_complete_t ble_on_phy_update_complete_event;
	rsi_ble_on_data_length_update_t ble_on_data_length_update_event;
	rsi_ble_on_enhance_connect_t ble_on_enhance_conn_status_event;
	rsi_ble_on_directed_adv_report_event_t ble_on_directed_adv_report_event;
	rsi_ble_on_conn_update_complete_t ble_on_conn_update_complete_event;
	rsi_ble_on_remote_conn_params_request_t ble_on_remote_conn_params_request_event;
	rsi_ble_on_smp_request_t ble_on_smp_request_event;
	rsi_ble_on_smp_response_t ble_on_smp_response_event;
	rsi_ble_on_smp_passkey_t ble_on_smp_passkey_event;
	rsi_ble_on_smp_failed_t ble_on_smp_failed_event;
	rsi_ble_on_encrypt_started_t ble_on_smp_encryptrd;
	rsi_ble_on_smp_passkey_display_t ble_on_smp_passkey_display_event;
	rsi_ble_on_sc_passkey_t ble_sc_passkey_event;
	rsi_ble_on_le_ltk_req_event_t ble_on_le_ltk_req_event;
	rsi_ble_on_le_security_keys_t ble_on_le_security_keys_event;
	rsi_ble_on_smp_response_t ble_on_cli_smp_response_event;
	rsi_ble_on_sc_method_t ble_on_sc_method_event;
	rsi_ble_on_remote_features_t ble_on_remote_features_event;
	rsi_ble_on_le_more_data_req_t ble_on_le_more_data_req_event;
	rsi_ble_on_remote_device_info_t ble_on_remote_device_info;
};

static struct bt_siwg917_data data;
static struct bt_siwg917_cb cb;


static void bt_siwg917_send_response(uint8_t type,
				     uint8_t error,
				     struct bt_hci_evt_cmd_complete *evt,
				     uint8_t *params,
				     size_t len)
{
	struct net_buf *buf_recv = NULL;

	buf_recv = bt_buf_get_evt(type, 0, K_NO_WAIT);
	if (!buf_recv) {
		LOG_ERR("Failed to allocate the buffer for RX.");
		return;
	}
	if (params) {
		if (len == 0) {
			LOG_ERR("Size of parameters is 0, but parameters are set");
			return;
		}
		net_buf_push_mem(buf_recv, params, len);
	}
	net_buf_push_u8(buf_recv, error);
	if (evt) {
		net_buf_push_mem(buf_recv, evt, sizeof(*evt));
	}
	net_buf_push_u8(buf_recv, len);
	net_buf_push_u8(buf_recv, type);
	bt_recv(buf_recv);
}

static uint8_t bt_siwg917_status_to_bt_error_code(sl_status_t status)
{
	return (status == RSI_ERROR_NONE) ? BT_HCI_ERR_SUCCESS : BT_HCI_ERR_HW_FAILURE;
}

static void rsi_ble_on_adv_report_event(rsi_ble_event_adv_report_t *rsi_ble_event_adv)
{
	struct net_buf *buf_recv = NULL;
	uint8_t evt_type = 0;
	bt_addr_le_t addr;

	buf_recv = bt_buf_get_evt(BT_HCI_EVT_LE_META_EVENT, 0, K_NO_WAIT);
	if (!buf_recv) {
		LOG_ERR("Failed to allocate the buffer for RX.");
		return;
	}

	net_buf_add_u8(buf_recv, BT_HCI_EVT_LE_META_EVENT /*event type*/);
	net_buf_add_u8(buf_recv, 0 /*status*/);
	net_buf_add_u8(buf_recv, BT_HCI_EVT_LE_ADVERTISING_REPORT /*subevent type*/);
	net_buf_add_u8(buf_recv, 1 /*num_reports*/);

	switch (rsi_ble_event_adv->report_type) {
	case 0x0:
		evt_type |= BT_HCI_LE_ADV_EVT_TYPE_CONN;
		evt_type |= BT_HCI_LE_ADV_EVT_TYPE_SCAN;
		break;
	case 0x1:
		evt_type |= BT_HCI_LE_ADV_EVT_TYPE_DIRECT;
		break;
	case 0x2:
		evt_type |= BT_HCI_LE_ADV_EVT_TYPE_SCAN_RSP;
		break;
	case 0x3:
		evt_type |= BT_HCI_LE_ADV_EVT_TYPE_SCAN_RSP;
		break;
	case 0x4:
		evt_type |= BT_HCI_LE_ADV_EVT_TYPE_SCAN_RSP;
		break;
	default:
		LOG_WRN("Unhandled case in adv report event, using default: %d", evt_type);
		break;
	}
	net_buf_add_u8(buf_recv, evt_type);
	addr.type = rsi_ble_event_adv->dev_addr_type;
	memcpy(addr.a.val, rsi_ble_event_adv->dev_addr,
			sizeof(uint8_t) * BT_ADDR_SIZE);
	net_buf_add_mem(buf_recv, &addr, sizeof(addr));
	net_buf_add_u8(buf_recv, rsi_ble_event_adv->adv_data_len - 1);
	net_buf_add_mem(buf_recv, rsi_ble_event_adv->adv_data,
			sizeof(uint8_t) * rsi_ble_event_adv->adv_data_len);

	bt_recv(buf_recv);
}

static void bt_siwg917_update_callbacks(void)
{
	rsi_ble_gap_register_callbacks(
		cb.ble_on_adv_report_event,
		cb.ble_on_conn_status_event,
		cb.ble_on_disconnect_event,
		cb.ble_on_le_ping_time_expired_event,
		cb.ble_on_phy_update_complete_event,
		cb.ble_on_data_length_update_event,
		cb.ble_on_enhance_conn_status_event,
		cb.ble_on_directed_adv_report_event,
		cb.ble_on_conn_update_complete_event,
		cb.ble_on_remote_conn_params_request_event);
	rsi_ble_gap_extended_register_callbacks(
		cb.ble_on_remote_features_event,
		cb.ble_on_le_more_data_req_event);
	rsi_ble_smp_register_callbacks(
		cb.ble_on_smp_request_event,
		cb.ble_on_smp_response_event,
		cb.ble_on_smp_passkey_event,
		cb.ble_on_smp_failed_event,
		cb.ble_on_smp_encryptrd,
		cb.ble_on_smp_passkey_display_event,
		cb.ble_sc_passkey_event,
		cb.ble_on_le_ltk_req_event,
		cb.ble_on_le_security_keys_event,
		cb.ble_on_cli_smp_response_event,
		cb.ble_on_sc_method_event);
	rsi_ble_enhanced_gap_extended_register_callbacks(RSI_BLE_ON_REMOTE_DEVICE_INFORMATION,
			(void (*)(uint16_t, uint8_t *))cb.ble_on_remote_device_info);
}

static void bt_siwg917_send_local_features(struct bt_hci_evt_cmd_complete *evt)
{
	/* features are set on driver initialization */
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			(uint8_t *)data.features,
			sizeof(data.features));
}

static void bt_siwg917_send_local_versions(struct bt_hci_evt_cmd_complete *evt)
{
	struct {
		uint8_t  hci_version;
		uint16_t hci_revision;
		uint8_t  lmp_version;
		uint16_t manufacturer;
		uint16_t lmp_subversion;
	} __packed local_version_info;

	/* version 4.0 */
	local_version_info.hci_version = 0x6;
	local_version_info.hci_revision = 0x0;
	/* version 5.2 */
	local_version_info.lmp_version = 0xB;
	local_version_info.manufacturer = 0x02FF;
	local_version_info.lmp_subversion = 0x0;
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			(uint8_t *)&local_version_info,
			sizeof(local_version_info));
}

static void bt_siwg917_send_supported_commands(struct bt_hci_evt_cmd_complete *evt)
{
	/* supported commands are set on driver initialization */
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			data.commands,
			sizeof(data.commands));
}

static void bt_siwg917_send_rand(struct bt_hci_evt_cmd_complete *evt)
{
	uint32_t result[2];

	RSI_RNG_Start(HWRNG, RSI_RNG_TRUE_RANDOM);
	RSI_RNG_GetBytes(HWRNG, result, 2);
	RSI_RNG_Stop(HWRNG);
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			(uint8_t *)result,
			8);
}

static void bt_siwg917_send_le_supported_features(struct bt_hci_evt_cmd_complete *evt)
{
	/* le supported features are set on driver initialization */
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			data.le_features,
			sizeof(data.le_features));
}

static void bt_siwg917_send_le_supported_states(struct bt_hci_evt_cmd_complete *evt)
{
	/* le supported states are set on driver initialization */
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			data.states,
			8);
}

static void bt_siwg917_le_set_event_mask(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	uint64_t mask = *buf;

	if (mask & BT_EVT_MASK_LE_CONN_COMPLETE) {
		LOG_WRN("LE CONN COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_ADVERTISING_REPORT) {
		cb.ble_on_adv_report_event = rsi_ble_on_adv_report_event;
	}
	if (mask & BT_EVT_MASK_LE_CONN_UPDATE_COMPLETE) {
		LOG_WRN("LE CONN UPDATE COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_REMOTE_FEAT_COMPLETE) {
		LOG_WRN("LE REMOTE FEAT COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_LTK_REQUEST) {
		LOG_WRN("LE LTK REQUEST event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_CONN_PARAM_REQ) {
		LOG_WRN("LE CONN PARAM event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_DATA_LEN_CHANGE) {
		LOG_WRN("LE DATA LEN CHANGE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_P256_PUBLIC_KEY_COMPLETE) {
		LOG_WRN("LE P256 PUBLIC KEY COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_GENERATE_DHKEY_COMPLETE) {
		LOG_WRN("LE GENERATE DHKEY COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_ENH_CONN_COMPLETE) {
		LOG_WRN("LE GENERATE DHKEY COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_ENH_CONN_COMPLETE) {
		LOG_WRN("LE ENH CONN event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_DIRECT_ADV_REPORT) {
		LOG_WRN("LE DIRECT ADV REPORT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PHY_UPDATE_COMPLETE) {
		LOG_WRN("LE PHY UPDATE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_EXT_ADVERTISING_REPORT) {
		LOG_WRN("LE EXT ADVERTISING REPORT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PER_ADV_SYNC_ESTABLISHED) {
		LOG_WRN("LE PER ADV SYNC ESTABLISHED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PER_ADVERTISING_REPORT) {
		LOG_WRN("LE PER ADVERTISING REPORT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PER_ADV_SYNC_LOST) {
		LOG_WRN("LE PER ADV SYNC LOST event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_SCAN_TIMEOUT) {
		LOG_WRN("LE SCAN TIMEOUT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_ADV_SET_TERMINATED) {
		LOG_WRN("LE ADV SET TERMINATED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_SCAN_REQ_RECEIVED) {
		LOG_WRN("LE SCAN REQ RECEIVED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_CHAN_SEL_ALGO) {
		LOG_WRN("LE CHAN SEL ALGO event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_CONNECTIONLESS_IQ_REPORT) {
		LOG_WRN("LE CONNECTIONLESS IQ REPORT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_CONNECTION_IQ_REPORT) {
		LOG_WRN("LE CONNECTION IQ REPORT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_CTE_REQUEST_FAILED) {
		LOG_WRN("LE CTE REQUEST FAILED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PAST_RECEIVED) {
		LOG_WRN("LE PAST RECEIEVED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_CIS_ESTABLISHED) {
		LOG_WRN("LE CIS ESTABLISHED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_CIS_REQ) {
		LOG_WRN("LE CIS REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_BIG_COMPLETE) {
		LOG_WRN("LE BIG COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_BIG_TERMINATED) {
		LOG_WRN("LE BIG TERMINATED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_BIG_SYNC_ESTABLISHED) {
		LOG_WRN("LE BIG SYNC ESTABLISHED event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_BIG_SYNC_LOST) {
		LOG_WRN("LE BIG SYNC LOST event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_REQ_PEER_SCA_COMPLETE) {
		LOG_WRN("LE REQ PEER SCA COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PATH_LOSS_THRESHOLD) {
		LOG_WRN("LE PATH LOSS THRESHOLD event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_TRANSMIT_POWER_REPORTING) {
		LOG_WRN("LE TRANSMIT POWER REPORTING event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_BIGINFO_ADV_REPORT) {
		LOG_WRN("LE BIGINFO ADV REPORT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PER_ADV_SYNC_ESTABLISHED_V2) {
		LOG_WRN("LE PER ADV SYNC ESTABLISED V2 event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PER_ADVERTISING_REPORT_V2) {
		LOG_WRN("LE PER ADVERTASING REPORT V2 event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PAST_RECEIVED_V2) {
		LOG_WRN("LE PAST RECEIEVED V2 event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PER_ADV_SUBEVENT_DATA_REQ) {
		LOG_WRN("LE PER ADV SUBEVENT DATA REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_PER_ADV_RESPONSE_REPORT) {
		LOG_WRN("LE PER ADV RESPONSE REPORT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_ENH_CONN_COMPLETE_V2) {
		LOG_WRN("LE PER ENH CONN COMPLETE V2 event mask is unsupported, ignoring.");
	}

	bt_siwg917_update_callbacks();

	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			NULL,
			0);
}

static void bt_siwg917_set_event_mask(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	uint64_t mask = *buf;

	if (mask & BT_EVT_MASK_INQUIRY_COMPLETE) {
		LOG_WRN("MASK INQUIRY COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_CONN_COMPLETE) {
		LOG_WRN("CONN STATUS event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_CONN_REQUEST) {
		LOG_WRN("MASK CONN REQUEST event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_DISCONN_COMPLETE) {
		LOG_WRN("DISCONN COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_AUTH_COMPLETE) {
		LOG_WRN("MASK AUTH COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_REMOTE_NAME_REQ_COMPLETE) {
		LOG_WRN("MASK REMOTE NAME REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_ENCRYPT_CHANGE) {
		LOG_WRN("MASK ENCRYPT CHANGE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_REMOTE_FEATURES) {
		LOG_WRN("REMOTE FEATURES event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_REMOTE_VERSION_INFO) {
		LOG_WRN("REMOTE VERSION INFO event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_HARDWARE_ERROR) {
		LOG_WRN("MASK HARDWARE ERROR event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_ROLE_CHANGE) {
		LOG_WRN("MASK ROLE CHANGE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_PIN_CODE_REQ) {
		LOG_WRN("MASK PIN CODE REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LINK_KEY_REQ) {
		LOG_WRN("MASK LINK KEY REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LINK_KEY_NOTIFY) {
		LOG_WRN("MASK LINK KEY NOTIFY event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_DATA_BUFFER_OVERFLOW) {
		LOG_WRN("MASK DATA BUFFER OVERFLOW event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_INQUIRY_RESULT_WITH_RSSI) {
		LOG_WRN("MASK INQUIRY RESULT WITH RSSI event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_REMOTE_EXT_FEATURES) {
		LOG_WRN("MASK REMOTE EXT FEATURES event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_SYNC_CONN_COMPLETE) {
		LOG_WRN("MASK SYNC CONN COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_EXTENDED_INQUIRY_RESULT) {
		LOG_WRN("MASK EXTENDED INQUIRY RESULT event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_ENCRYPT_KEY_REFRESH_COMPLETE) {
		LOG_WRN("MASK ENCRYPT KEY REFRESH COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_IO_CAPA_REQ) {
		LOG_WRN("MASK IO CAPA REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_IO_CAPA_RESP) {
		LOG_WRN("MASK IO CAPA RESP event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_USER_CONFIRM_REQ) {
		LOG_WRN("MASK USER CONFIRM REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_USER_PASSKEY_REQ) {
		LOG_WRN("MASK USER PASSKEY REQ event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_SSP_COMPLETE) {
		LOG_WRN("MASK SSP COMPLETE event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_USER_PASSKEY_NOTIFY) {
		LOG_WRN("MASK USER PASSKEY NOTIFY event mask is unsupported, ignoring.");
	}
	if (mask & BT_EVT_MASK_LE_META_EVENT) {
		LOG_WRN("MASK LE META EVENT event mask is unsupported, ignoring.");
	}

	bt_siwg917_update_callbacks();
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			NULL,
			0);
}
static void bt_siwg917_get_local_device_address(struct bt_hci_evt_cmd_complete *evt)
{
	uint8_t result[6];
	sl_status_t status;

	status = rsi_bt_get_local_device_address((uint8_t *)&result);
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			bt_siwg917_status_to_bt_error_code(status),
			evt,
			result,
			sizeof(uint8_t) * 6);
}

static void bt_siwg917_set_advertising_parameters(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	struct bt_hci_cp_le_set_adv_param *set_param = (struct bt_hci_cp_le_set_adv_param *) buf;
	uint8_t adv_type = UNDIR_NON_CONN;
	double x0 = (double)(set_param->min_interval - BT_LE_ADV_INTERVAL_MIN)
		/ (BT_LE_ADV_INTERVAL_MAX - BT_LE_ADV_INTERVAL_MIN);
	double x1 = (double)(set_param->max_interval - BT_LE_ADV_INTERVAL_MIN)
		/ (BT_LE_ADV_INTERVAL_MAX - BT_LE_ADV_INTERVAL_MIN);

	if (data.ble_adv_params == NULL) {
		data.ble_adv_params = k_malloc(sizeof(rsi_ble_req_adv_t));
	}
	memset(data.ble_adv_params, 0, sizeof(rsi_ble_req_adv_t));

	data.ble_adv_params->adv_int_min = ((RSI_BLE_ADV_INT_MAX - RSI_BLE_ADV_INT_MIN) * x0)
		+ RSI_BLE_ADV_INT_MIN;
	data.ble_adv_params->adv_int_max = ((RSI_BLE_ADV_INT_MAX - RSI_BLE_ADV_INT_MIN) * x1)
		+ RSI_BLE_ADV_INT_MIN;
	switch (set_param->type) {
	case BT_HCI_ADV_IND:
		adv_type = UNDIR_CONN;
		break;
	case BT_HCI_ADV_DIRECT_IND:
		adv_type = DIR_CONN;
		break;
	case BT_HCI_ADV_SCAN_IND:
		adv_type = UNDIR_SCAN;
		break;
	case BT_HCI_ADV_NONCONN_IND:
		adv_type = UNDIR_NON_CONN;
		break;
	case BT_HCI_ADV_DIRECT_IND_LOW_DUTY:
		adv_type = DIR_CONN_LOW_DUTY_CYCLE;
		break;
	default:
		LOG_ERR("Unhandled adv_type: %d, using default (%d)\n", set_param->type, adv_type);
		break;
	}
	data.ble_adv_params->adv_type = adv_type;
	data.ble_adv_params->own_addr_type = set_param->own_addr_type;
	data.ble_adv_params->direct_addr_type = set_param->direct_addr.type;
	memcpy(data.ble_adv_params->direct_addr, set_param->direct_addr.a.val,
			sizeof(uint8_t) * BT_ADDR_SIZE);
	data.ble_adv_params->adv_channel_map = set_param->channel_map;
	data.ble_adv_params->filter_type = set_param->filter_policy;
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			BT_HCI_ERR_SUCCESS,
			evt,
			NULL,
			0);
}

static void bt_siwg917_set_advertising_data(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	sl_status_t status;
	struct bt_hci_cp_le_set_adv_data *set_data = (struct bt_hci_cp_le_set_adv_data *)buf;

	status = rsi_ble_set_advertise_data(set_data->data, set_data->len);
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			bt_siwg917_status_to_bt_error_code(status),
			evt,
			NULL,
			0);
}

static void bt_siwg917_set_scan_response_data(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	sl_status_t status;
	struct bt_hci_cp_le_set_adv_data *set_data = (struct bt_hci_cp_le_set_adv_data *)buf;

	status = rsi_ble_set_scan_response_data(set_data->data, set_data->len);
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			bt_siwg917_status_to_bt_error_code(status),
			evt,
			NULL,
			0);
}

static void bt_siwg917_le_start_advertising(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	sl_status_t status;
	uint8_t enable = *buf;

	if (!enable) {
		status = rsi_ble_stop_advertising();
	} else {
		if (data.ble_adv_params != NULL) {
			status = rsi_ble_start_advertising_with_values(data.ble_adv_params);
		} else {
			status = rsi_ble_start_advertising();
		}
	}
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			bt_siwg917_status_to_bt_error_code(status),
			evt,
			NULL,
			0);
}

static void bt_siwg917_le_read_buffer_size(struct bt_hci_evt_cmd_complete *evt)
{
	struct {
		uint16_t le_max_len;
		uint8_t le_max_num;
	} __packed result;
	sl_status_t status;
	rsi_ble_read_max_data_length_t blereaddatalen;

	status = rsi_ble_read_max_data_len(&blereaddatalen);
	result.le_max_len = blereaddatalen.maxrxoctets;
	result.le_max_num = 1;
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			bt_siwg917_status_to_bt_error_code(status),
			evt,
			(uint8_t *)&result,
			sizeof(result));
}

static void bt_siwg917_le_set_random_address(struct bt_hci_evt_cmd_complete *evt)
{
	sl_status_t status;

	status = rsi_ble_set_random_address();
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			bt_siwg917_status_to_bt_error_code(status),
			evt,
			NULL,
			0);
}

static void bt_siwg917_le_set_scan_parameters(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	struct bt_hci_cp_le_set_scan_param *set_param = (struct bt_hci_cp_le_set_scan_param *)buf;

	if (data.ble_scan_params == NULL) {
		data.ble_scan_params = malloc(sizeof(rsi_ble_req_scan_t));
	}
	memset(data.ble_scan_params, 0, sizeof(rsi_ble_req_scan_t));
	data.ble_scan_params->scan_type = set_param->scan_type;
	data.ble_scan_params->filter_type =
		set_param->filter_policy == BT_HCI_LE_SCAN_FP_BASIC_NO_FILTER ? 0 : 1;
	data.ble_scan_params->own_addr_type = set_param->addr_type;
	data.ble_scan_params->scan_int = set_param->interval;
	data.ble_scan_params->scan_win = set_param->window;

	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE, 0, evt, NULL, 0);
}

static void bt_siwg917_le_set_scan_enable(struct bt_hci_evt_cmd_complete *evt, uint8_t *buf)
{
	struct bt_hci_cp_le_set_scan_enable *cp = (struct bt_hci_cp_le_set_scan_enable *)buf;
	sl_status_t status;

	if (cp->filter_dup) {
		LOG_WRN("siwg917_hci driver currently doesn't support "
				 "filtering duplicates on scanning, ignoring it.");
	}
	if (!cp->enable) {
		status = rsi_ble_stop_scanning();
	} else {
		if (data.ble_scan_params) {
			status = rsi_ble_start_scanning_with_values(data.ble_scan_params);
		} else {
			status = rsi_ble_start_scanning();
		}
	}
	bt_siwg917_send_response(BT_HCI_EVT_CMD_COMPLETE,
			bt_siwg917_status_to_bt_error_code(status),
			evt,
			NULL,
			0);
}

/* SiWG917 HAL doesn't implement HCI API. Instead it implements SAPI (Simple API).
 * This function translates HCI API opcodes into SAPI calls and encodes SAPI responses
 * in HCI format.
 */
static int bt_siwg917_handle_cmd_opcodes(struct net_buf *buf)
{
	int rv = 0;
	struct bt_hci_cmd_hdr *hdr = (struct bt_hci_cmd_hdr *)buf->data;
	uint8_t *data_buf = buf->data + BT_HCI_CMD_HDR_SIZE;
	struct bt_hci_evt_cmd_complete evt = {.ncmd = 1, .opcode = hdr->opcode};

	switch (hdr->opcode) {
	case BT_HCI_OP_READ_LOCAL_FEATURES:
		bt_siwg917_send_local_features(&evt);
		break;
	case BT_HCI_OP_READ_SUPPORTED_COMMANDS:
		bt_siwg917_send_supported_commands(&evt);
		break;
	case BT_HCI_OP_READ_LOCAL_VERSION_INFO:
		bt_siwg917_send_local_versions(&evt);
		break;
	case BT_HCI_OP_LE_RAND:
		bt_siwg917_send_rand(&evt);
		break;
	case BT_HCI_OP_LE_READ_LOCAL_FEATURES:
		bt_siwg917_send_le_supported_features(&evt);
		break;
	case BT_HCI_OP_LE_READ_SUPP_STATES:
		bt_siwg917_send_le_supported_states(&evt);
		break;
	case BT_HCI_OP_LE_SET_EVENT_MASK:
		bt_siwg917_le_set_event_mask(&evt, data_buf);
		break;
	case BT_HCI_OP_SET_EVENT_MASK:
		bt_siwg917_set_event_mask(&evt, data_buf);
		break;
	case BT_HCI_OP_READ_BD_ADDR:
		bt_siwg917_get_local_device_address(&evt);
		break;
	case BT_HCI_OP_LE_SET_ADV_PARAM:
		bt_siwg917_set_advertising_parameters(&evt, data_buf);
		break;
	case BT_HCI_OP_LE_SET_ADV_DATA:
		bt_siwg917_set_advertising_data(&evt, data_buf);
		break;
	case BT_HCI_OP_LE_SET_SCAN_RSP_DATA:
		bt_siwg917_set_scan_response_data(&evt, data_buf);
		break;
	case BT_HCI_OP_LE_SET_ADV_ENABLE:
		bt_siwg917_le_start_advertising(&evt, data_buf);
		break;
	case BT_HCI_OP_LE_READ_BUFFER_SIZE:
		bt_siwg917_le_read_buffer_size(&evt);
		break;
	case BT_HCI_OP_LE_SET_RANDOM_ADDRESS:
		bt_siwg917_le_set_random_address(&evt);
		break;
	case BT_HCI_OP_LE_SET_SCAN_PARAM:
		bt_siwg917_le_set_scan_parameters(&evt, data_buf);
		break;
	case BT_HCI_OP_LE_SET_SCAN_ENABLE:
		bt_siwg917_le_set_scan_enable(&evt, data_buf);
		break;
	default:
		LOG_INF("unhandled HAL opcode: 0x%x\n", hdr->opcode);
		rv = -ENOTSUP;
		break;
	}
	return rv;
}

static int bt_siwg917_send(struct net_buf *buf)
{
	int rv = 0;

	switch (bt_buf_get_type(buf)) {
	case BT_BUF_ACL_OUT:
		rv = -ENOTSUP;
		break;
	case BT_BUF_CMD:
		rv = bt_siwg917_handle_cmd_opcodes(buf);
		break;
	default:
		rv = -EINVAL;
		break;
	}
	net_buf_unref(buf);
	return rv;
}

static int bt_siwg917_open(void)
{
	return 0;
}

static const struct bt_hci_driver drv = {.name = "siwg917:bt",
					 .bus = BT_HCI_DRIVER_BUS_VIRTUAL,
					 .open = bt_siwg917_open,
					 .send = bt_siwg917_send,
					 .quirks = BT_QUIRK_NO_RESET};

static int bt_siwg917_init(void)
{
	int ret;

	/*
	 * Wiseconnect SDK uses the same function to initialize WiFi and Bluetooth
	 */
	ret = sl_wifi_init(&config, NULL);
	if (ret) {
		LOG_ERR("Failed to init bt_siwg917, err: %d", ret);
		return ret;
	}

	memset(&data, 0, sizeof(data));

	BT_FEAT_SET_LE(data.features);
	BT_FEAT_SET_BREDR(data.features);

	BT_CMD_LE_Rand(data.commands);

	ret = bt_hci_driver_register(&drv);
	if (ret) {
		LOG_ERR("Failed to register SiWG917 BT HCI, err: %d", ret);
		return ret;
	}

	return 0;
}

/*
 * Connect M4 packet pending interrupt to TA
 */
extern void IRQ074_Handler(void);
Z_ISR_DECLARE(74, ISR_FLAG_DIRECT, IRQ074_Handler, 0);

SYS_INIT(bt_siwg917_init, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
