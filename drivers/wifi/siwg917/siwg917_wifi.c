/*
 * Copyright (c) 2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#define LOG_LEVEL CONFIG_WIFI_LOG_LEVEL
LOG_MODULE_REGISTER(wifi_siwg917);

#define DT_DRV_COMPAT silabs_siwg917_wifi

#include <zephyr/device.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_offload.h>

#include "sl_net.h"
#include "sl_wifi.h"
#include "sl_wifi_callback_framework.h"
#include "sl_utility.h"
#include "sl_net_wifi_types.h"
#include "sl_net_si91x.h"

int sli_si91x_shutdown(int socket, int how);
int sl_si91x_recvfrom(int socket, uint8_t *buffer, size_t buffersize, int32_t flags,
		      struct sockaddr *fromAddr, socklen_t *fromAddrLen);
int sl_si91x_send(int socket, const uint8_t *buffer, size_t buffer_length, int32_t flags);

int sl_si91x_sendto(int socket, uint8_t *buffer, size_t buffer_length, int32_t flags,
		    const struct sockaddr *addr, socklen_t addr_len);

int sl_si91x_socket(int family, int type, int protocol);
int sl_si91x_bind(int socket, const struct sockaddr *addr, socklen_t addr_len);
int sl_si91x_connect(int socket, const struct sockaddr *addr, socklen_t addr_len);

int sl_si91x_socket_set_recv_timeout(int socket, int32_t timeout);
int sl_si91x_socket_set_trans_callback(int socket, void *callback);
int sl_si91x_socket_set_recv_callback(int socket, void *callback);

struct siwg917_wifi_status {
	char ssid[WIFI_SSID_MAX_LEN + 1];
	char pass[WIFI_PSK_MAX_LEN + 1];
	int state;
	sl_wifi_security_t security;
	uint8_t channel;
	int rssi;
};

struct socket_data {
	struct net_context *context;
	struct net_pkt *rx_pkt;
	struct net_buf *pkt_buf;
};

struct siwg917_wifi_runtime {
	struct socket_data socket_data[CONFIG_WIFI_SIWG91_OFFLOAD_MAX_SOCKETS];
	uint8_t mac_addr[6];
	uint8_t frame_buf[NET_ETH_MAX_FRAME_SIZE];
#if defined(CONFIG_NET_STATISTICS_WIFI)
	struct net_stats_wifi stats;
#endif
	struct siwg917_wifi_status status;
	scan_result_cb_t scan_cb;
};

static struct siwg917_wifi_runtime siwg917_data;
static struct net_if *siwg917_wifi_iface;

NET_BUF_POOL_DEFINE(siwg917_tx_pool, 10, CONFIG_WIFI_SIWG917_MAX_PACKET_SIZE, 0, NULL);
NET_BUF_POOL_DEFINE(siwg917_rx_pool, 10, CONFIG_WIFI_SIWG917_MAX_PACKET_SIZE, 0, NULL);

#ifdef CONFIG_SIWG917_CLIENT_MODE
static void scan_callback_handler(sl_wifi_event_t event, sl_wifi_scan_result_t *result,
				  uint32_t result_length, void *arg)
{
	struct wifi_scan_result res = {0};
	siwg917_data.status.state = WIFI_STATE_SCANNING;

	for (int i = 0; i < result->scan_count; i++) {
		memset(&res, 0, sizeof(struct wifi_scan_result));
		res.ssid_length = strlen(result->scan_info[i].ssid);
		memcpy(res.ssid, result->scan_info[i].ssid, res.ssid_length);
		res.channel = result->scan_info[i].rf_channel;
		res.mac_length = sizeof(result->scan_info[i].bssid);
		memcpy(res.mac, result->scan_info[i].bssid, res.mac_length);
		res.rssi = result->scan_info[i].rssi_val;
		switch (result->scan_info[i].security_mode) {
		case SL_WIFI_OPEN:
			break;
		case SL_WIFI_WPA:
			res.security = WIFI_SECURITY_TYPE_WPA_PSK;
			break;
		case SL_WIFI_WPA2:
			res.security = WIFI_SECURITY_TYPE_PSK;
			break;
		case SL_WIFI_WPA3:
		case SL_WIFI_WPA3_TRANSITION:
			res.security = WIFI_SECURITY_TYPE_SAE;
			break;
		case SL_WIFI_WEP:
			res.security = WIFI_SECURITY_TYPE_WEP;
			break;
		case SL_WIFI_WPA_ENTERPRISE:
		case SL_WIFI_WPA2_ENTERPRISE:
			res.security = WIFI_SECURITY_TYPE_EAP;
			break;
		default:
			res.security = WIFI_SECURITY_TYPE_UNKNOWN;
			break;
		}
		siwg917_data.scan_cb(siwg917_wifi_iface, 0, &res);
	}

	siwg917_data.scan_cb(siwg917_wifi_iface, 0, NULL);

	siwg917_data.scan_cb = NULL;
}

static int siwg917_wifi_disconnect(const struct device *dev)
{
	if (siwg917_data.status.state == WIFI_STATE_DISCONNECTED) {
		return -EALREADY;
	}
	siwg917_data.status.state = WIFI_STATE_DISCONNECTED;

	wifi_mgmt_raise_disconnect_result_event(siwg917_wifi_iface, 0);

	int ret = sl_wifi_disconnect(SL_WIFI_CLIENT_INTERFACE);

	return ret;
}

static sl_status_t join_callback_handler(sl_wifi_event_t event, char *result,
					 uint32_t result_length, void *arg)
{
	UNUSED_PARAMETER(arg);
	if (CHECK_IF_EVENT_FAILED(event)) {
		return -EINVAL;
	}

	siwg917_data.status.state = WIFI_STATE_COMPLETED;
	wifi_mgmt_raise_connect_result_event(siwg917_wifi_iface, 0);

	sl_net_ip_configuration_t ip = {
		.mode = SL_IP_MANAGEMENT_DHCP,
		.type = SL_IPV4,
		.host_name = NULL,
		.ip = {{{0}}},
	};

	int status = sl_si91x_configure_ip_address(&ip, 0);

	if (status) {
		return status;
	}

	struct in_addr addr;

	for (int i = 0U; i < 4; i++) {
		addr.s4_addr[i] = ip.ip.v4.ip_address.bytes[i];
	}

	net_if_ipv4_addr_add(siwg917_wifi_iface, &addr, NET_ADDR_DHCP, 0);

	return 0;
}

static int siwg917_wifi_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	struct siwg917_wifi_runtime *data = dev->data;
	sl_status_t status = 0;
	sl_wifi_credential_id_t id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
	sl_wifi_client_configuration_t ap = {0};
	sl_net_wifi_client_profile_t profile;

	memcpy(ap.ssid.value, params->ssid, params->ssid_length);
	ap.ssid.length = params->ssid_length;

	memcpy(data->status.ssid, params->ssid, params->ssid_length);
	data->status.ssid[params->ssid_length] = '\0';

	sl_wifi_set_callback(SL_WIFI_JOIN_EVENTS,
			     (sl_wifi_callback_function_t)join_callback_handler, NULL);

	status = sl_net_set_credential(id, SL_NET_WIFI_PSK, params->psk, params->psk_length);

	memcpy(data->status.pass, params->psk, params->psk_length);
	data->status.pass[params->psk_length] = '\0';

	data->status.security = SL_WIFI_WPA2;

	ap.security = SL_WIFI_WPA2;
	ap.encryption = SL_WIFI_CCMP_ENCRYPTION;
	ap.credential_id = id;

	if (params->channel == WIFI_CHANNEL_ANY) {
		ap.channel.channel = 0U;
		data->status.channel = 0U;
	} else {
		ap.channel.channel = params->channel;
		data->status.channel = params->channel;
	}

	sl_net_ip_configuration_t ip = {
		.mode = SL_IP_MANAGEMENT_DHCP,
		.type = SL_IPV4,
		.host_name = NULL,
		.ip = {{{0}}},
	};

	profile.config = ap;
	profile.ip = ip;
	status = sl_net_set_profile(SL_NET_WIFI_CLIENT_INTERFACE,
				    SL_NET_DEFAULT_WIFI_CLIENT_PROFILE_ID, &profile);

	status = sl_wifi_connect(SL_WIFI_CLIENT_INTERFACE, &profile.config, 0);

	if (status != SL_STATUS_IN_PROGRESS) {
		return -status;
	}

	return 0;
}

static int siwg917_wifi_scan(const struct device *dev, struct wifi_scan_params *params,
			     scan_result_cb_t cb)
{
	if (siwg917_data.status.state == WIFI_STATE_COMPLETED) {
		return -ENOTSUP;
	}

	if (siwg917_data.scan_cb != NULL) {
		LOG_ERR("Scan callback in progress");
		return -EALREADY;
	}

	siwg917_data.scan_cb = cb;

	sl_wifi_scan_configuration_t wifi_scan_configuration = {0};

	wifi_scan_configuration = default_wifi_scan_configuration;

	sl_wifi_set_scan_callback((sl_wifi_scan_callback_t)scan_callback_handler, NULL);

	sl_wifi_start_scan(SL_WIFI_CLIENT_2_4GHZ_INTERFACE, NULL, &wifi_scan_configuration);

	return 0;
}
#endif

#ifdef CONFIG_SIWG917_AP_MODE
static int siwg917_wifi_ap_enable(const struct device *dev, struct wifi_connect_req_params *params)
{
	sl_wifi_ap_configuration_t config = {0};
	memcpy(config.ssid.value, params->ssid, params->ssid_length);
	config.ssid.length = params->ssid_length;
	config.security = SL_WIFI_WPA2;
	config.encryption = SL_WIFI_CCMP_ENCRYPTION;
	config.channel.channel = params->channel;
	config.rate_protocol = SL_WIFI_RATE_PROTOCOL_AUTO;
	config.options = 0;
	config.credential_id = SL_NET_DEFAULT_WIFI_AP_CREDENTIAL_ID;
	config.keepalive_type = SI91X_AP_NULL_BASED_KEEP_ALIVE;
	config.beacon_interval = 100;
	config.client_idle_timeout = 120000;
	config.dtim_beacon_count = 4;
	config.maximum_clients = 1;

	uint32_t status = sl_net_set_credential(config.credential_id, SL_NET_WIFI_PSK, params->psk,
						params->psk_length);
	if (status != SL_STATUS_OK) {
		LOG_ERR("Failed to set credentials: 0x%x", status);
		return status;
	}

	status = sl_wifi_start_ap(SL_WIFI_AP_2_4GHZ_INTERFACE, &config);
	if (status != SL_STATUS_OK) {
		LOG_ERR("Failed to bring Wi-Fi AP interface up: 0x%x", status);
		return status;
	}

	return 0;
}
#endif

static int siwg917_wifi_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct siwg917_wifi_runtime *data = dev->data;

	strncpy(status->ssid, data->status.ssid, WIFI_SSID_MAX_LEN);
	status->ssid_len = strlen(data->status.ssid);
	status->band = WIFI_FREQ_BAND_2_4_GHZ;
	status->link_mode = WIFI_LINK_MODE_UNKNOWN;
	status->mfp = WIFI_MFP_DISABLE;
	status->security = WIFI_SECURITY_TYPE_PSK;
	status->state = siwg917_data.status.state;
	status->iface_mode = WIFI_MODE_AP;

	return 0;
}

// This on is defined in HAL in the sl_si91x_socket_types.h file

void siwg917_recv_data_callback(uint32_t sock_no, uint8_t *buffer, uint32_t length)
{
	printf("Receive data on sock %d, len %d\n", sock_no, length);
}

/**
 * This function is called when the socket is to be opened.
 */
static int siwg917_get(sa_family_t family, enum net_sock_type type, enum net_ip_protocol ip_proto,
		       struct net_context **context)
{
	int sock;
	struct socket_data *sd;

	if (family != AF_INET) {
		LOG_ERR("Only AF_INET is supported!\n");
		return -1;
	}

	sock = sl_si91x_socket(2, type, ip_proto);
	sd = &siwg917_data.socket_data[sock];

	(*context)->offload_context = (void *)(intptr_t)sock;
	sd->context = *context;

	return errno;
}

/**
 * This function is called when user wants to bind to local IP address.
 */
static int siwg917_bind(struct net_context *context, const struct sockaddr *addr, socklen_t addrlen)
{
	net_sin(addr)->sin_family = 2;

	if (net_sin(addr)->sin_port == 0U) {
		return 0;
	}
	net_sin(addr)->sin_port = ntohs(net_sin(addr)->sin_port);

	int ret = sl_si91x_bind((int)context->offload_context, addr, addrlen + 8);

	if (ret < 0) {
		return errno;
	}

	return 0;
}

/**
 * This function is called when user wants to mark the socket
 * to be a listening one.
 */
static int siwg917_listen(struct net_context *context, int backlog)
{
	printf("%s\n", __func__);
	return 0;
}

/**
 * This function is called when user wants to create a connection
 * to a peer host.
 */
static int siwg917_connect(struct net_context *context, const struct sockaddr *addr,
			   socklen_t addrlen, net_context_connect_cb_t cb, int32_t timeout,
			   void *user_data)
{
	net_sin(addr)->sin_port = ntohs(net_sin(addr)->sin_port);
	net_sin(addr)->sin_family = 2;

	int ret = sl_si91x_connect((int)context->offload_context, net_sin(addr), addrlen + 8);

	return ret;
}

/**
 * This function is called when user wants to accept a connection
 * being established.
 */
static int siwg917_accept(struct net_context *context, net_tcp_accept_cb_t cb, int32_t timeout,
			  void *user_data)
{
	printf("%s\n", __func__);
	return 0;
}

/**
 * This function is called when user wants to send data to peer host.
 */

static int siwg917_send(struct net_pkt *pkt, net_context_send_cb_t cb, int32_t timeout,
			void *user_data)
{
	struct net_context *context = pkt->context;
	int sock = (int)context->offload_context;
	int ret = 0;
	struct net_buf *buf;

	sl_si91x_socket_set_trans_callback(sock, siwg917_recv_data_callback);

	buf = net_buf_alloc(&siwg917_tx_pool, K_MSEC(1000));
	if (!buf) {
		return -ENOBUFS;
	}

	if (net_pkt_read(pkt, buf->data, net_pkt_get_len(pkt))) {
		net_buf_unref(buf);
		return -ENOBUFS;
	}

	net_buf_add(buf, net_pkt_get_len(pkt));

	ret = sl_si91x_send(sock, buf->data, buf->len, 0);

	if (ret < 0) {
		return errno;
	}

	net_pkt_unref(pkt);
	net_buf_unref(buf);

	return 0;
}

/**
 * This function is called when user wants to send data to peer host.
 */
static int siwg917_sendto(struct net_pkt *pkt, const struct sockaddr *dst_addr, socklen_t addrlen,
			  net_context_send_cb_t cb, int32_t timeout, void *user_data)
{
	struct net_context *context = pkt->context;
	int sock = (int)context->offload_context;
	int ret = 0;
	struct net_buf *buf;

	sl_si91x_socket_set_trans_callback(sock, siwg917_recv_data_callback);

	buf = net_buf_alloc(&siwg917_tx_pool, K_MSEC(1000));
	if (!buf) {
		return -ENOBUFS;
	}

	if (net_pkt_read(pkt, buf->data, net_pkt_get_len(pkt))) {
		ret = -ENOBUFS;
	}

	net_buf_add(buf, net_pkt_get_len(pkt));
	net_sin(dst_addr)->sin_port = ntohs(net_sin(dst_addr)->sin_port);
	net_sin(dst_addr)->sin_family = 2;

	ret = sl_si91x_sendto(sock, buf->data, buf->len, 0, dst_addr, addrlen + 8);

	net_pkt_unref(pkt);
	net_buf_unref(buf);

	if (ret < 0) {
		return errno;
	}

	return 0;
}

/**
 * This function is called when user wants to receive data from peer
 * host.
 */
static int siwg917_recv(struct net_context *context, net_context_recv_cb_t cb, int32_t timeout,
			void *user_data)
{
	int sock = (int)context->offload_context;
	int ret;

	sl_si91x_socket_set_recv_callback(sock, siwg917_recv_data_callback);
	sl_si91x_socket_set_trans_callback(sock, siwg917_recv_data_callback);

	siwg917_data.socket_data[sock].rx_pkt =
		net_pkt_rx_alloc_on_iface(siwg917_wifi_iface, K_MSEC(100));
	if (!siwg917_data.socket_data[sock].rx_pkt) {
		LOG_ERR("Could not allocate rx packet");
		return -1;
	}

	/* Reserve a data buffer to receive the frame */
	siwg917_data.socket_data[sock].pkt_buf = net_buf_alloc(&siwg917_rx_pool, K_MSEC(100));
	if (!siwg917_data.socket_data[sock].pkt_buf) {
		LOG_ERR("Could not allocate data buffer");
		net_pkt_unref(siwg917_data.socket_data[sock].rx_pkt);
		return -1;
	}

	net_pkt_append_buffer(siwg917_data.socket_data[sock].rx_pkt,
			      siwg917_data.socket_data[sock].pkt_buf);

	ret = sl_si91x_recvfrom(sock, siwg917_data.socket_data[sock].pkt_buf->data,
				CONFIG_WIFI_SIWG917_MAX_PACKET_SIZE, 0, NULL, NULL);

	if (ret < 0) {
		return errno;
	}

	return 0;
}

/**
 * This function is called when user wants to close the socket.
 */
static int siwg917_put(struct net_context *context)
{
	int sock = (int)context->offload_context;

	struct socket_data *sd = &siwg917_data.socket_data[sock];

	memset(&(context->remote), 0, sizeof(struct sockaddr_in));
	context->flags &= ~NET_CONTEXT_REMOTE_ADDR_SET;
	int ret = sli_si91x_shutdown((int)context->offload_context, 0);

	if (ret < 0) {
		return errno;
	}

	net_pkt_unref(sd->rx_pkt);

	memset(sd, 0, sizeof(struct socket_data));

	return 0;
}

static struct net_offload siwg917_offload = {
	.get = siwg917_get,
	.bind = siwg917_bind,
	.listen = siwg917_listen,
	.connect = siwg917_connect,
	.accept = siwg917_accept,
	.send = siwg917_send,
	.sendto = siwg917_sendto,
	.recv = siwg917_recv,
	.put = siwg917_put,
};

static void siwg917_wifi_init(struct net_if *iface)
{
	uint32_t status;

#ifdef CONFIG_SIWG917_AP_MODE
	status = sl_net_init(SL_NET_WIFI_AP_INTERFACE, NULL, NULL, NULL);
	if (status != SL_STATUS_OK) {
		LOG_ERR("Failed to start Wi-Fi AP interface: 0x%x", status);
	}
#endif
#ifdef CONFIG_SIWG917_CLIENT_MODE
	status = sl_net_init(SL_NET_WIFI_CLIENT_INTERFACE, NULL, NULL, NULL);

	if (status != SL_STATUS_OK) {
		LOG_ERR("Failed to start Wi-Fi client interface: 0x%x", status);
	}

	sl_mac_address_t mac_addr;

	sl_wifi_get_mac_address(SL_WIFI_CLIENT_INTERFACE, &mac_addr);
	memcpy(siwg917_data.mac_addr, mac_addr.octet, sizeof(mac_addr.octet));

	net_if_set_link_addr(iface, siwg917_data.mac_addr, sizeof(siwg917_data.mac_addr),
			     NET_LINK_ETHERNET);
#endif

	iface->if_dev->offload = &siwg917_offload;
	siwg917_wifi_iface = iface;
}

#if defined(CONFIG_NET_STATISTICS_WIFI)
static int siwg917_wifi_stats(const struct device *dev, struct net_stats_wifi *stats)
{
	return 0;
}
#endif

static int siwg917_wifi_dev_init(const struct device *dev)
{
	return 0;
}

static const struct wifi_mgmt_ops siwg917_wifi_mgmt = {
#ifdef CONFIG_SIWG917_CLIENT_MODE
	.scan = siwg917_wifi_scan,
	.connect = siwg917_wifi_connect,
	.disconnect = siwg917_wifi_disconnect,
#endif
#ifdef CONFIG_SIWG917_AP_MODE
	.ap_enable = siwg917_wifi_ap_enable,
#endif
	.iface_status = siwg917_wifi_status,
#if defined(CONFIG_NET_STATISTICS_WIFI)
	.get_stats = siwg917_wifi_stats,
#endif
};

static enum offloaded_net_if_types siwg917_get_wifi_type(void)
{
	return L2_OFFLOADED_NET_IF_TYPE_WIFI;
}

static const struct net_wifi_mgmt_offload siwg917_api = {
	.wifi_iface.iface_api.init = siwg917_wifi_init,
	.wifi_iface.get_type = siwg917_get_wifi_type,
	.wifi_mgmt_api = &siwg917_wifi_mgmt,
};

NET_DEVICE_OFFLOAD_INIT(siwg917, "siwf917", siwg917_wifi_dev_init, NULL, &siwg917_data, NULL,
			CONFIG_WIFI_INIT_PRIORITY, &siwg917_api,
			CONFIG_WIFI_SIWG917_MAX_PACKET_SIZE);
