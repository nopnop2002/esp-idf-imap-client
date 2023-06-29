/*
 * IMAP email client
 *
 * I forked from here.
 * https://github.com/RealAlphabet/IMAP
 *
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
//#include "protocol_examples_common.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include <mbedtls/base64.h>
#include <sys/param.h>

#define SERVER_USES_STARTSSL 1

static const char *TAG = "IMAP";

/**
 * Root cert for imap.googlemail.com, taken from gmail_root_cert.pem
 *
 * The PEM file was extracted from the output of this command:
 * openssl s_client -showcerts -connect imap.googlemail.com:587 -starttls imap
 *
 * The CA root cert is the last cert given in the chain of certs.
 *
 * To embed it in the app binary, the PEM file is named
 * in the component.mk COMPONENT_EMBED_TXTFILES variable.
 */

extern const uint8_t gmail_root_cert_pem_start[] asm("_binary_gmail_root_cert_pem_start");
extern const uint8_t gmail_root_cert_pem_end[]	 asm("_binary_gmail_root_cert_pem_end");

extern const uint8_t esp_logo_png_start[] asm("_binary_esp_logo_png_start");
extern const uint8_t esp_logo_png_end[]   asm("_binary_esp_logo_png_end");

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

static int s_retry_num = 0;

static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
		esp_wifi_connect();
	} else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if (s_retry_num < CONFIG_ESP_MAXIMUM_RETRY) {
				esp_wifi_connect();
				s_retry_num++;
				ESP_LOGI(TAG, "retry to connect to the AP");
		} else {
				xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
		}
		ESP_LOGI(TAG,"connect to the AP fail");
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
		ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
		s_retry_num = 0;
		xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
	}
}

void wifi_init_sta(void)
{
	s_wifi_event_group = xEventGroupCreate();

	ESP_ERROR_CHECK(esp_netif_init());

	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	esp_event_handler_instance_t instance_any_id;
	esp_event_handler_instance_t instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
		ESP_EVENT_ANY_ID,
		&event_handler,
		NULL,
		&instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
		IP_EVENT_STA_GOT_IP,
		&event_handler,
		NULL,
		&instance_got_ip));

	wifi_config_t wifi_config = {
		.sta = {
			.ssid = CONFIG_ESP_WIFI_SSID,
			.password = CONFIG_ESP_WIFI_PASSWORD,
			/* Setting a password implies station will connect to all security modes including WEP/WPA.
			 * However these modes are deprecated and not advisable to be used. Incase your Access point
			 * doesn't support WPA2, these mode can be enabled by commenting below line */
			.threshold.authmode = WIFI_AUTH_WPA2_PSK,

			.pmf_cfg = {
				.capable = true,
				.required = false
			},
		},
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
	ESP_ERROR_CHECK(esp_wifi_start() );

	ESP_LOGI(TAG, "wifi_init_sta finished.");

	/* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
	 * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
	EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
						WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
						pdFALSE,
						pdFALSE,
						portMAX_DELAY);

	/* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
	 * happened. */
	if (bits & WIFI_CONNECTED_BIT) {
		ESP_LOGI(TAG, "connected to ap SSID:%s password:%s", CONFIG_ESP_WIFI_SSID, CONFIG_ESP_WIFI_PASSWORD);
	} else if (bits & WIFI_FAIL_BIT) {
		ESP_LOGI(TAG, "Failed to connect to SSID:%s, password:%s", CONFIG_ESP_WIFI_SSID, CONFIG_ESP_WIFI_PASSWORD);
	} else {
		ESP_LOGE(TAG, "UNEXPECTED EVENT");
	}

	/* The event will not be processed after unregister */
	//ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
	//ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
	vEventGroupDelete(s_wifi_event_group);
}

#define BUF_SIZE 512

static int perform_tls_handshake(mbedtls_ssl_context *ssl)
{
	int ret = -1;
	uint32_t flags;
	char *buf = NULL;
	buf = (char *) calloc(1, BUF_SIZE);
	if (buf == NULL) {
		ESP_LOGE(TAG, "calloc failed for size %d", BUF_SIZE);
		goto exit;
	}

	ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

	fflush(stdout);
	while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
			goto exit;
		}
	}

	ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

	if ((flags = mbedtls_ssl_get_verify_result(ssl)) != 0) {
		/* In real life, we probably want to close connection if ret != 0 */
		ESP_LOGW(TAG, "Failed to verify peer certificate!");
		mbedtls_x509_crt_verify_info(buf, BUF_SIZE, "  ! ", flags);
		ESP_LOGW(TAG, "verification info: %s", buf);
	} else {
		ESP_LOGI(TAG, "Certificate verified.");
	}

	ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(ssl));
	ret = 0; /* No error */

exit:
	if (buf) {
		free(buf);
	}
	return ret;
}

esp_err_t imap_login(mbedtls_ssl_context *ssl, const char *email, const char *password)
{
	unsigned char buf[2048];
	unsigned char answer[256];
	size_t len;

	// Read and set null terminated string.
	len = mbedtls_ssl_read(ssl, buf, 2048);
	buf[len] = 0;

	// Build and send LOGIN command.
	len = snprintf((char *)answer, 256, "A001 LOGIN %s %s\r\n", email, password);
	mbedtls_ssl_write(ssl, answer, len);

	// Read and set null terminated string.
	len = mbedtls_ssl_read(ssl, buf, 2048);
	buf[len]	= 0;
	printf("imap_login=[%s]\n", buf);
	printf("buf=[%s]\n", buf);

	if (strstr((char *)buf, "A001 OK") == 0)
		return ESP_FAIL;

	return ESP_OK;
}

esp_err_t imap_list_mailboxes(mbedtls_ssl_context *ssl)
{
	unsigned char buf[2048];
	size_t len;

	// Send LIST command.
	unsigned char command[64];
	strcpy((char *)command, "A002 LIST \"\" \"*\"\r\n");
	mbedtls_ssl_write(ssl, command, strlen((char *)command));

	// Read and set null terminated string.
	len = mbedtls_ssl_read(ssl, buf, 2048);
	buf[len] = 0;
	printf("imap_list_mailboxes=[%s]\n", buf);

	if (strstr((char *)buf, "A002 OK") == 0)
		return ESP_FAIL;

	return ESP_OK;
}

esp_err_t imap_select_mailboxes(mbedtls_ssl_context *ssl, int *mails)
{
	unsigned char buf[2048];
	size_t len;

	// Send SELECT command.
	unsigned char command[64];
	strcpy((char *)command, "A003 SELECT \"INBOX\"\r\n");
	mbedtls_ssl_write(ssl, command, strlen((char *)command));

	// Read and set null terminated string.
	len = mbedtls_ssl_read(ssl, buf, 2048);
	buf[len] = 0;
	//printf("imap_select_mailboxes=[%s]\n", buf);

	if (strstr((char *)buf, "A003 OK") == 0) {
		return ESP_FAIL;
	} else {
		char *work = strtok((char *)buf,"\r\n");
		ESP_LOGD(TAG, "work=[%s]", work);
		while(1) {
			work = strtok(NULL,"\r\n");
			if (work == NULL) break;
			ESP_LOGD(TAG, "work=[%s]", work);
			if (strstr(work, "EXISTS") != 0) {
				*mails = atoi(work+2);
				ESP_LOGI(TAG, "*mails=%d", *mails);
			}
		}
		return ESP_OK;
	}
}

esp_err_t imap_search_mailboxes(mbedtls_ssl_context *ssl, char *options, int *ids, int *mails)
{
	size_t ptrsz = 0;
	unsigned char *ptr = malloc(ptrsz+1);
	ptr[ptrsz] = 0;
	unsigned char buf[2048];
	size_t len;

	// Send FETCH command.
	unsigned char command[64];
	//sprintf(command, "A004 SEARCH ALL\r\n");
	//sprintf(command, "A004 SEARCH SEEN\r\n");
	//sprintf(command, "A004 SEARCH UNSEEN\r\n");
	sprintf((char *)command, "A004 SEARCH %s\r\n", options);
	ESP_LOGD(TAG, "search command=[%s]", command);
	mbedtls_ssl_write(ssl, command, strlen((char *)command));

	// Read and set null terminated string.
	while(1) {
		len = mbedtls_ssl_read(ssl, buf, 2048);
		buf[len] = 0;
		//printf("imap_search_mailboxes=[%s]\n", buf);
		ptrsz = ptrsz + len;
		ESP_LOGD(TAG, "ptrsz=%d", ptrsz);
		unsigned char *tmp = realloc(ptr, ptrsz+1);
		if (tmp == NULL) {
			ESP_LOGE(TAG, "realloc fail");
			free(ptr);
			return ESP_FAIL;
		} else {
			ptr = tmp;
			strcat((char *)ptr, (char *)buf);
			ptr[ptrsz] = 0;
		}
		if (strstr((char *)buf, "A004 BAD") != 0) return ESP_FAIL;
		if (strstr((char *)buf, "A004 OK") != 0) break;
	}
	//printf("imap_search_header_mailboxes=[%s]\n", ptr);
	char *epos;
	epos = strstr((char *)ptr, "\r\nA004 OK");
	int eslen = (char *)epos - (char *)ptr;
	ptr[eslen] = 0;
	//printf("imap_search_header_mailboxes=[%s]\n", ptr);

	int index = 0;
	char *work = strtok((char *)ptr," ");
	ESP_LOGD(TAG, "work=[%s]", work);
	while(1) {
		work = strtok(NULL," ");
		if (work == NULL) break;
		ids[index] = atoi(work);
		ESP_LOGD(TAG, "work=[%s] ids[%d]=%d", work, index, ids[index]);
		if (ids[index] != 0) index++;
	}

	free(ptr);
	*mails = index;
	return ESP_OK;
}

esp_err_t imap_fetch_header_mailboxes(mbedtls_ssl_context *ssl, int message)
{
	size_t ptrsz = 0;
	unsigned char *ptr = malloc(ptrsz+1);
	ptr[ptrsz] = 0;
	unsigned char buf[2048];
	size_t len;

	// Send FETCH command.
	unsigned char command[64];
	sprintf((char *)command, "A005 FETCH %d RFC822.HEADER\r\n", message);
	mbedtls_ssl_write(ssl, command, strlen((char *)command));

	// Read and set null terminated string.
	while(1) {
		len = mbedtls_ssl_read(ssl, buf, 2048);
		ESP_LOGD(TAG, "len=%d",len);
		buf[len] = 0;
		//printf("imap_fetch_header_mailboxes=[%s]\n", buf);
		ptrsz = ptrsz + len;
		ESP_LOGD(TAG, "ptrsz=%d", ptrsz);
		unsigned char *tmp = realloc(ptr, ptrsz+1);
		if (tmp == NULL) {
			ESP_LOGE(TAG, "realloc fail");
			free(ptr);
			return ESP_FAIL;
		} else {
			ptr = tmp;
			strcat((char *)ptr, (char *)buf);
			ptr[ptrsz] = 0;
		}
		if (strstr((char *)buf, "A005 BAD") != 0) return ESP_FAIL;
		if (strstr((char *)buf, "A005 OK") != 0) break;
	}
	//printf("imap_fetch_header_mailboxes=[%s]\n", ptr);
	char *spos;
	char *epos;
	int eslen;

	// Parse Date
	if ((spos = strstr((char *)ptr, "\r\nDate:")) != 0) {
		epos = strstr(spos+2, "\r\n");
		eslen = (char *)epos - (char *)spos;
		ESP_LOGI(TAG, "[%.*s]", eslen - 2, spos + 2);
	}
	// Parse From
	if ((spos = strstr((char *)ptr, "\r\nFrom:")) != 0) {
		epos = strstr(spos+2, "\r\n");
		eslen = (char *)epos - (char *)spos;
		ESP_LOGI(TAG, "[%.*s]", eslen - 2, spos + 2);
	}
#if 0
	// Parse To
	if ((spos = strstr((char *)ptr, "\r\nTo:")) != 0) {
		epos = strstr(spos+2, "\r\n");
		eslen = (char *)epos - (char *)spos;
		ESP_LOGI(TAG, "[%.*s]", eslen - 2, spos + 2);
	}
#endif
	// Parse Subject
	if ((spos = strstr((char *)ptr, "\r\nSubject:")) != 0) {
		epos = strstr(spos+2, "\r\n");
		eslen = (char *)epos - (char *)spos;
		ESP_LOGI(TAG, "[%.*s]", eslen - 2, spos + 2);
	}

	free(ptr);
	return ESP_OK;
}

static void imap_client_task(void *pvParameters)
{
	int ret;
	int *ids = NULL;

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_x509_crt cacert;
	mbedtls_ssl_config conf;
	mbedtls_net_context server_fd;

	mbedtls_ssl_init(&ssl);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	ESP_LOGI(TAG, "Seeding the random number generator");

	mbedtls_ssl_config_init(&conf);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									 NULL, 0)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%x", -ret);
		goto exit;
	}

	ESP_LOGI(TAG, "Loading the CA root certificate...");

	ret = mbedtls_x509_crt_parse(&cacert, gmail_root_cert_pem_start,
								 gmail_root_cert_pem_end - gmail_root_cert_pem_start);

	if (ret < 0) {
		ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x", -ret);
		goto exit;
	}

	ESP_LOGI(TAG, "Setting hostname for TLS session...");

	/* Hostname set here should match CN in server certificate */
	if ((ret = mbedtls_ssl_set_hostname(&ssl, CONFIG_IMAP_SERVER)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
		goto exit;
	}

	ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

	if ((ret = mbedtls_ssl_config_defaults(&conf,
										   MBEDTLS_SSL_IS_CLIENT,
										   MBEDTLS_SSL_TRANSPORT_STREAM,
										   MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned -0x%x", -ret);
		goto exit;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
	mbedtls_esp_enable_debug_log(&conf, 4);
#endif

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
		goto exit;
	}

	mbedtls_net_init(&server_fd);

	ESP_LOGI(TAG, "Connecting to %s:%s...", CONFIG_IMAP_SERVER, CONFIG_IMAP_PORT_NUMBER);

	if ((ret = mbedtls_net_connect(&server_fd, CONFIG_IMAP_SERVER,
								   CONFIG_IMAP_PORT_NUMBER, MBEDTLS_NET_PROTO_TCP)) != 0) {
		ESP_LOGE(TAG, "mbedtls_net_connect returned -0x%x", -ret);
		goto exit;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	// Perform SSL handshake.
	if ((ret = perform_tls_handshake(&ssl)) != 0) { 
		ESP_LOGE(TAG, "perform_tls_handshake returned -0x%x", -ret);
		goto exit;
	}
	ESP_LOGI(TAG, "Connected.");

	// Login into account.
	if (imap_login(&ssl, CONFIG_IMAP_SENDER_MAIL, CONFIG_IMAP_SENDER_PASSWORD) != ESP_OK) {
		ESP_LOGE(TAG, "imap_list_mailboxes fail");
		goto exit;
	}

	// List mailboxes.
	if (imap_list_mailboxes(&ssl) != ESP_OK) {
		ESP_LOGE(TAG, "imap_list_mailboxes fail");
		goto exit;
	}

	// Select mailboxes.
	int mails;
	if (imap_select_mailboxes(&ssl, &mails) != ESP_OK) {
		ESP_LOGE(TAG, "imap_select_mailboxes fail");
		goto exit;
	}
	ESP_LOGI(TAG, "imap_select_mailboxes mails=%d", mails);
	ids = (int *) calloc(mails, sizeof(int));
	if (ids == NULL) {
		ESP_LOGE(TAG, "calloc fail");
		goto exit;
	}

	// Search mailboxes.
#if CONFIG_IMAP_SEARCH_ALL
	char options[] = "ALL";
#endif
#if CONFIG_IMAP_SEARCH_SEEN
	char options[] = "SEEN";
#endif
#if CONFIG_IMAP_SEARCH_UNSEEN
	char options[] = "UNSEEN";
#endif
#if CONFIG_IMAP_SEARCH_ANSWERED
	char options[] = "ANSWERED";
#endif
#if CONFIG_IMAP_SEARCH_NOANSWERED
	char options[] = "NOANSWERED";
#endif
#if CONFIG_IMAP_SEARCH_SUBJECT
	ESP_LOGI(TAG, "IMAP_SEARCH_SUBJECT_TEXT=[%s]", CONFIG_IMAP_SEARCH_SUBJECT_TEXT);
	//char options[] = "HEADER Subject \"Add a profile photo\"";
	char options[128];
	sprintf(options, "HEADER Subject \"%s\"", CONFIG_IMAP_SEARCH_SUBJECT_TEXT);
#endif
	ESP_LOGI(TAG, "Fetch %s mails from imap", options);
	if (imap_search_mailboxes(&ssl, options, ids, &mails) != ESP_OK) {
		ESP_LOGE(TAG, "imap_search_mailboxes fail");
		goto exit;
	}
	ESP_LOGI(TAG, "imap_retch_mailboxes mails=%d", mails);

	// Fetch mail header.
	for (int i=0;i<mails;i++) {
		int message = ids[i]; 
		if (imap_fetch_header_mailboxes(&ssl, message) != ESP_OK) {
			ESP_LOGE(TAG, "imap_fetch_header_mailboxes fail. message=%d", message);
			goto exit;
		}
		ESP_LOGI(TAG, "-------------------------------------------------");
	}

	/* Close connection */
	mbedtls_ssl_close_notify(&ssl);
	ret = 0; /* No errors */

exit:
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	if (ret != 0) {
		char buf[100];
		mbedtls_strerror(ret, buf, 100);
		ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
	}

	if (ids) free(ids);
	vTaskDelete(NULL);
}

void app_main(void)
{
	// Initialize NVS
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);

	// Initialize WiFi
	wifi_init_sta();

	// Start task
	xTaskCreate(&imap_client_task, "imap_client_task", 8 * 1024, NULL, 5, NULL);
}
