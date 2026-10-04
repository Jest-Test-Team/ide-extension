// ESP-IDF sample: Wi-Fi CSI sensing + USB HID bridge (intentionally insecure fixture).
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#define WIFI_PASSWORD "hunter2-lab"
static const char *TAG = "csi";
static uint8_t g_report[64];
static QueueHandle_t q;

static const uint8_t aes_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static void csi_cb(void *ctx, wifi_csi_info_t *info) {
    int8_t local[128];
    memcpy(local, info->buf, info->len);
    ESP_LOGI(TAG, "csi len=%d", info->len);
}

static void IRAM_ATTR button_isr(void *arg) {
    xQueueSend(q, &arg, 0);
}

void hid_set_report(uint8_t id, const uint8_t *buffer, uint16_t bufsize) {
    memcpy(g_report, buffer, bufsize);
}

void hid_set_report_checked(uint8_t id, const uint8_t *buffer, uint16_t bufsize) {
    if (bufsize > sizeof(g_report)) {
        return;
    }
    memcpy(g_report, buffer, bufsize);
}

void log_payload(const char *payload) {
    printf(payload);
    char name[16];
    strcpy(name, payload);
}

void app_main(void) {
    nvs_flash_init();
    ESP_ERROR_CHECK(esp_netif_init());
    esp_netif_create_default_wifi_sta();
    wifi_config_t cfg = { .sta = { .ssid = "lab", .password = "hunter22" } };
    esp_wifi_set_config(WIFI_IF_STA, &cfg);
    esp_wifi_set_csi_rx_cb(csi_cb, NULL);
    gpio_isr_handler_add(GPIO_NUM_0, button_isr, NULL);
    uint8_t *buf = malloc(256);
    buf[0] = 1;
    uint8_t *ok = malloc(256);
    if (ok == NULL) {
        return;
    }
    uint32_t nonce = esp_random();
    int r = rand();
}
