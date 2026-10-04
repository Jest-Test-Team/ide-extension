// macOS Endpoint Security agent (intentionally flawed fixture).
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>

static es_client_t *g_client;

static void handle(es_client_t *client, const es_message_t *msg) {
    if (msg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
        es_message_t *copy = es_copy_message(msg);
        printf("exec\n");
        es_free_message(copy);
    }
}

int start_agent(void) {
    es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) { handle(c, m); });
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_EXEC };
    if (es_subscribe(g_client, events, 2) != ES_RETURN_SUCCESS) {
        return 1;
    }
    return 0;
}
