#include "aho_queue.h"
#include <stdio.h>

void aho_queue_init(aho_queue_t *q) {
    if (!q) return;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
}

bool aho_queue_enqueue(aho_queue_t *q, uint8_t vertex_idx) {
    if (!q || aho_queue_is_full(q)) {
        DEBUG_PRINTF("Erro: Fila cheia. Falha ao enfileirar vertice %u\n", vertex_idx);
        return false;
    }
    q->buffer[q->tail] = vertex_idx;
    q->tail = (q->tail + 1) % AC_MAX_VERTICES;
    q->count++;
    return true;
}

uint8_t aho_queue_dequeue(aho_queue_t *q) {
    if (!q || aho_queue_is_empty(q)) {
        DEBUG_PRINTF("Erro: Fila vazia. Falha ao desenfileirar.\n");
        return INVALID_VERTEX_U8;
    }
    uint8_t vertex_idx = q->buffer[q->head];
    q->head = (q->head + 1) % AC_MAX_VERTICES;
    q->count--;
    return vertex_idx;
}

bool aho_queue_is_empty(const aho_queue_t *q) {
    return q ? (q->count == 0) : true;
}

bool aho_queue_is_full(const aho_queue_t *q) {
    return q ? (q->count == AC_MAX_VERTICES) : true;
}
