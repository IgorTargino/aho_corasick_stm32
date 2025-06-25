#ifndef AHO_QUEUE_H
#define AHO_QUEUE_H

#include <stdbool.h>
#include <stdint.h>
#include "aho_config.h"

typedef struct {
    uint8_t buffer[AC_MAX_VERTICES];
    uint8_t head;
    uint8_t tail;
    uint8_t count;
} aho_queue_t;

void aho_queue_init(aho_queue_t *q);
bool aho_queue_enqueue(aho_queue_t *q, uint8_t vertex_idx);
uint8_t aho_queue_dequeue(aho_queue_t *q);
bool aho_queue_is_empty(const aho_queue_t *q);
bool aho_queue_is_full(const aho_queue_t *q);

#endif // AHO_QUEUE_H
