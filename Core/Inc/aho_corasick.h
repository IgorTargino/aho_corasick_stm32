#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

#include <stdbool.h>
#include <stdint.h>
#include "aho_queue.h"
#include "aho_config.h"

typedef void (*ac_match_callback_t)(const char* pattern, int position);

typedef struct {
    uint8_t character;
    uint8_t next_vertex;
} ac_transition_t;

typedef struct ac_vertex {
    ac_transition_t transitions[AC_MAX_TRANSITIONS_PER_VERTEX];
    uint8_t num_transitions;
    uint8_t link;             // Link de falha
    bool is_output;           // Flag que indica se este estado é terminal
    uint8_t num_patterns;     // Número de padrões que terminam aqui
    uint8_t pattern_indices[AC_MAX_PATTERNS_PER_VERTEX];
} ac_vertex_t;

typedef struct ac_automaton {
    ac_vertex_t vertices[AC_MAX_VERTICES];
    uint8_t vertex_count;
    const char* patterns[AC_MAX_PATTERNS];
    uint8_t pattern_count;
    aho_queue_t queue;
    ac_match_callback_t match_callback;
} ac_automaton_t;

void ac_init(ac_automaton_t *ac, ac_match_callback_t callback);
bool ac_add_pattern(ac_automaton_t *ac, const char* pattern);
void ac_build(ac_automaton_t *ac);
void ac_search(ac_automaton_t *ac, const char* text);

#endif // AHO_CORASICK_H
