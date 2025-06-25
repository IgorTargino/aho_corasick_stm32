#include "aho_corasick.h"
#include <string.h> 

// O vértice 0 é sempre a raiz do Trie.
static const uint8_t ROOT_VERTEX = 0;

// Converte um caractere para um índice no alfabeto (0-25).
// Retorna -1 se o caractere for inválido. A busca é case-insensitive.
static int char_to_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    return -1;
}

static uint8_t find_transition(const ac_vertex_t *v, uint8_t char_idx);
static uint8_t get_next_state(ac_automaton_t *ac, uint8_t current_state, uint8_t char_idx);
static void report_matches(ac_automaton_t *ac, uint8_t state, int text_pos);

void ac_init(ac_automaton_t *ac, ac_match_callback_t callback) {
    if (!ac) return;

    memset(ac, 0, sizeof(ac_automaton_t));
    ac->match_callback = callback;
    aho_queue_init(&ac->queue);

    ac->vertex_count = 1;
    ac->vertices[ROOT_VERTEX].link = ROOT_VERTEX;
}

// Adiciona um padrão ao Trie
bool ac_add_pattern(ac_automaton_t *ac, const char* pattern) {
    if (!ac || !pattern || *pattern == '\0' || ac->pattern_count >= AC_MAX_PATTERNS) {
        return false;
    }

    uint8_t current_vertex = ROOT_VERTEX;
    int pattern_len = strlen(pattern);

    // Verifica se há espaço para os novos vértices
    if (ac->vertex_count + pattern_len > AC_MAX_VERTICES) {
        return false;
    }

    // Adiciona o caminho do padrão no Trie
    for (int i = 0; i < pattern_len; ++i) {
        int char_idx = char_to_index(pattern[i]);
        if (char_idx == -1) continue; // Ignora caracteres inválidos

        uint8_t next_vertex = find_transition(&ac->vertices[current_vertex], (uint8_t)char_idx);

        if (next_vertex == INVALID_VERTEX_U8) {
            next_vertex = ac->vertex_count++;
            if (next_vertex >= AC_MAX_VERTICES) return false; // Segurança

            memset(&ac->vertices[next_vertex], 0, sizeof(ac_vertex_t));
            ac->vertices[next_vertex].link = INVALID_VERTEX_U8;

            ac_vertex_t *v = &ac->vertices[current_vertex];
            if (v->num_transitions < AC_MAX_TRANSITIONS_PER_VERTEX) {
                v->transitions[v->num_transitions].character = (uint8_t)char_idx;
                v->transitions[v->num_transitions].next_vertex = next_vertex;
                v->num_transitions++;
            } else {
                 return false;
            }
        }
        current_vertex = next_vertex;
    }

    ac_vertex_t *v = &ac->vertices[current_vertex];
    if (v->num_patterns < AC_MAX_PATTERNS_PER_VERTEX) {
        v->is_output = true;
        ac->patterns[ac->pattern_count] = pattern;
        v->pattern_indices[v->num_patterns++] = ac->pattern_count++;
    } else {
        return false;
    }

    return true;
}

void ac_build(ac_automaton_t *ac) {
    if (!ac || ac->vertex_count <= 1) return;

    aho_queue_init(&ac->queue);
    ac_vertex_t *root = &ac->vertices[ROOT_VERTEX];

    for (uint8_t i = 0; i < root->num_transitions; ++i) {
        uint8_t child_idx = root->transitions[i].next_vertex;
        ac->vertices[child_idx].link = ROOT_VERTEX;
        aho_queue_enqueue(&ac->queue, child_idx);
    }

    while (!aho_queue_is_empty(&ac->queue)) {
        uint8_t current_v_idx = aho_queue_dequeue(&ac->queue);
        ac_vertex_t *current_v = &ac->vertices[current_v_idx];

        for (uint8_t i = 0; i < current_v->num_transitions; ++i) {
            uint8_t char_idx = current_v->transitions[i].character;
            uint8_t child_idx = current_v->transitions[i].next_vertex;

            ac->vertices[child_idx].link = get_next_state(ac, current_v->link, char_idx);
            aho_queue_enqueue(&ac->queue, child_idx);
        }
    }
}

void ac_search(ac_automaton_t *ac, const char* text) {
    if (!ac || !text || ac->pattern_count == 0) return;

    uint8_t current_state = ROOT_VERTEX;
    for (int i = 0; text[i] != '\0'; ++i) {
        int char_idx = char_to_index(text[i]);
        if (char_idx == -1) {
            current_state = ROOT_VERTEX;
            continue;
        }

        current_state = get_next_state(ac, current_state, (uint8_t)char_idx);
        report_matches(ac, current_state, i);
    }
}

static uint8_t find_transition(const ac_vertex_t *v, uint8_t char_idx) {
    for (int i = 0; i < v->num_transitions; ++i) {
        if (v->transitions[i].character == char_idx) {
            return v->transitions[i].next_vertex;
        }
    }
    return INVALID_VERTEX_U8;
}

static uint8_t get_next_state(ac_automaton_t *ac, uint8_t current_state, uint8_t char_idx) {
    while (true) {
        uint8_t next = find_transition(&ac->vertices[current_state], char_idx);
        if (next != INVALID_VERTEX_U8) {
            return next;
        }
        if (current_state == ROOT_VERTEX) {
            return ROOT_VERTEX;
        }
        current_state = ac->vertices[current_state].link;
    }
}

static void report_matches(ac_automaton_t *ac, uint8_t state, int text_pos) {
    if (!ac->match_callback) return;

    uint8_t current_state = state;
    while (current_state != ROOT_VERTEX) {
        if (ac->vertices[current_state].is_output) {
            ac_vertex_t *v = &ac->vertices[current_state];
            for (uint8_t i = 0; i < v->num_patterns; ++i) {
                uint8_t pattern_idx = v->pattern_indices[i];
                ac->match_callback(ac->patterns[pattern_idx], text_pos);
            }
        }
        current_state = ac->vertices[current_state].link;
    }
}
