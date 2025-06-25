#ifndef AHO_CONFIG_H
#define AHO_CONFIG_H

#include <stdint.h>

#define AC_MAX_VERTICES 80
#define AC_MAX_PATTERNS 255
#define AC_MAX_PATTERNS_PER_VERTEX 2
#define AC_MAX_TRANSITIONS_PER_VERTEX 26
#define INVALID_VERTEX_U8 255

#ifdef DEBUG_PRINTS
    #include <stdio.h>
    #define DEBUG_PRINTF(format, ...) printf("[DEBUG] " format, ##__VA_ARGS__)
#else
    #define DEBUG_PRINTF(format, ...) ((void)0)
#endif

#endif
