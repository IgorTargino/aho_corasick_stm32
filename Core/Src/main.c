/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : STM32 Network Packet Filter using Aho-Corasick Algorithm
  ******************************************************************************
  * Network packet filtering with realistic pattern count for 80 vertices
  * Each vertex = 1 character state in the automaton
  * Estimated ~15-20 patterns maximum for 80 vertices
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "aho_corasick.h"
#include <string.h>
#include <stdio.h>

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

typedef enum {
    FILTER_STATE_IDLE,
    FILTER_STATE_RECEIVING,
    FILTER_STATE_PROCESSING,
    FILTER_STATE_COMPLETE
} filter_state_t;

typedef struct {
    char buffer[256];           // Buffer para dados recebidos
    uint16_t length;
    uint16_t rx_index;
    filter_state_t state;
    uint32_t matches_found;
    uint32_t packets_processed;
    bool processing_active;
} packet_filter_t;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

#define LED_GREEN_Pin GPIO_PIN_5
#define LED_GREEN_GPIO_Port GPIOA
#define USER_BUTTON_Pin GPIO_PIN_13
#define USER_BUTTON_GPIO_Port GPIOC

#define PACKET_START_MARKER "PKT:"
#define PACKET_END_MARKER "\r\n"

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

// Padrões críticos de segurança - dimensionados para ~80 vértices
// Estimativa: 15-20 padrões curtos/médios para não exceder limite de vértices
static const char* security_threat_patterns[18] = {
    // SQL Injection (padrões curtos mais efetivos)
    "' OR '1'='1",      // 11 chars
    "admin'--",         // 8 chars  
    "UNION SELECT",     // 12 chars
    "DROP TABLE",       // 10 chars
    
    // XSS básico
    "<script>",         // 8 chars
    "javascript:",      // 11 chars
    "onerror=",         // 8 chars
    
    // Comandos perigosos
    "/bin/sh",          // 7 chars
    "cmd.exe",          // 7 chars
    "wget ",            // 5 chars
    "curl ",            // 5 chars
    
    // Network exploits
    "nc -l",            // 5 chars
    "nmap ",            // 5 chars
    
    // Malware indicators
    "payload",          // 7 chars
    "shell",            // 5 chars
    "exploit",          // 7 chars
    
    // File inclusion
    "../",              // 3 chars
    "..\\",             // 3 chars
};

// Cálculo estimado de vértices:
// - Padrão mais longo: "' OR '1'='1" = 11 vértices
// - Total caracteres únicos: ~45-50 vértices na trie
// - Links de falha e otimizações: ~25-30 vértices extras
// - Total estimado: ~70-80 vértices (dentro do limite)

static ac_automaton_t packet_filter_ac;
static packet_filter_t filter_context;
static char uart_rx_buffer[64];
static char uart_tx_buffer[256];

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);

/* USER CODE BEGIN PFP */

static void packet_filter_init(void);
static void packet_filter_reset(void);
static void packet_filter_process_byte(uint8_t byte);
static void packet_filter_analyze(void);
static void send_status_report(void);
static void send_vertex_usage_report(void);
static void on_threat_pattern_found(const char* pattern, int position);

/* USER CODE END PFP */

/* USER CODE BEGIN 0 */

/**
 * @brief Callback chamado quando um padrão malicioso é encontrado
 */
static void on_threat_pattern_found(const char* pattern, int position) {
    filter_context.matches_found++;
    
    // Pisca LED verde para indicar detecção
    HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_SET);
    HAL_Delay(100);
    HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_RESET);
    
    // Envia alerta via UART
    snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
             "THREAT: Pattern '%s' found at position %d\r\n", pattern, position);
    HAL_UART_Transmit(&huart2, (uint8_t*)uart_tx_buffer, strlen(uart_tx_buffer), 1000);
}

/**
 * @brief Inicializa o sistema de filtragem de pacotes
 */
static void packet_filter_init(void) {
    // Inicializa o autômato Aho-Corasick
    ac_init(&packet_filter_ac, on_threat_pattern_found);
    
    // Adiciona padrões de ameaças (limitado para não exceder 80 vértices)
    uint8_t patterns_added = 0;
    const uint8_t max_patterns = sizeof(security_threat_patterns) / sizeof(security_threat_patterns[0]);
    
    for (int i = 0; i < max_patterns; i++) {
        if (ac_add_pattern(&packet_filter_ac, security_threat_patterns[i])) {
            patterns_added++;
        } else {
            snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
                     "ERROR: Failed to add pattern %d: '%s' - Vertex limit reached!\r\n", 
                     i, security_threat_patterns[i]);
            HAL_UART_Transmit(&huart2, (uint8_t*)uart_tx_buffer, strlen(uart_tx_buffer), 1000);
            break;
        }
    }
    
    // Constrói o autômato
    ac_build(&packet_filter_ac);
    
    // Inicializa contexto do filtro
    packet_filter_reset();
    
    // Relatório detalhado de inicialização
    snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
             "INIT: Packet filter ready\r\n"
             "  Patterns loaded: %d/%d\r\n"
             "  Vertices used: %d/80\r\n",
             patterns_added, max_patterns, packet_filter_ac.vertex_count);
    HAL_UART_Transmit(&huart2, (uint8_t*)uart_tx_buffer, strlen(uart_tx_buffer), 1000);
    
    // Envia relatório de uso de vértices
    send_vertex_usage_report();
    
    // Instruções de uso
    const char* instructions = 
        "Commands:\r\n"
        "  PKT:<data>\\r\\n  - Process packet data\r\n"
        "  STATUS\\r\\n      - Show statistics\r\n"
        "  VERTICES\\r\\n    - Show vertex usage\r\n"
        "  RESET\\r\\n       - Reset counters\r\n"
        "Ready for packet analysis...\r\n";
    HAL_UART_Transmit(&huart2, (uint8_t*)instructions, strlen(instructions), 2000);
}

/**
 * @brief Envia relatório detalhado do uso de vértices
 */
static void send_vertex_usage_report(void) {
    float vertex_usage = (packet_filter_ac.vertex_count * 100.0f) / AC_MAX_VERTICES;
    
    snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
             "VERTEX USAGE REPORT:\r\n"
             "  Total vertices: %d/%d (%.1f%%)\r\n"
             "  Remaining: %d vertices\r\n"
             "  Patterns loaded: %d\r\n"
             "  Transitions per vertex: %d max\r\n",
             packet_filter_ac.vertex_count, AC_MAX_VERTICES, vertex_usage,
             AC_MAX_VERTICES - packet_filter_ac.vertex_count,
             packet_filter_ac.pattern_count,
             AC_MAX_TRANSITIONS_PER_VERTEX);
    
    HAL_UART_Transmit(&huart2, (uint8_t*)uart_tx_buffer, strlen(uart_tx_buffer), 2000);
    
    // Lista os padrões carregados
    HAL_UART_Transmit(&huart2, (uint8_t*)"LOADED PATTERNS:\r\n", 18, 1000);
    for (int i = 0; i < packet_filter_ac.pattern_count; i++) {
        snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
                 "  %2d: '%s' (%d chars)\r\n", 
                 i+1, packet_filter_ac.patterns[i], strlen(packet_filter_ac.patterns[i]));
        HAL_UART_Transmit(&huart2, (uint8_t*)uart_tx_buffer, strlen(uart_tx_buffer), 1000);
    }
}

/**
 * @brief Reseta o contexto do filtro
 */
static void packet_filter_reset(void) {
    memset(&filter_context, 0, sizeof(filter_context));
    filter_context.state = FILTER_STATE_IDLE;
}

/**
 * @brief Processa um byte recebido via UART
 */
static void packet_filter_process_byte(uint8_t byte) {
    static char command_buffer[16];
    static uint8_t cmd_index = 0;
    
    switch (filter_context.state) {
        case FILTER_STATE_IDLE:
            // Verifica se é início de comando
            if (byte == 'P' || byte == 'S' || byte == 'R' || byte == 'V') {
                command_buffer[0] = byte;
                cmd_index = 1;
            } else if (cmd_index > 0) {
                command_buffer[cmd_index++] = byte;
                
                // Verifica comando PKT:
                if (cmd_index == 4 && strncmp(command_buffer, "PKT:", 4) == 0) {
                    filter_context.state = FILTER_STATE_RECEIVING;
                    filter_context.rx_index = 0;
                    cmd_index = 0;
                }
                // Verifica comando STATUS
                else if (cmd_index == 6 && strncmp(command_buffer, "STATUS", 6) == 0) {
                    send_status_report();
                    cmd_index = 0;
                }
                // Verifica comando VERTICES
                else if (cmd_index == 8 && strncmp(command_buffer, "VERTICES", 8) == 0) {
                    send_vertex_usage_report();
                    cmd_index = 0;
                }
                // Verifica comando RESET
                else if (cmd_index == 5 && strncmp(command_buffer, "RESET", 5) == 0) {
                    filter_context.matches_found = 0;
                    filter_context.packets_processed = 0;
                    HAL_UART_Transmit(&huart2, (uint8_t*)"RESET: Counters cleared\r\n", 25, 1000);
                    cmd_index = 0;
                }
                // Reset se comando inválido
                else if (cmd_index >= 10) {
                    cmd_index = 0;
                }
            }
            break;
            
        case FILTER_STATE_RECEIVING:
            // Verifica fim do pacote
            if (byte == '\r') {
                filter_context.state = FILTER_STATE_PROCESSING;
            } else if (filter_context.rx_index < sizeof(filter_context.buffer) - 1) {
                filter_context.buffer[filter_context.rx_index++] = byte;
            } else {
                // Buffer overflow - descarta pacote
                HAL_UART_Transmit(&huart2, (uint8_t*)"ERROR: Packet too large\r\n", 25, 1000);
                filter_context.state = FILTER_STATE_IDLE;
                filter_context.rx_index = 0;
            }
            break;
            
        case FILTER_STATE_PROCESSING:
            if (byte == '\n') {
                filter_context.state = FILTER_STATE_COMPLETE;
            }
            break;
            
        default:
            filter_context.state = FILTER_STATE_IDLE;
            break;
    }
}

/**
 * @brief Analisa o pacote recebido usando Aho-Corasick
 */
static void packet_filter_analyze(void) {
    if (filter_context.state != FILTER_STATE_COMPLETE) {
        return;
    }
    
    // Null-terminate buffer
    filter_context.buffer[filter_context.rx_index] = '\0';
    filter_context.length = filter_context.rx_index;
    
    uint32_t matches_before = filter_context.matches_found;
    
    // Executa análise Aho-Corasick
    ac_search(&packet_filter_ac, filter_context.buffer);
    
    filter_context.packets_processed++;
    
    // Relatório do resultado
    uint32_t new_matches = filter_context.matches_found - matches_before;
    if (new_matches > 0) {
        snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
                 "ALERT: %lu threat(s) detected in packet #%lu (%u bytes)\r\n",
                 new_matches, filter_context.packets_processed, filter_context.length);
    } else {
        snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
                 "CLEAN: Packet #%lu analyzed (%u bytes) - No threats\r\n",
                 filter_context.packets_processed, filter_context.length);
    }
    
    HAL_UART_Transmit(&huart2, (uint8_t*)uart_tx_buffer, strlen(uart_tx_buffer), 1000);
    
    // Reset para próximo pacote
    filter_context.state = FILTER_STATE_IDLE;
    filter_context.rx_index = 0;
    memset(filter_context.buffer, 0, sizeof(filter_context.buffer));
}

/**
 * @brief Envia relatório de status
 */
static void send_status_report(void) {
    float vertex_usage = (packet_filter_ac.vertex_count * 100.0f) / AC_MAX_VERTICES;
    
    snprintf(uart_tx_buffer, sizeof(uart_tx_buffer), 
             "STATUS REPORT:\r\n"
             "  Packets processed: %lu\r\n"
             "  Threats detected: %lu\r\n"
             "  Patterns loaded: %d\r\n"
             "  Vertices used: %d/80 (%.1f%%)\r\n"
             "  Filter state: %s\r\n",
             filter_context.packets_processed,
             filter_context.matches_found,
             packet_filter_ac.pattern_count,
             packet_filter_ac.vertex_count, vertex_usage,
             filter_context.state == FILTER_STATE_IDLE ? "IDLE" :
             filter_context.state == FILTER_STATE_RECEIVING ? "RECEIVING" :
             filter_context.state == FILTER_STATE_PROCESSING ? "PROCESSING" : "COMPLETE");
    
    HAL_UART_Transmit(&huart2, (uint8_t*)uart_tx_buffer, strlen(uart_tx_buffer), 2000);
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void) {
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();

  /* USER CODE BEGIN 2 */
  
  // Inicializa sistema de filtragem
  packet_filter_init();
  
  // Inicia recepção UART em modo interrupt
  HAL_UART_Receive_IT(&huart2, (uint8_t*)uart_rx_buffer, 1);

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1) {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    
    // Processa análise de pacotes
    packet_filter_analyze();
    
    // Verifica botão do usuário para relatório de vértices
    if (HAL_GPIO_ReadPin(USER_BUTTON_GPIO_Port, USER_BUTTON_Pin) == GPIO_PIN_RESET) {
        HAL_Delay(50); // Debounce
        if (HAL_GPIO_ReadPin(USER_BUTTON_GPIO_Port, USER_BUTTON_Pin) == GPIO_PIN_RESET) {
            send_vertex_usage_report();
            while (HAL_GPIO_ReadPin(USER_BUTTON_GPIO_Port, USER_BUTTON_Pin) == GPIO_PIN_RESET) {
                HAL_Delay(10);
            }
        }
    }
    
    // Heartbeat LED (sistema ativo)
    static uint32_t last_heartbeat = 0;
    if (HAL_GetTick() - last_heartbeat > 3000) {
        HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);
        HAL_Delay(50);
        HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);
        last_heartbeat = HAL_GetTick();
    }
    
    HAL_Delay(10);
  }
  /* USER CODE END 3 */
}

// ...existing code... (resto das funções permanecem inalteradas)

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void) {
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitStruct structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK) {
    Error_Handler();
  }
}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void) {
  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void) {
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : USER_BUTTON_Pin */
  GPIO_InitStruct.Pin = USER_BUTTON_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_PULLUP;
  HAL_GPIO_Init(USER_BUTTON_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : LED_GREEN_Pin */
  GPIO_InitStruct.Pin = LED_GREEN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LED_GREEN_GPIO_Port, &GPIO_InitStruct);
}

/* USER CODE BEGIN 4 */

/**
 * @brief Callback de recepção UART
 */
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    if (huart->Instance == USART2) {
        // Processa byte recebido
        packet_filter_process_byte((uint8_t)uart_rx_buffer[0]);
        
        // Reinicia recepção para próximo byte
        HAL_UART_Receive_IT(&huart2, (uint8_t*)uart_rx_buffer, 1);
    }
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void) {
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1) {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name and location of the C source file where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line) {
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */