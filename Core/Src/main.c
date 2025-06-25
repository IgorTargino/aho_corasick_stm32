/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Refatorado para Filtro de SPAM com Aho-Corasick
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include <stdio.h> // Ainda necessário para snprintf
#include <string.h>
#include <stdbool.h> // Adicionado para usar o tipo bool
#include "aho_corasick.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
// Estrutura para simular um e-mail
typedef struct {
    const char* from;
    const char* subject;
    const char* body;
} Email;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define NUM_SPAM_KEYWORDS 12
#define NUM_EMAILS 4
#define UART_TX_TIMEOUT 100 // Timeout para transmissão UART em ms
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart2;
ac_automaton_t ac_spam_filter; // Nome da variável mais descritivo

/* USER CODE BEGIN PV */

// --- Base de Dados para o Filtro de SPAM ---

// 1. Padrões (palavras-chave) de SPAM a serem procurados
const char* spam_keywords[NUM_SPAM_KEYWORDS] = {
    "oferta", "gratis", "promocao", "desconto",
    "clique aqui", "renda extra", "viagra", "urgente", "tigrinho", "vaga", "pishing", "virus"
};

// 2. Lista de e-mails para simular uma caixa de entrada
Email email_inbox[NUM_EMAILS] = {
    {
        "amigo@email.com",
        "Re: Nosso almoco",
        "Oi, tudo bem? So confirmando nosso encontro na sexta-feira. Abracos."
    },
    {
        "vendas@loja-suspeita.com",
        "OFERTA IMPERDIVEL! So hoje!",
        "Parabens! Voce ganhou um super desconto de 90%. Para garantir sua renda extra, clique aqui agora!"
    },
    {
        "chefe@empresa.com",
        "Relatorio Semanal",
        "Por favor, envie o relatorio de vendas ate o final do dia. Obrigado."
    },
    {
        "spam@propaganda.com",
        "Sua saude em primeiro lugar",
        "Temos um produto com preco gratis para voce, compre viagra com seguranca."
    }
};

// Variável de estado para a detecção no e-mail atual
bool g_spam_found_in_current_email = false;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
/* USER CODE BEGIN PFP */

// Função auxiliar para enviar strings via UART
void UART_Transmit_String(const char* str) {
    HAL_UART_Transmit(&huart2, (uint8_t*)str, strlen(str), UART_TX_TIMEOUT);
}

// Callback chamado quando uma palavra-chave de SPAM é encontrada
void on_spam_match_found(const char* pattern, int position)
{
    char buffer[128];
    int len = snprintf(buffer, sizeof(buffer), "    [!] Palavra de SPAM encontrada: '%s'\r\n", pattern);
    HAL_UART_Transmit(&huart2, (uint8_t*)buffer, len, UART_TX_TIMEOUT);

    // Marca o e-mail atual como SPAM
    g_spam_found_in_current_email = true;

    // Pisca o LED para indicar uma detecção
//    HAL_GPIO_TogglePin(LD2_GPIO_Port, LD2_Pin);
//    HAL_Delay(50);
//    HAL_GPIO_TogglePin(LD2_GPIO_Port, LD2_Pin);
}

// O retarget de printf foi removido
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* --- 1. INICIALIZAÇÃO DO HARDWARE E DO AUTÔMATO (EXECUTADO UMA VEZ) --- */
  HAL_Init();
  SystemClock_Config();
  MX_GPIO_Init();
  MX_USART2_UART_Init();

  // Uma pequena pausa para garantir que o terminal serial esteja pronto
  HAL_Delay(100);

  // Substituindo printf por UART_Transmit_String ou snprintf + HAL_UART_Transmit
  UART_Transmit_String("--- Filtro de SPAM Aho-Corasick STM32 ---\r\n");
  UART_Transmit_String("Inicializando e construindo base de dados de SPAM...\r\n\r\n");

  // Inicializa o autômato com o novo callback
  ac_init(&ac_spam_filter, on_spam_match_found);

  // Adiciona as palavras-chave de SPAM ao autômato
  for (int i = 0; i < NUM_SPAM_KEYWORDS; ++i) {
    ac_add_pattern(&ac_spam_filter, spam_keywords[i]);
  }

  // Constrói a máquina de estados Aho-Corasick. Agora ela está pronta.
  ac_build(&ac_spam_filter);
  UART_Transmit_String("Filtro pronto para analisar e-mails.\r\n");
  UART_Transmit_String("----------------------------------------\r\n\r\n");

  // Itera sobre a lista de e-mails, simulando a chegada de novas mensagens
  while(1) {
	  for (int i = 0; i < NUM_EMAILS; ++i) {
		  const Email* current_email = &email_inbox[i];
		  char buffer[256];
		  int len;

		  len = snprintf(buffer, sizeof(buffer), "Analisando E-mail %d de '%s'...\r\n", i + 1, current_email->from);
		  HAL_UART_Transmit(&huart2, (uint8_t*)buffer, len, UART_TX_TIMEOUT);

		  len = snprintf(buffer, sizeof(buffer), "  Assunto: %s\r\n", current_email->subject);
		  HAL_UART_Transmit(&huart2, (uint8_t*)buffer, len, UART_TX_TIMEOUT);

		  // Reseta o status de SPAM para o e-mail atual
		  g_spam_found_in_current_email = false;

		  // Executa a busca no assunto e no corpo do e-mail
		  ac_search(&ac_spam_filter, current_email->subject);
		  ac_search(&ac_spam_filter, current_email->body);

		  // Apresenta o veredito final para o e-mail
		  if (g_spam_found_in_current_email) {
			  UART_Transmit_String("  VEREDITO: E-mail classificado como SPAM.\r\n\r\n");
		  } else {
			  UART_Transmit_String("  VEREDITO: E-mail legitimo.\r\n\r\n");
		  }

		  HAL_Delay(5000);
	  }

	  UART_Transmit_String("----------------------------------------\r\n");
	  UART_Transmit_String("Todos os e-mails foram analisados. Reiniciando a demonstracao em 10s...\r\n");
	  UART_Transmit_String("----------------------------------------\r\n\r\n");
	  HAL_Delay(10000);
  }

}

/* O resto do arquivo (SystemClock_Config, etc.) permanece o mesmo */
// ...

/**
 * @brief System Clock Configuration
 * @retval None
 */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
   * in the RCC_OscInitTypeDef structure.
   */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL12;
  RCC_OscInitStruct.PLL.PREDIV = RCC_PREDIV_DIV1;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
   */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
 * @brief USART2 Initialization Function
 * @param None
 * @retval None
 */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 38400;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
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
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOF_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */
  /* Configure GPIO pin : LD2_Pin */
//  GPIO_InitStruct.Pin = LD2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
//  HAL_GPIO_Init(LD2_GPIO_Port, &GPIO_InitStruct);
  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
 * @brief  This function is executed in case of error occurrence.
 * @retval None
 */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef USE_FULL_ASSERT
/**
 * @brief  Reports the name of the source file and the source line number
 * where the assert_param error has occurred.
 * @param  file: pointer to the source file name
 * @param  line: assert_param error line source number
 * @retval None
 */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
