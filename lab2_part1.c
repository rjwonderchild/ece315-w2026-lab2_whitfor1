/*
 *	Lab 2: Part 2: UART in Polling Mode
 *
 *	ECE 315		: Computer Interfacing
 *  Created on	: July 27, 2021
 *  Author	: Shyama M. Gandhi, Mazen Elbaz
 *  Modified by : Antonio Andara
 *  Modified on	: January, 2026
 *  Modified on : February, 26, 2026
 *  Authors  : Riley Whitford, Komaldeep Taggar
 *     ------------------------------------------------------------------------------------------------------------------------------
 *
 *     This is the main file that uses "sha256.h" header file.
 *     The final objective is to finish the implementation of a hashing and verification system.
 *
 *     ------------------------------------------------------------------------------------------------------------------------------
 */
 
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "sha256.h"

#include "xuartps.h"
#include "xparameters.h"

#include <portmacro.h>
#include <projdefs.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <xil_io.h>
#include <xil_printf.h>

// ======================================================
// Configuration
// ======================================================
#define UART_BASEADDR 	XPAR_UART1_BASEADDR
#define RX_QUEUE_LEN     512
#define CMD_QUEUE_LEN     16
#define TX_QUEUE_LEN     512

#define INPUT_TEXT_LEN   256
#define HASH_HEX_LEN      64   // SHA-256 hex chars
#define HASH_LEN          32

#define POLL_DELAY_MS     1000

// ======================================================
// Types
// ======================================================
typedef enum {
  CMD_NONE,
  CMD_HASH = '1',
  CMD_VERIFY = '2',
} command_type_t;

typedef struct {
    command_type_t type;
    char input_text[INPUT_TEXT_LEN];
    char expected_hash[HASH_HEX_LEN + 1];  // used only for VERIFY
} crypto_request_t;


typedef struct {
    command_type_t type;
    char calculated_hash[HASH_HEX_LEN + 1];
    u8 match;   // 0 = false, 1 = true
} crypto_result_t;


// ======================================================
// FreeRTOS objects
// ======================================================
static QueueHandle_t q_rx_byte = NULL;   // uint8_t
static QueueHandle_t q_cmd     = NULL;   // crypto_request_t
static QueueHandle_t q_result  = NULL;   // crypto_result_t
static QueueHandle_t q_tx      = NULL;   // char

// ======================================================
// UART instance
// ======================================================
static XUartPs UartPs;

// ======================================================
// Task prototypes
// ======================================================
static void UART_RX_Task(void *pvParameters);
static void CLI_Task(void *pvParameters);
static void Crypto_Task(void *pvParameters);
static void UART_TX_Task(void *pvParameters);


// ======================================================
// Crypto helpers
// ======================================================
void hash_to_string(BYTE *hash, char *hashString);
void sha256_string(const char* input, BYTE output[32]);


// ======================================================
// UART helpers
// ======================================================
uint8_t receive_byte(uint8_t *out_byte);
void receive_string(char *buf, size_t buf_len);
static void uart_init(void);
static int uart_poll_rx(uint8_t *b);
static void uart_tx_byte(uint8_t b);


// ======================================================
// Custom UART functions
// ======================================================
void print_string(const char *str);
void print_new_lines(int count);
void flush_uart(void);

const char *init_message =
	"A hash function is a mathematical algorithm that takes an input (or \"message\")\n"
	"and returns a fixed-size string of bytes. The output, often called the hash\n"
	"value or hash code, is unique (within reason) to the given input. In this lab,\n"
	"we use the sha256 algorithm to compute the hash of a given string or to verify\n"
	"a signature.\n";


// ======================================================
// main()
// ======================================================

int main(void)
{

  uart_init();

  xTaskCreate(UART_RX_Task,
                "UART_RX",
                1024, 
                NULL, 
                3, 
                NULL);

  xTaskCreate(UART_TX_Task, 
                "UART_TX", 
                1024, 
                NULL, 
                3, 
                NULL);

  xTaskCreate(CLI_Task, 
                "CLI",     
                2048, 
                init_message, 
                2, 
                NULL);

  xTaskCreate(Crypto_Task,  
                "CRYPTO",  
                2048, 
                NULL, 
                2, 
                NULL);
  
  q_rx_byte = xQueueCreate(RX_QUEUE_LEN, sizeof(uint8_t));
  q_cmd     = xQueueCreate(CMD_QUEUE_LEN, sizeof(crypto_request_t));
  q_result  = xQueueCreate(CMD_QUEUE_LEN, sizeof(crypto_result_t)); 
  q_tx      = xQueueCreate(TX_QUEUE_LEN, sizeof(uint8_t));
  
  configASSERT(UART_RX_Task);
  configASSERT(UART_TX_Task);
  configASSERT(CLI_Task);
  configASSERT(Crypto_Task);
  configASSERT(q_rx_byte);
  configASSERT(q_cmd);
  configASSERT(q_result);
  configASSERT(q_tx);

  print_new_lines(50);
  xil_printf("Initialization complete\nSTARTING APP\n");

  vTaskStartScheduler();

  while (1) {}
}

// ======================================================
// UART RX Task
// ======================================================

static void UART_RX_Task(void *pvParameters)
{

  uint8_t byte;

  for (;;){
    if (uart_poll_rx(&byte)){
      xQueueSend(q_rx_byte, &byte, 0);
    }
    vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
  }
}

// ======================================================
// UART TX Task
// ======================================================

static void UART_TX_Task(void *pvParameters)
{

  char c;

  for (;;){
    if (xQueueReceive(q_tx, &c, 0) == pdTRUE){
      uart_tx_byte((uint8_t)c);
    }
    vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
  }
}


// ======================================================
// CLI Task
// ======================================================

static void CLI_Task(void *pvParameters)
{
    command_type_t op = CMD_NONE;
    crypto_request_t req;
    crypto_result_t  res;

    uint8_t dummy;

    xil_printf((const char *)pvParameters);

    for (;;){
        xil_printf("\n*******************************************\n");
        xil_printf("Menu:\n1. Hash a string\n2. Verify hash of a given string\n");
        xil_printf("\nEnter your option: ");

        receive_byte((uint8_t *)&op);

        xil_printf("\n*******************************************\n");

        switch (op){
            case CMD_HASH:
                req.type = CMD_HASH;
                xil_printf("\nEnter string to calculate hash: ");
                receive_string(req.input_text, sizeof(req.input_text));
                xQueueSend(q_cmd, &req, 0);
                /* Polling queue for result */
                while (xQueueReceive(q_result, &res, 0) != pdTRUE){
                    vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
                }
                xil_printf("\nCalculated hash: ");
                xil_printf(res.calculated_hash);
                xil_printf("\n");
                break;

            case CMD_VERIFY:
                req.type = CMD_VERIFY;
                xil_printf("\nEnter string to verify: ");
                receive_string(req.input_text, sizeof(req.input_text));

                xil_printf("\nEnter the precomputed hash: ");
                receive_string(req.expected_hash, sizeof(req.expected_hash));

                xQueueSend(q_cmd, &req, 0);

                /* Wait (polling) for result */
                while (xQueueReceive(q_result, &res, 0) != pdTRUE){
                    vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
                }

                xil_printf("\nCalculated hash: ");
                xil_printf(res.calculated_hash);
                xil_printf("\nExpected hash: ");
                xil_printf(req.expected_hash);

                if (res.match){
                    xil_printf("\nHashes are the same!\n");
				} else {
                    xil_printf("\nHashes are different\n");
				}
                break;

            default:
                xil_printf("\nOption not recognized\n");
                break;
        }
		
        vTaskDelay(pdMS_TO_TICKS(1000));
        xil_printf("\nPress any key to continue.");
        receive_byte(&dummy);
        vTaskDelay(pdMS_TO_TICKS(1000));
        flush_uart();
        print_new_lines(50);
    }
}


// ======================================================
// Crypto Task
// ======================================================

static void Crypto_Task(void *pvParameters)
{
    crypto_request_t req;
    crypto_result_t  res;

    unsigned char hash[HASH_LEN];

    for (;;){
        if (xQueueReceive(q_cmd, &req, 0) == pdTRUE){
            sha256_string(req.input_text, hash);
            hash_to_string(hash, res.calculated_hash);

            res.type = req.type;
            res.match = 0;

            if (req.type == CMD_VERIFY){
                if (strcmp(res.calculated_hash, req.expected_hash) == 0){
                    res.match = 1;
                }
            }

            xQueueSend(q_result, &res, 0);
        }
		
        vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
    }
}


uint8_t receive_byte(uint8_t *out_byte)
{
    while(1){
        if (xQueueReceive(q_rx_byte, out_byte, 0)!=pdTRUE){            
            vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
        } else {
            return *out_byte;
        }
    }
}


void receive_string(char *buf, size_t buf_len)
{
    uint8_t recvd;
    size_t idx = 0;
    buf[0] = '\0';

    while (1){
		xQueueReceive(q_rx_byte, &recvd, 0);
        if (idx < buf_len-1) {
            if (recvd != '\r') {
             buf[idx++] = recvd;
        } else {
            return;
        }
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
    }
}


void flush_uart(void)
{
    uint8_t dummy;    
    while (xQueueReceive(q_rx_byte, &dummy, 0) == pdTRUE);
}


void print_string(const char *str)
{

}

void print_new_lines(int count)
{
    for (int i = 0; i < count; i++){
        xil_printf("\n");
    }
}


void hash_to_string(BYTE *hash, char *hash_string)
{
    for (int i = 0; i < HASH_LEN; i++){
        sprintf(&hash_string[i * 2], "%02X", hash[i]);
    }

    hash_string[HASH_LEN * 2] = '\0'; // Null terminate the string
}

void sha256_string(const char* input, BYTE output[32])
{
    SHA256_CTX ctx;
    sha256Init(&ctx);
    sha256Update(&ctx, (BYTE*)input, strlen(input));
    sha256Final(&ctx, output);
}


static void uart_init(void)
{
  XUartPs_Config *cfg;

  cfg = XUartPs_LookupConfig(UART_BASEADDR);
  if (!cfg){
    while (1) {}
  }

  if (XUartPs_CfgInitialize(&UartPs, cfg, cfg->BaseAddress) != XST_SUCCESS){
    while (1) {}
  }

  XUartPs_SetBaudRate(&UartPs, 115200);
}


static int uart_poll_rx(uint8_t *b)
{
  if (XUartPs_IsReceiveData(UartPs.Config.BaseAddress)){
    *b = XUartPs_ReadReg(UartPs.Config.BaseAddress, XUARTPS_FIFO_OFFSET);
    return 1;
  }
  return 0;
}

static void uart_tx_byte(uint8_t b)
{
  while (XUartPs_IsTransmitFull(UartPs.Config.BaseAddress)){

  }
  
  XUartPs_WriteReg(UartPs.Config.BaseAddress, XUARTPS_FIFO_OFFSET, b);
}
