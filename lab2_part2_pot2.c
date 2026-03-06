/*
 *	Lab 2: Part 2: UART in Polling Mode
 *
 *	ECE 315		: Computer Interfacing
 *  Created on	: July 27, 2021
 *  Author	: Shyama M. Gandhi, Mazen Elbaz
 *  Modified by : Antonio Andara
 *  Modified on	: January, 2026
 *  Authors : Riley Whitford (whitfor1), Komaldeep Tagger (ktaggar)
 *  Modified on : March 4, 2026
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
#include <FreeRTOSConfig.h>

#include "xuartps.h"
#include "xparameters.h"

#include <portmacro.h>
#include <projdefs.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Include xilinx Libraries
#include <xparameters.h>
#include <xgpio.h>
#include <xscugic.h>
#include <xil_exception.h>
#include <xil_printf.h>
#include <sleep.h>
#include <xil_cache.h>
#include <xil_io.h>

// Other miscellaneous libraries
#include "pmodkypd.h"
#include "rgb_led.h"

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

// Device ID declarations
#define KYPD_DEVICE_ID   	XPAR_GPIO_KYPD_BASEADDR
#define SSD_DEVICE_ID       XPAR_GPIO_SSD_BASEADDR
#define LEDS_DEVICE_ID      XPAR_GPIO_LEDS_BASEADDR
#define PUSH_DEVICE_ID      XPAR_GPIO_INPUTS_BASEADDR

// keypad key table
#define DEFAULT_KEYTABLE 	"0FED789C456B123A"

// Declaring devices
PmodKYPD 	KYPDInst;
XGpio       SSDInst;
XGpio       rgbLedInst;
XGpio       pushInst;

// ======================================================
// Types
// ======================================================
typedef enum {
  CMD_NONE,
  CMD_HASH = '1',
  CMD_VERIFY = '2',
  CMD_KBD_SSD = '3',
  CMD_KBD_RGB = '4'
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

// GPIO structs

typedef struct {
    u8 current;
    u8 previous;
} key_t;

typedef struct {
    TickType_t xOn;
    TickType_t xPeriod;
    uint8_t COLOUR;
} duty_t;

// ======================================================
// FreeRTOS objects
// ======================================================
static QueueHandle_t q_rx_byte = NULL;   // uint8_t
static QueueHandle_t q_cmd     = NULL;   // crypto_request_t
static QueueHandle_t q_result  = NULL;   // crypto_result_t
static QueueHandle_t q_tx      = NULL;   // char
static QueueHandle_t xkey2display = NULL; // key_t
static QueueHandle_t xbtn2rgb = NULL; // duty_ty

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

// GPIO Prototypes
void InitializeKeypad();
static void vKeypadTask( void *pvParameters );
static void vRgbTask(void *pvParameters);   
static void vButtonsTask(void *pvParameters);
static void vDisplayTask(void *pvParameters);
u32 SSD_decode(u8 key_value, u8 cathode);
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
void getHex();
int hexChk(char c);

const char *init_message =
	"A hash function is a mathematical algorithm that takes an input (or \"message\")\n"
	"and returns a fixed-size string of bytes. The output, often called the hash\n"
	"value or hash code, is unique (within reason) to the given input. In this lab,\n"
	"we use the sha256 algorithm to compute the hash of a given string or to verify\n"
	"a signature.\n";

//
volatile int g_ssd_source_uart = 0;
volatile int g_rgb_source_uart = 0;


// ======================================================
// main()
// ======================================================

int main(void)
{
  int status;
  uart_init();
  InitializeKeypad();

  q_rx_byte = xQueueCreate(RX_QUEUE_LEN, sizeof(uint8_t));
  q_cmd     = xQueueCreate(CMD_QUEUE_LEN, sizeof(crypto_request_t));
  q_result  = xQueueCreate(CMD_QUEUE_LEN, sizeof(crypto_result_t)); 
  q_tx      = xQueueCreate(TX_QUEUE_LEN, sizeof(uint8_t));
  xkey2display = xQueueCreate(1, sizeof(key_t));
        if(xkey2display == NULL) {
            xil_printf("Failed to create key to display queue.\r\n");
            return XST_FAILURE;
        }
  xbtn2rgb = xQueueCreate(1, sizeof(duty_t));
        if(xbtn2rgb == NULL) {
            xil_printf("Failed to create button to rgb queue.\r\n");
            return XST_FAILURE;
        }

  status = XGpio_Initialize(&SSDInst, SSD_DEVICE_ID);
        if (status != XST_SUCCESS) {
            xil_printf("GPIO Initialization for SSD failed.\r\n");
            return XST_FAILURE;
        }
  XGpio_SetDataDirection(&SSDInst, 1, 0x00);

  status = XGpio_Initialize(&rgbLedInst, LEDS_DEVICE_ID);
    if (status != XST_SUCCESS) {
        xil_printf("GPIO Initialization for RGB LED failed.\r\n");
        return XST_FAILURE;
    }

  XGpio_SetDataDirection(&rgbLedInst, 1, 0x00);

  status = XGpio_Initialize(&pushInst, PUSH_DEVICE_ID);
    if (status != XST_SUCCESS) {
        xil_printf("GPIO Initialization for Push Button failed.\r\n");
        return XST_FAILURE;
    }

  XGpio_SetDataDirection(&pushInst, 1, 0xFF);

  xTaskCreate(vKeypadTask,					
			"keypad task", 				
			configMINIMAL_STACK_SIZE, 	
			NULL, 						
			tskIDLE_PRIORITY,			
			NULL);


  xTaskCreate(vRgbTask,
            "rgb task",
            configMINIMAL_STACK_SIZE,
            NULL,
            tskIDLE_PRIORITY,
            NULL);

  xTaskCreate(vDisplayTask,
             "display task",
            configMINIMAL_STACK_SIZE,
            NULL,
            tskIDLE_PRIORITY,
            NULL);

  xTaskCreate(vButtonsTask,
            "button task",
            configMINIMAL_STACK_SIZE,
            NULL,
            tskIDLE_PRIORITY,
            NULL);



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
  

  configASSERT(UART_RX_Task);
  configASSERT(UART_TX_Task);
  configASSERT(CLI_Task);
  configASSERT(Crypto_Task);
  configASSERT(q_rx_byte);
  configASSERT(q_cmd);
  configASSERT(q_result);
  configASSERT(q_tx);

  print_new_lines(50);
  print_string("Initialization complete\nSTARTING APP\n");

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
    vTaskDelay(pdMS_TO_TICKS(5));
  }
}

// ======================================================
// UART TX Task
// ======================================================

static void UART_TX_Task(void *pvParameters)
{

  char c;

  for (;;){
    if (xQueueReceive(q_tx, &c, pdMS_TO_TICKS(50)) == pdTRUE){
      uart_tx_byte((uint8_t)c);

      while (xQueueReceive(q_tx, &c, 0) == pdTRUE)
        uart_tx_byte(c);
    }
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

    print_string((const char *)pvParameters);

    for (;;){
        print_string("\n*******************************************\n");
        print_string("Menu:\n1. Hash a string\n2. Verify hash of a given string\n3. SSD Display\n4. LED Control\n");
        print_string("\nEnter your option: ");

        receive_byte((uint8_t *)&op);

        print_string("\n*******************************************\n");

        switch (op){
            case CMD_HASH:
                req.type = CMD_HASH;
                print_string("\nEnter string to calculate hash: ");
                receive_string(req.input_text, sizeof(req.input_text));
                xQueueSend(q_cmd, &req, 0);
                /* Polling queue for result */
                while (xQueueReceive(q_result, &res, 0) != pdTRUE){
                    vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
                }
                print_string("\nCalculated hash: ");
                print_string(res.calculated_hash);
                print_string("\n");
                break;

            case CMD_VERIFY:
                req.type = CMD_VERIFY;
                print_string("\nEnter string to verify: ");
                receive_string(req.input_text, sizeof(req.input_text));

                print_string("\nEnter the precomputed hash: ");
                receive_string(req.expected_hash, sizeof(req.expected_hash));

                xQueueSend(q_cmd, &req, 0);

                /* Wait (polling) for result */
                while (xQueueReceive(q_result, &res, 0) != pdTRUE){
                    vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
                }

                print_string("\nCalculated hash: ");
                print_string(res.calculated_hash);
                print_string("\nExpected hash: ");
                print_string(req.expected_hash);

                if (res.match){
                    print_string("\nHashes are the same!\n");
				} else {
                    print_string("\nHashes are different\n");
				}
                break;

            case CMD_KBD_SSD:
                print_string("Keyboard to SSD Active. Please input a hex valid key; 0-9, a-f, or A-F.\n");
                print_string("Enter q to quit.\n");
                print_string("Enter command: \n");

                getHex();

                break;
            
            case CMD_KBD_RGB:
                print_string("Keyboard to RGB Active. Please input one of the following options.\n");
                print_string("Select either a colour, or change the brightness of the LED.\n");
                print_string("Select:\n1. Red\n2. Green\n3. Blue\n4. Yellow\n5. Cyan\n6. Magenta\n7. White\n");
                print_string("Brightness Controls: + to increase, - to decrease.\n");
                print_string("Enter Command: ");

                break;

            default:
                print_string("\nOption not recognized\n");
                break;
        }
		
        vTaskDelay(pdMS_TO_TICKS(1000));
        print_string("\nPress any key to continue.");
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

// ======================================================
// Keypad Task
// ======================================================

static void vKeypadTask( void *pvParameters )
{
	key_t txKey;
    u16 keystate;
	XStatus status, previous_status = KYPD_NO_KEY;
	u8 new_key, current_key = 'x', previous_key = 'x';
    const TickType_t debounceDelay = 25;

    //xil_printf("Pmod KYPD app started. Press any key on the Keypad.\r\n");
	while (1){
		// Capture state of the keypad
		keystate = KYPD_getKeyStates(&KYPDInst);

		// Determine which single key is pressed, if any
		// if a key is pressed, store the value of the new key in new_key
		status = KYPD_getKeyPressed(&KYPDInst, keystate, &new_key);

        vTaskDelay(debounceDelay);

		// Print key detect if a new key is pressed or if status has changed
		if (status == KYPD_SINGLE_KEY && previous_status == KYPD_NO_KEY){
			//xil_printf("Key Pressed: %c\r\n", (char) new_key);

/*************************** Enter your code here ****************************/
			// TODO: update value of previous_key and current_key

            previous_key = current_key;

            current_key = new_key;

/*****************************************************************************/
		} else if (status == KYPD_MULTI_KEY && status != previous_status){
			//xil_printf("Error: Multiple keys pressed\r\n");
		}

/*************************** Enter your code here ****************************/
		// TODO: display the value of `status` each time it changes

        if (status != previous_status) {
           //xil_printf("Status changed: %d\r\n", status);
        }

/*****************************************************************************/

		previous_status = status;

        txKey.previous = previous_key;
        txKey.current = current_key;

        if (!g_ssd_source_uart) {
            xQueueOverwrite(xkey2display, &txKey);
        }

/*****************************************************************************/
	}
}

// ======================================================
// Display Task
// ======================================================

static void vDisplayTask(void *pvParameters) 
{
    u32 ssd_value=0;
    const TickType_t xDelay = pdMS_TO_TICKS(12);
    // 10 works, 15 has slight flickering, 12 seems to have no flickering.
    key_t rxKey;
    key_t currentKey = {'x', 'x'};

    while (1) 
    {
        if (xQueueReceive(xkey2display, &rxKey, 0) == pdPASS) 
            {
                currentKey = rxKey;
            }

            ssd_value = SSD_decode(currentKey.current, 1);
            XGpio_DiscreteWrite(&SSDInst, 1, ssd_value);
            vTaskDelay(xDelay);

            ssd_value = SSD_decode(currentKey.previous, 0);
            XGpio_DiscreteWrite(&SSDInst, 1, ssd_value);
            vTaskDelay(xDelay);
    }
}

// ======================================================
// Button Task
// ======================================================

static void vButtonsTask(void *pvParameters)
{

const TickType_t xBtnDelay  = pdMS_TO_TICKS(150);
duty_t txBtn;
txBtn.xPeriod = 10;
txBtn.xOn = 5;

while (1)
    {
         // Button input
        int readPush = XGpio_DiscreteRead(&pushInst, 1);
    
        // Increase brightness (was previously increase delay)
        if (readPush == 8 && txBtn.xOn <= (txBtn.xPeriod - 1)) 
        {
            txBtn.xOn++;
            //xil_printf("Brightness: %d%%\r\n", ((txBtn.xOn * 100) / txBtn.xPeriod));
            vTaskDelay(xBtnDelay);

        // Decrease brightness (was previously decrease delay)
        } else if (readPush == 1 && txBtn.xOn > 0) {
            txBtn.xOn--;
            //xil_printf("Brightness: %d%%\r\n", ((txBtn.xOn * 100) / txBtn.xPeriod));
            vTaskDelay(xBtnDelay);
        }
        
        if (!g_rgb_source_uart) {
            xQueueOverwrite(xbtn2rgb, &txBtn);
        }
    }
}

// ======================================================
// RGB Task
// ======================================================

static void vRgbTask(void *pvParameters)
{
    uint8_t color = RGB_CYAN;
	TickType_t xOff;
    duty_t rxBtn;
    
    while (1){


        if (xQueueReceive(xbtn2rgb, &rxBtn, 0) == pdPASS) {

            xOff = rxBtn.xPeriod - rxBtn.xOn;

            if (rxBtn.xOn == 0) {
                // LED is OFF here
                XGpio_DiscreteWrite(&rgbLedInst, RGB_CHANNEL, 0);
                vTaskDelay(xOff);
            } else {
                // LED is ON here
                XGpio_DiscreteWrite(&rgbLedInst, RGB_CHANNEL, color);
                vTaskDelay(rxBtn.xOn);
                // LED is OFF here
                XGpio_DiscreteWrite(&rgbLedInst, RGB_CHANNEL, 0);
                vTaskDelay(xOff);
            }
        }
    }

}

void InitializeKeypad()
{
	KYPD_begin(&KYPDInst, KYPD_DEVICE_ID);
	KYPD_loadKeyTable(&KYPDInst, (u8*) DEFAULT_KEYTABLE);
}

// This function is hard coded to translate key value codes to their binary representation
u32 SSD_decode(u8 key_value, u8 cathode)
{
    u32 result;

	// key_value represents the code of the pressed key
	switch(key_value){ // Handles the coding of the 7-seg display
		case 48: result = 0b00111111; break; // 0
        case 49: result = 0b00110000; break; // 1
        case 50: result = 0b01011011; break; // 2
        case 51: result = 0b01111001; break; // 3
        case 52: result = 0b01110100; break; // 4
        case 53: result = 0b01101101; break; // 5
        case 54: result = 0b01101111; break; // 6
        case 55: result = 0b00111000; break; // 7
        case 56: result = 0b01111111; break; // 8
        case 57: result = 0b01111100; break; // 9
        case 65: result = 0b01111110; break; // A
        case 66: result = 0b01100111; break; // B
        case 67: result = 0b00001111; break; // C
        case 68: result = 0b01110011; break; // D
        case 69: result = 0b01001111; break; // E
        case 70: result = 0b01001110; break; // F
        default: result = 0b00000000; break; // default case - all seven segments are OFF
    }

	// cathode handles which display is active (left or right)
	// by setting the MSB to 1 or 0
    if(cathode==0){
            return result;
    } else {
            return result | 0b10000000;
	}
}

// ======================================================
// UART SSD TASK
// ======================================================

int hexChk(char c) 
{
    if ((c >= '0' && c<= '9') ||
        (c >= 'a' && c<= 'f') ||
        (c >= 'A' && c<= 'F'))
        {
            return 1;
        }

        return 0;
}

void getHex()
{
    uint8_t c;
    key_t txKey;
    g_ssd_source_uart = 1;

    txKey.previous = 'x';
    txKey.current = 'x';

    
    while (1)
    {
        receive_byte(&c);

        if (c == '\r' || c == '\n')
            continue;

        if (c == 'q' || c == 'Q')
        {
            g_ssd_source_uart = 0;
            print_string("\nExiting keyboard mode\n");
            return;
        }

        if (hexChk(c))
        {
            if (c >= 'a' && c <= 'f')
                c -= 32;

            txKey.previous = txKey.current;
            txKey.current = c;

            xQueueOverwrite(xkey2display, &txKey);

            print_string("\nDisplaying: ");
            char out = c;
            xQueueSend(q_tx, &out, 0);
            print_string("\n");

        }
        else 
        {
            print_string("\nInvalid hex key\n");
        }
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

    if (buf_len == 0) 
        return;

    while (1){
		if (xQueueReceive(q_rx_byte, &recvd, pdMS_TO_TICKS(50)) == pdTRUE) {

            if (recvd == '\n'){
                continue;
            }

            if (recvd == '\r') {
                buf[idx] = '\0';
                return;
            }

            if (idx < buf_len - 1) {
                buf[idx++] = recvd;
                buf[idx] = '\0';
            }
        } else {
            vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
        }
    }
}


void flush_uart(void)
{
    uint8_t dummy;    
    while (xQueueReceive(q_rx_byte, &dummy, 0) == pdTRUE);
}


void print_string(const char *str)
{
    if (str == NULL) {
        return;
    }

    while (*str != '\0') {
        uint8_t c = (uint8_t)*str++;

        xQueueSend(q_tx, &c, pdMS_TO_TICKS(50));
    }

}

void print_new_lines(int count)
{
    for (int i = 0; i < count; i++){
        print_string("\n");
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
