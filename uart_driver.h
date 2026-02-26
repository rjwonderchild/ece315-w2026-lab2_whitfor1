/*
 * uart_driver.h
 *
 * Created on: July 27, 2021
 * Author: Shyama M. Gandhi
 * Modified by : Antonio Andara
 * Modified on : January 24, 2023
 */

#ifndef UART_DRIVER_H_
#define UART_DRIVER_H_

#include "xil_io.h"
#include "xuartps.h" // UART definitions header file
#include "xscugic.h" // Interrupt controller header file
#include "xparameters.h"

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

// Macros
#define INTC               	XScuGic
#define UART_DEVICE_ID     	0
#define INTC_DEVICE_ID     	0
#define UART_INT_IRQ_ID    	82
#define UART_BASEADDR       XPAR_UART1_BASEADDR
#define UART_FIFO_OFFSET    XUARTPS_FIFO_OFFSET
#define UART_RX_BUFFER_SIZE 3U
#define RECEIVED_DATA       XUARTPS_EVENT_RECV_DATA
#define SENT_DATA           XUARTPS_EVENT_SENT_DATA
#define SIZE_OF_QUEUE      	100

#define SEND_TO_QUEUE 0
#define SEND_DIRECT   1

// External variable declarations
extern XUartPs UART;
extern XUartPs_Config *Config;
extern INTC InterruptController;
extern u32 IntrMask;

// Queues
extern QueueHandle_t xTxQueue;
extern QueueHandle_t xRxQueue;

// Interrupt counters
extern int countRxIrq;
extern int countTxIrq;
extern int countSent;
extern int byteCount;

// Function prototypes
void interruptHandler(void *CallBackRef, u32 Event, unsigned int EventData);
void handleReceiveEvent();
void handleSentEvent();
void transmitDataFromQueue(u8 *data, BaseType_t *taskToSwitch);
void disableTxEmpty();
void enableTxEmpty();
int initializeUART(void);
int setupInterruptSystem(INTC *IntcInstancePtr, XUartPs *UartInstancePtr, u16 UartIntrId);
BaseType_t myReceiveData(void);
u8 myReceiveByte(void);
BaseType_t myTransmitFull(void);
void mySendByte(u8 Data);
void mySendString(const char *pString);

#endif /* SRC_UART_DRIVER_H_ */
