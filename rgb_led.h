#ifndef RGB_LED_H
#define RGB_LED_H

/* ================= RGB LED Colors ================= */
#define RGB_OFF     0b000
#define RGB_RED     0b100
#define RGB_GREEN   0b010
#define RGB_BLUE    0b001
#define RGB_YELLOW  0b110  // Red + Green
#define RGB_CYAN    0b011  // Green + Blue
#define RGB_MAGENTA 0b101  // Red + Blue
#define RGB_WHITE   0b111

/* ================= Device Configuration ================= */
#define RGB_LED_BASEADDR XPAR_GPIO_LEDS_BASEADDR
#define RGB_CHANNEL   2


#endif /* RGB_LED_H */
