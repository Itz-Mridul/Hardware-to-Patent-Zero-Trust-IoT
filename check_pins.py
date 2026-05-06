import os
import glob
for p in glob.glob("/Users/itz-mridul/Library/Arduino15/packages/esp32/hardware/esp32/*/variants/*/pins_arduino.h"):
    if 'esp32cam' in p or 'ai32' in p or 'thinker' in p:
        print("--- File:", p)
        with open(p, 'r') as f:
            for line in f:
                if 'SS' in line or 'SCK' in line or 'MISO' in line or 'MOSI' in line:
                    print(line.strip())
