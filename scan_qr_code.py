import sensor,lcd,time,ubinascii,ucryptolib,uhashlib,machine,
from machine import PWM,Timer
from maix import GPIO
from fpioa_manager import fm


aesKey = "11451411451411451411451411451444".encode()
aesIV  = "1145141145144444".encode()
tim = Timer(Timer.TIMER0,Timer.CHANNEL0, mode=Timer.MODE_PWM)
beep = PWM(tim, freq=1000, duty=50, pin=9, enable=False)
expireTime = 60

fm.register(8,fm.fpioa.GPIOHS0, force=True)
sw = GPIO(GPIO.GPIOHS0, GPIO.OUT)
sw.value(0)

sensor.reset()
sensor.set_pixformat(sensor.GRAYSCALE)
sensor.set_framesize(sensor.QVGA)
sensor.set_vflip(1)    
sensor.skip_frames(30)
sensor.set_auto_gain(False)
lcd.init()

while True:
    sw.value(0)
    while True:
    #二维码检测与识别
        img = sensor.snapshot()
        res = img.find_qrcodes() #寻找二维码

        if len(res) > 0: #在图片和终端显示二维码信息
            img.draw_rectangle(res[0].rect())
            img.draw_string(2,2, res[0].payload(), color=(0,128,0), scale=2)
            cipherBase64Str = res[0].payload()#获得内容
            break   

        lcd.display(img)
        time.sleep_ms(50)

    print(cipherBase64Str)
    #开始解码与验证
    #Base64 decode
    cipherBytes = ubinascii.a2b_base64(cipherBase64Str)

    aes128 = ucryptolib.aes(aesKey, ucryptolib.MODE_CBC, aesIV)
    contentBytes = aes128.decrypt(cipherBytes)

    contentStr = contentBytes.decode()
    #print("Content:-",contentStr,"-")

    if contentStr.count(";") != 2:
        print("[!]Format unmatch")
        continue
    p = contentStr.rfind(";")
    
    

    payloadStr = contentStr[0:p]
    payloadBytes = payloadStr.encode()
    shaTargetStr = contentStr[p+1:]

    shaCalcBytes = uhashlib.sha256(payloadBytes).digest()
    shaHexStr = ubinascii.hexlify(shaCalcBytes).decode()

    if shaTargetStr.lower()[0:12] == shaHexStr[0:12]:
        p = payloadStr.rfind(";")
        if p == -1:
            print("[!]No ; found")
            continue
        timeGotStr = payloadStr[p+1:]
        if timeGotStr.isdigit():
            timeInt = int(timeGotStr)
            if timeInt > time.time():
                time.set_time(time.localtime(timeInt))
                print(time.localtime())
            elif (time.time()-timeInt) > expireTime:
                print("[!]QRCode expired")
                continue
        else:
            print("[!]Not digital:-",timeGotStr,"-")
            continue

        #Do the Job, Open the door
        sw.value(1)
        print("[*]Successfully Authenticated.","Code:",payloadStr)
        beep.enable()
        time.sleep_ms(500)
        beep.disable()
        sw.value(0)
        
        continue
    else:
        sw.value(0)
        print("[!]SHA UNMATCH, DROP.")
        print(type(shaTargetStr.lower()))
        print(shaTargetStr.lower())
        print(type(shaHexStr[0:12]))
        print(shaHexStr[0:12])
        
        continue



