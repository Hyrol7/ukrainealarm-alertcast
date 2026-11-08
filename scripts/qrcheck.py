#!/usr/bin/env python3
# Розпізнавання QR-кодів, згенерованих тестом: QR_DIR=/tmp/qr go test -run QR . && python3 scripts/qrcheck.py /tmp/qr
# Потрібен opencv-python.
import cv2, glob, sys, os
d=sys.argv[1]; bad=0; n=0
det=cv2.QRCodeDetector()
for p in sorted(glob.glob(d+'/*.png')):
    want=open(p[:-4]+'.txt','rb').read().decode()
    got,_,_=det.detectAndDecode(cv2.imread(p))
    n+=1
    if got!=want: bad+=1; print('FAIL',os.path.basename(p),repr(got)[:60])
print(n,'checked',bad,'bad')
