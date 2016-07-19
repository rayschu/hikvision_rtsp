# hikvision_rtsp
Use this script to check the HiKVision's RTSP is vulnerable or not.
You neet to scann the tcp port 554 and save it as ip.txt file first, maybe you will like masscan?
$masscan -p 554 0.0.0.0/0 >> ip_554.txt
$cat ip_554.txt | awk '{print $6}' >> ip.txt
$./hikvision.py
