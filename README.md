# Huawei_LTE_Manage
Huawei LTE Manager Pro v1.3.5 - TW Edition

華為 LTE 4G路由器的鎖頻工具 (台灣專用)

主要功能：

    1. 信號指標：
       顯示 RSRP (接收功率)、SINR (信噪比)、RSRQ (接收品質)，並根據台灣實測數據
       進行「極優/優/良/中/差」五級信號判定。

    2. 頻段鎖定：
       支援 B1/B3/B7/B8/B28 鎖定功能。透過監控 PCI 與鎖頻配合，可有效解決
       路由器在多個同頻基地台間頻繁切換導致的網路不穩定。

    3. 性能分析：
       整合 Speedtest 測速引擎, 顯示即時流量。

    4. 簡訊管理：
       簡訊讀取/刪除管理。



需求套件：
  
  huawei-lte-api==1.7.3
  
  speedtest-cli==2.1.3
  
pip install -r requirements.txt
