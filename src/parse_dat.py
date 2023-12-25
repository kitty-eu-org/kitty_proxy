import v2ray.config_pb2 as config_pb2

def read_geoip_dat(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    geolist = config_pb2.GeoIPList()
    geolist.ParseFromString(data)

    for geoip in geolist.entry:
        country_code = geoip.country_code
        if country_code.lower() == "CN".lower():
            # print(country_code)
            # print(geoip.cidr)
            # for cidr in geoip.cidr:
            #     print(cidr)
            for cidr in geoip.cidr:
                # print(cidr)
                network = cidr.ip
                prefix = cidr.prefix
                print("network: ", network)
                print(prefix)
            # 在这里处理解析得到的数据

# 读取并解析 geoip.dat 文件
read_geoip_dat('/home/hezhaozhao/opensource/kitty/src-tauri/binaries/geoip.dat')