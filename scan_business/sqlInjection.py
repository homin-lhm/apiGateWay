from apiScanServer.main import DIR
from copy import deepcopy
import requests


def sql_injection_scan(method, url, headers=None, data=None, data_type=None):
    if data is None:
        return []
    with open(file=DIR + '\\scan_business\\sqlInjectDb.txt', mode='r', encoding='utf-8') as f:
        attack_f = f.readlines()
    with open(file=DIR + '\\scan_business\\api_checkDB.txt', mode='r', encoding='utf-8') as f2:
        check_list = f2.readlines()

    data = deepcopy(data)
    fail_data = []
    # 遍历每一个字段
    for k in data.keys():
        # 遍历每一个攻击语句
        for attack in attack_f:
            data[k] = attack
            # 接口参数篡改好后，发起请求
            if data_type == 'params':
                res = requests.request(method=method, url=url, params=data, headers=headers)
            else:
                res = requests.request(method=method, url=url, json=data, headers=headers)
            # 接口结果分析
            for i in check_list:
                if i in res.text:
                    fail_data.append(
                        {"attack": attack, "scan_key": k, "status_code": res.status_code, "res": res.text})
    return fail_data


if __name__ == '__main__':
    print(DIR)
