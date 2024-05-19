from flask import Flask, request, jsonify
from jsonschema import validate
import requests
import time
import json
import jsonschema
from threading import Thread
from scan_business.sqlInjection import sql_injection_scan
import redis

app = Flask(__name__)

redis_conn = redis.Redis(
    host="127.0.0.1",
    port=6379,
    db=14,
    password="3558hominT."
)

api_scan_schema = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "maxLength": 50},
        "method": {"type": "string", "maxLength": 5},
        "headers": {"type": "object"},
        "json": {"type": "object"},
        "params": {"type": "object"},
    },
    "required": ["url", "method"]
}


# 单接口扫描
@app.route('/scan', methods=['POST'])
def api_scan():
    # 入参协议校验
    try:
        validate(instance=request.json, schema=api_scan_schema)
    except jsonschema.exceptions.ValidationError as err:
        print(f'{request.remote_addr} request json error, err msg: {err}!')
        return jsonify({"scan_id": None, "scan_status": False}), 400

    # 生成scan_id
    create_scan_id = str(int(time.time() * 1000)) + '_id'

    # 基准测试
    if 'params' in request.json.keys():
        data_type = 'params'
        re_data = request.json['params']
        res = requests.request(method=request.json['method'], url=request.json['url'], headers=request.json['headers'],
                               params=request.json['params'])
    elif 'json' in request.json.keys():
        data_type = 'json'
        re_data = request.json['json']
        res = requests.request(method=request.json['method'], url=request.json['url'], headers=request.json['headers'],
                               json=request.json['json'])
    else:
        data_type = None
        re_data = None
        res = requests.request(method=request.json['method'], url=request.json['url'], headers=request.json['headers'])
    if res.status_code != 200:
        return jsonify({"scan_id": create_scan_id, "scan_status": False}), 403

    # 执行扫描策略
    def scan(scan_id, method, url, headers, data, data_type):
        all_scan_res = []
        # sql注入扫描
        all_scan_res.append(sql_injection_scan(method=method, url=url,
                                               headers=headers,
                                               data=data, data_type=data_type))
        # xss扫描

        # headers必填字段校验

        # 扫描完成后
        redis_conn.set(f'scan_id:{scan_id}', json.dumps(all_scan_res), ex=3600 * 24)

    t = Thread(target=scan, args=(
        create_scan_id, request.json['method'], request.json['url'], request.json['headers'], re_data, data_type))
    t.start()
    return jsonify({"scan_id": create_scan_id, "scan_status": True}), 200


# 获取扫描结果
@app.route('/scan_result', methods=['GET'])
def scan_result():
    scan_id = request.args['scan_id']
    res = redis_conn.get(f'scan_id:{scan_id}')
    if res is not None:
        res = json.loads(res.decode('utf-8'))
    else:
        return jsonify({"result": False, "status": "no scanning", "fail_data": res}), 200
    if res is []:
        result = True
    else:
        result = False

    return jsonify({"result": result, "status": "scan success", "fail_data": res}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8978, debug=True)
