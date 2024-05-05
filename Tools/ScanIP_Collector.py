import datetime
import logging
import os
import re
import sys
import threading
import time
from base64 import b64encode


from util import *

global semaphore, all_clean_server_db
db = ''
client_db = ''
record_db = ''

server_db = ''
server_stauts_db = ''
global shodan_key_count, stop_threads
shodan_key_count = 0
stop_threads = False

global fake_ips




valid_http_server_db = ''
valid_nohttp_server_db = ''
all_clean_server_db = ''


def get_server_ip_port_query(ip: str, port: int, engine: str):
    if engine == "zoomeye":
        query = f'ip%3A"{ip}"%2Bport%3A{port}'
    elif engine == "shodan":
        query = f"ip:{ip} port:{port}"
    elif engine == "fofa":
        raw_query = f'ip="{ip}" && port="{port}"'
        query = b64encode(raw_query.encode()).decode()
    return query


def get_record_by_server(server_info: dict, engine: str, key_count):
    server_ip = server_info["server_ip"]
    server_port = server_info["server_port"]
    # pattern = server_info['pattern']
    # reverseFlag = server_info['reverseFlag']
    query = get_server_ip_port_query(server_ip, server_port, engine)
    # notice(123)
    if engine == "fofa":
        # TODO: 一次处理8个IP
        resJson = get_one_record_from_fofa(query)
        # print(resJson)
        matchRes = process_res_from_engine(resJson, engine)
        if matchRes and len(matchRes):
            if len(matchRes) == 1:
                record = matchRes[0]
            else:
                merge_record = matchRes[0]
                for record in matchRes[1:]:
                    merge_record[3] = merge_record[3] + record[3]
                    merge_record[4] = merge_record[4] + record[4]
                record = merge_record
        else:
            record = None
        # print(record)
    elif engine == "shodan":
        # notice(456)
        resJson = get_one_record_from_shodan(query, key_count)
        # print(resJson)
        matchRes = resJson["matches"]
        if matchRes and len(matchRes):
            record = matchRes[0]
        else:
            record = None
    elif engine == "zoomeye":
        # notice(789)
        resJson = get_one_record_from_zoomeye(query, key_count)
        # print(resJson)
        if resJson == -1:
            # print('Error in get_record_from_zoomeye')
            return None
        elif resJson == -2:
            # print('Error in get_record_from_zoomeye')
            return None
        matchRes = resJson["matches"]
        if matchRes and len(matchRes):
            record = matchRes[0]
        else:
            record = None

        # print(record)
        # exit()

    return record


def extract_ip_by_pattern(record, pattern, engine, reverseFlag, protocol=None):
    if engine == "fofa":
        banner = record[3]
        header = record[4]
        if header and len(header):
            content = header + banner
        else:
            content = banner
        # print(f'header is {header}')
        # print(f'banner is {banner}')
    elif engine == "shodan":
        if "mysql" in record and "error_message" in record["mysql"]:
            banner = record["mysql"]["error_message"]
        elif "data" in record:
            banner = record["data"]
        else:
            banner = ""
        content = banner

    elif engine == "zoomeye":
        if "portinfo" in record and "banner" in record["portinfo"]:
            banner = record["portinfo"]["banner"]
        else:
            banner = ""
        content = banner

    # process http content,promote the accuracy of ip extraction
    if protocol is not None:
        if protocol == "http":
            if "%2E" in pattern:
                pass
            else:
                content = content.replace("%2E", ".")

    client_ips = re.findall(pattern, content, re.I)
    client_ips = [x.replace("%2E", ".") for x in client_ips]
    client_ips = [x for x in client_ips if not x.startswith("224")]

    real_client_ips = [x for x in client_ips if is_ipv4_address(x) and is_public_ip(x)]
    client_ips = real_client_ips

    if client_ips and len(client_ips):
        if len(set(client_ips)) == 1:
            client_ip = client_ips[0]
            if reverseFlag:
                client_ip = ".".join(client_ip.split(".")[::-1])
            return client_ip
        else:
            if engine == "fofa":
                return client_ips
            print(f"This record {record} contains two different client_ips!")
            return None
    # print(content)
    return None


def insert_one_record_to_client_db(client_ip: str, engine: str, newIpPath=None):
    if client_ip in fake_ips:
        return -1
    if engine == "fofa":
        reverse_ip = ".".join(client_ip.split(".")[::-1])
        query = {"client_ip": reverse_ip, "engine": engine}
        numCount = client_db.count_documents(query)
        if numCount!=0:
            return -1
        
    
    data = {"client_ip": client_ip, "engine": engine}
    numCount = client_db.count_documents(data)
    if numCount == 0:
        if newIpPath is not None:
            with open(newIpPath, "a+") as wf:
                wf.write(client_ip + "\n")
        client_db.insert_one(data)
    return 0


def singleJobForShodan(
    res: dict, engine: str, allIpPath: str, newIpPath: str, key_count=1
):
    # key_count=1
    if res is None:
        return
    queryData = {"server_ip": res["server_ip"], "server_port": res["server_port"]}
    numCount = server_stauts_db.count_documents(queryData)
    if numCount == 0:
        server_stauts_db.insert_one(queryData)
    current_server_status = server_stauts_db.find(queryData)[0]
    try:

        record = get_record_by_server(res, engine, key_count)
    except Exception as e:
        # print(res)
        # print(res, engine, key_count)
        logging.exception(e)
        # exit()
        notice(f"Error in get_record_by_server.py is singleJobForShodan {e}")
        return

    if engine not in current_server_status:
        last_client_ips = []
        last_times = 0
    else:
        last_client_ips = current_server_status[engine]["client_ips"]
        last_times = current_server_status[engine]["times"]

    current_time = datetime.datetime.now()
    if len(last_client_ips):
        flag = False
        for cip in last_client_ips:
            if not cip.startswith("224"):
                flag = True
                break
        if not flag:
            data = {
                engine: {
                    "status": "modified record",
                    "client_ips": last_client_ips,
                    "times": 9999,
                    "lastModifyTime": current_time,
                }
            }
            server_stauts_db.update_one(queryData, {"$set": data})
            # print(666)
            return

    data = {
        engine: {
            "status": "not found",
            "client_ips": last_client_ips,
            "times": last_times + 1,
            "lastModifyTime": current_time,
        }
    }
    if record is not None:
        data[engine]["status"] = "invalid"
        client_ip = extract_ip_by_pattern(
            record, res["pattern"], engine, res["reverseFlag"], res["protocol"]
        )

        if client_ip and len(client_ip):
            data[engine]["status"] = "valid"
            if client_ip not in last_client_ips:
                ef = insert_one_record_to_client_db(client_ip, engine, newIpPath)
                if ef == 0:
                    with open(allIpPath, "a+") as wf:
                        wf.write(client_ip + "\n")
                    last_client_ips.append(client_ip)
                    data[engine]["client_ips"] = last_client_ips

            # client_data = {'client_ip': client_ip, 'engine': engine}
            # numCount = client_db.count_documents(client_data)
            # if numCount == 0:
            # client_db.insert_one(client_data)
    # print(data)
    server_stauts_db.update_one(queryData, {"$set": data})


def singleJob(res: dict, engine: str):
    allIpPath, newIpPath = assertStoreFilePath(engine)
    global key_count, semaphore, stop_threads
    with semaphore:
        if stop_threads:
            exit()

        queryData = {"server_ip": res["server_ip"], "server_port": res["server_port"]}
        numCount = server_stauts_db.count_documents(queryData)
        if numCount == 0:
            server_stauts_db.insert_one(queryData)
        current_server_status = server_stauts_db.find(queryData)[0]
        try:

            record = get_record_by_server(res, engine, key_count)
        except Exception as e:
            # print(res)
            # print(res, engine, key_count)
            notice(f"Error in get_record_by_server.py is 123 {e}")
            stop_threads = False  # !eddddd

            exit()

        key_count += 1
        if engine not in current_server_status:
            last_client_ips = []
            last_times = 0
        else:
            try:
                last_client_ips = current_server_status[engine]["client_ips"]
                last_times = current_server_status[engine]["times"]
            except Exception as e:
                print(e)
                print(current_server_status)
                # logging.exception(e)
                # exit()
                return

        current_time = datetime.datetime.now()
        data = {
            engine: {
                "status": "not found",
                "client_ips": last_client_ips,
                "times": last_times + 1,
                "lastModifyTime": current_time,
            }
        }
        if record is not None:
            data[engine]["status"] = "invalid"
            client_ip = extract_ip_by_pattern(
                record, res["pattern"], engine, res["reverseFlag"], res["protocol"]
            )

            if engine in ["fofa"] and type(client_ip) == list:
                data[engine]["status"] = "valid"
                for cip in client_ip:
                    error_flag = insert_one_record_to_client_db(cip, engine, newIpPath)
                    if error_flag == 0:
                        with open(allIpPath, "a+") as wf:
                            wf.write(cip + "\n")
                        if cip not in last_client_ips:
                            last_client_ips.append(cip)
                # last_client_ips.extend()(client_ip)
                data[engine]["client_ips"] = last_client_ips
                # client_data = {'client_ip': client_ip, 'engine': engine}

            elif client_ip and len(client_ip):
                data[engine]["status"] = "valid"
                ef = insert_one_record_to_client_db(client_ip, engine, newIpPath)
                if ef == 0:
                    if client_ip not in last_client_ips:
                        with open(allIpPath, "a+") as wf:
                            wf.write(client_ip + "\n")
                        last_client_ips.append(client_ip)
                        data[engine]["client_ips"] = last_client_ips
                
                # client_data = {'client_ip': client_ip, 'engine': engine}
                # numCount = client_db.count_documents(client_data)
                # if numCount == 0:
                # client_db.insert_one(client_data)
        # print(data)
        server_stauts_db.update_one(queryData, {"$set": data})


def multiJob(results: list, engine: str):
    global key_count, semaphore, stop_threads
    allIpPath, newIpPath = assertStoreFilePath(engine)
    finalQuery = ""
    serverInfoDict = dict()
    for res in results:
        server_ip = res["server_ip"]
        server_port = res["server_port"]
        key = f"{server_ip}:{server_port}"
        serverInfoDict[key] = res
        queryData = {"server_ip": server_ip, "server_port": server_port}

        numCount = server_stauts_db.count_documents(queryData)
        if numCount == 0:
            server_stauts_db.insert_one(queryData)
        # current_server_status = server_stauts_db.find(queryData)[0]
        if engine == "zoomeye":
            finalQuery += " "
            finalQuery += get_server_ip_port_query(server_ip, server_port, engine)
        elif engine == "fofa":
            # finalQuery += ' || '
            finalQuery += f'(ip="{server_ip}" && port="{server_port}")'
            finalQuery += " || "

    finalQuery = b64encode(finalQuery.encode()).decode()
    # print(finalQuery)
    # exit()

    if engine == "zoomeye":
        record = get_one_record_from_zoomeye(finalQuery, key_count)
        # print(record)
    elif engine == "fofa":
        try:
            record = get_one_record_from_fofa(finalQuery)
        except KeyError as e:
            if "results" in e:
                # 提醒fofa额度用完了
                notice(f"fofa key is used up!")
            return

        except Exception as e:
            for _ in range(3):
                os.system("bash ~/conn.sh")
                time.sleep(5)
                try:
                    record = get_one_record_from_fofa(finalQuery)
                    notice("reconnect to network success!")
                    break
                except KeyError as e:
                    # if 'results' in e:
                    return
                    # else:
                    #     print(e)
            return
            # print(e)
        # print(record)

    key_count += 1

    allRecords = process_res_from_engine(record, engine)

    passFlags = []

    for aR in allRecords:
        server_ip, server_port = extract_info_from_file(aR, engine)
        if server_ip is None or server_port is None:
            continue
        if not is_ipv4_address(server_ip) or not is_public_ip(server_ip):
            continue

        queryData = {"server_ip": server_ip, "server_port": server_port}

        numCount = server_stauts_db.count_documents(queryData)
        if numCount == 0:
            server_stauts_db.insert_one(queryData)
        current_server_status = server_stauts_db.find(queryData)[0]

        # print(current_server_status)

        if engine not in current_server_status:
            last_client_ips = []
            last_times = 0
        else:
            last_client_ips = current_server_status[engine]["client_ips"]
            last_times = current_server_status[engine]["times"]
        current_time = datetime.datetime.now()

        if (server_ip, server_port) in passFlags:
            # continue
            data = {
                engine: {
                    "status": "not found",
                    "client_ips": last_client_ips,
                    "times": last_times,
                    "lastModifyTime": current_time,
                }
            }
        else:
            data = {
                engine: {
                    "status": "not found",
                    "client_ips": last_client_ips,
                    "times": last_times + 1,
                    "lastModifyTime": current_time,
                }
            }
            passFlags.append((server_ip, server_port))

        # if aR is not None:
        data[engine]["status"] = "invalid"

        currentRes = serverInfoDict[f"{server_ip}:{server_port}"]

        client_ip = extract_ip_by_pattern(
            aR,
            currentRes["pattern"],
            engine,
            currentRes["reverseFlag"],
            currentRes["protocol"],
        )
        if engine in ["fofa"] and type(client_ip) == list:
            data[engine]["status"] = "valid"
            for cip in client_ip:
                ef = insert_one_record_to_client_db(cip, engine, newIpPath)
                if ef == 0:
                    with open(allIpPath, "a+") as wf:
                        wf.write(cip + "\n")
                    if cip not in last_client_ips:
                        last_client_ips.append(cip)
            # last_client_ips.extend()(client_ip)
            data[engine]["client_ips"] = last_client_ips
            # client_data = {'client_ip': client_ip, 'engine': engine}

        elif client_ip and len(client_ip):
            data[engine]["status"] = "valid"
            
            ef = insert_one_record_to_client_db(client_ip, engine, newIpPath)
            if ef == 0:
                if client_ip not in last_client_ips:
                    with open(allIpPath, "a+") as wf:
                        wf.write(client_ip + "\n")
                    last_client_ips.append(client_ip)
                    data[engine]["client_ips"] = last_client_ips
            
            # client_data = {'client_ip': client_ip, 'engine': engine}
            # numCount = client_db.count_documents(client_data)
            # if numCount == 0:
            # client_db.insert_one(client_data)
        # print(data)
        server_stauts_db.update_one(queryData, {"$set": data})
    # process remains
    remains = [
        x for x in results if (x["server_ip"], x["server_port"]) not in passFlags
    ]
    for res in remains:
        queryData = {"server_ip": res["server_ip"], "server_port": res["server_port"]}

        numCount = server_stauts_db.count_documents(queryData)
        if numCount == 0:
            server_stauts_db.insert_one(queryData)
        current_server_status = server_stauts_db.find(queryData)[0]
        # print(222)
        # print(current_server_status)

        if engine not in current_server_status:
            last_client_ips = []
            last_times = 0
        else:
            last_client_ips = current_server_status[engine]["client_ips"]
            last_times = current_server_status[engine]["times"]
        current_time = datetime.datetime.now()
        data = {
            engine: {
                "status": "not found",
                "client_ips": last_client_ips,
                "times": last_times + 1,
                "lastModifyTime": current_time,
            }
        }
        server_stauts_db.update_one(queryData, {"$set": data})

    # return finalQuery


def check_and_correct():
    engines = ["fofa", "zoomeye", "shodan"]
    global server_db, client_db, server_stauts_db
    server_status_infos = server_stauts_db.find()
    for server_status_info in server_status_infos:
        for engine in engines:
            if engine in server_status_info:
                try:
                    queryData = {
                        "server_ip": server_status_info["server_ip"],
                        "server_port": server_status_info["server_port"],
                    }
                    client_ips = server_status_info[engine]["client_ips"]
                    real_client_ips = [
                        x for x in client_ips if is_ipv4_address(x) and is_public_ip(x)
                    ]
                    if client_ips != real_client_ips:
                        rawData = server_status_info[engine]
                        rawData["client_ips"] = real_client_ips
                        if len(real_client_ips) == 0:
                            rawData["status"] = "invalid"
                        server_stauts_db.update_one(
                            queryData, {"$set": {engine: rawData}}
                        )
                        for cip in client_ips:
                            if cip not in real_client_ips:
                                client_db.delete_one(
                                    {"engine": engine, "client_ip": cip}
                                )
                except Exception as e:
                    print(server_status_info)


def correct():
    global server_db, client_db, server_stauts_db
    #    data = {engine: {'status': 'not found', 'client_ips': last_client_ips,
    #                  'times': last_times+1, 'lastModifyTime': current_time}}

    fields_to_delete = ["status", "client_ips", "times", "lastModifyTime"]
    server_stauts_db.update_many(
        {"times": 1}, {"$unset": {field: "" for field in fields_to_delete}}
    )
    # server_status_infos = server_stauts_db.find({'times':1})
    # for server_status_info in server_status_infos:


def get_work_list(engine: str, startNumber=None, Number=None):
    global server_db, client_db, server_stauts_db
    if startNumber is not None and Number is not None:
        all_work_server = server_db.find({}).skip(startNumber).limit(Number)
    else:
        all_work_server = server_db.find({})
    work_list = []
    for server_info in all_work_server:
        queryData = {
            "server_ip": server_info["server_ip"],
            "server_port": server_info["server_port"],
        }
        numCount = server_stauts_db.count_documents(queryData)
        # print(server_stauts_db.find(queryData))
        flag = 0
        if not numCount:
            # if server_info not in work_list:
            flag = 1
            # work_list.append(server_info)
        else:
            rawStatusData = server_stauts_db.find(queryData)[0]
            # print(rawStatusData)
            if engine not in rawStatusData:
                flag = 1
        if flag == 1 and server_info not in work_list:
            work_list.append(server_info)
    return work_list


def get_wrok_list_by_server_status(engine: str, Number=None):
    global server_stauts_db, server_db
    work_list = []
    if Number is not None:
        all_work_server = server_stauts_db.find(
            {f"{engine}.times": {"$exists": False}}
        ).limit(Number)
    else:
        all_work_server = server_stauts_db.find({f"{engine}.times": {"$exists": False}})

    if engine == "shodan":
        number = 1 if Number is None else Number
        all_work_server = server_stauts_db.find({f"{engine}.times": 1}).limit(number)
    elif engine == "fofa":
        number = 1 if Number is None else Number
        all_work_server = server_stauts_db.find({f"{engine}.times": 1}).limit(number)
        # all_work_server=server_stauts_db.find({ f"{engine}.times": { "$exists": False } }).limit(number)
    elif engine == "zoomeye":
        number = 1 if Number is None else Number
        all_work_server = server_stauts_db.find({f"{engine}.times": 1}).limit(number)

    for work_server in all_work_server:
        queryData = {
            "server_ip": work_server["server_ip"],
            "server_port": work_server["server_port"],
        }
        try:
            server_info = server_db.find(queryData)[0]
        except Exception as e:
            logging.exception(e)
            continue
        if server_info not in work_list:
            work_list.append(server_info)
    # work_list=[]

    return work_list


def work(startNumber, Number, engine: str, workList=None):
    global server_db, client_db
    if workList is None:
        if Number == -1:
            server_infos = server_db.find().skip(startNumber)
        else:
            server_infos = server_db.find().skip(startNumber).limit(Number)

    else:
        server_infos = workList

    threads = []
    try:
        if engine == "fofa":
            length = len(server_infos)
            step_length = 10
            for i in range(0, length, step_length):
                try:
                    results = server_infos[i : i + step_length]
                    multiJob(results, engine)
                except Exception as e:
                    logging.exception(e)
                # th = threading.Thread(target=eightJob, args=(results, engine,))
                # th.start()
                # threads.append(th)

            # print(finalQuery)
            # exit()
        else:
            for res in server_infos:
                # print(res)
                # exit()
                th = threading.Thread(
                    target=singleJob,
                    args=(
                        res,
                        engine,
                    ),
                )
                th.start()
                threads.append(th)
            for th in threads:
                th.join()
    except Exception as e:
        logging.exception(e)
        # print(res)


def get_all_remain_server():
    global server_db, client_db, server_stauts_db
    server_infos = server_db.find().skip(97362)
    for server_info in server_infos:
        server_ip = server_info["server_ip"]
        server_port = server_info["server_port"]
        queryData = {"server_ip": server_ip, "server_port": server_port}
        numCount = server_stauts_db.count_documents(queryData)
        if numCount == 0:
            server_stauts_db.insert_one(queryData)


def assertStoreFilePath(engine: str):
    current_date = datetime.date.today()
    formatted_date = current_date.strftime("%Y-%m-%d")
    # print(formatted_date)workDIr
    workDir = ''

    allIpPath = os.path.join(workDir, "all_ips.txt")
    newIpPath = os.path.join(workDir, "new_ips.txt")

    if not os.path.exists(workDir):
        try:
            os.makedirs(workDir)
        except Exception as e:
            logging.exception(e)
    if not os.path.exists(allIpPath):
        with open(allIpPath, "a+") as wf:
            wf.write("")
    if not os.path.exists(newIpPath):
        with open(newIpPath, "a+") as wf:
            wf.write("")
    return allIpPath, newIpPath


def getMaxTimes(engine: str, db=None):
    global server_stauts_db
    if db is None:
        db = server_stauts_db

    status = db.aggregate(
        [
            {"$group": {"_id": f"${engine}.times", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
    )
    maxID = -1
    for s in status:

        if s["_id"] is not None and s["_id"] > maxID:
            maxID = s["_id"]
        # print(s)
    # print(status)
    # print(maxID)
    return maxID


def shodanScheduledTask(target=None, newServer=False, encode=False, typePara=None):
    engine = "shodan"
    if target is None:
        with open("server_status.json", "r") as wf:
            data = json.load(wf)
            target = data[engine] + 1

    notice(f"Shodan ScheduledTask start, current target is {target}")
    if encode == False:
        global server_db, client_db, server_stauts_db
        while True:
            if target is None:
                maxID = getMaxTimes("shodan")
            else:
                maxID = target
            maxWorkNums = 40000
            remainQuery = {
                f"{engine}.client_ips": {"$exists": True, "$ne": []},
                "$or": [
                    {f"{engine}.times": {"$exists": False}},
                    {f"{engine}.times": {"$lt": maxID}},
                ],
            }

            if newServer:
                remainQuery = {
                    f"{engine}.times": {"$exists": False},
                }
                # remainQuery={f"{engine}.times":8,}
            if typePara is not None:
                remainQuery = {f"type": typePara, f"{engine}.times": {"$exists": False}}

            remains = server_stauts_db.find(remainQuery).limit(maxWorkNums)
            work_list = []
            # for work_server in remains:
            #     queryData = {
            #         'server_ip': work_server['server_ip'], 'server_port': work_server['server_port']}
            #     try:
            #         server_info = server_db.find(queryData)[0]
            #     except Exception as e:
            #         logging.exception(e)
            #         # exit()
            #         continue
            #     if server_info not in work_list:
            #         work_list.append(server_info)

            for work_server in remains:
                queryData = {
                    "server_ip": work_server["server_ip"],
                    "server_port": work_server["server_port"],
                    "engine": engine,
                }
                try:
                    server_info = all_clean_server_db.find(queryData)[0]
                except Exception as e:
                    # logging.exception(e)
                    print_error_log(e)
                    continue
                if server_info not in work_list:
                    work_list.append(server_info)

            notice(f"shodan's WorkList Ready, work_list length is {len(work_list)}")
            length = len(work_list)
            for i in range(0, length, 2):
                if i + 1 >= length:
                    worker1 = work_list[i]
                    worker2 = None
                else:
                    worker1 = work_list[i]
                    worker2 = work_list[i + 1]
                try:
                    allIpPath, newIpPath = assertStoreFilePath("shodan")
                    singleJobForShodan(worker1, "shodan", allIpPath, newIpPath, 0)
                    singleJobForShodan(worker2, "shodan", allIpPath, newIpPath, 1)
                except Exception as e:
                    # print(e)
                    # logging.exception(e)
                    # exit()
                    notice(
                        f"Error in get_record_by_server.py is singleJobForShodan111 {e}"
                    )

            # for res in work_list:
            #     try:
            #         allIpPath,newIpPath=assertStoreFilePath('shodan')
            #         singleJobForShodan(res, 'shodan', allIpPath, newIpPath, 1)
            #     except Exception as e:
            #         print(e)
            #         notice(f'Error in get_record_by_server.py is singleJobForShodan {e}')
            if length == 0:
                notice(
                    f"current times is {maxID}, shodan's WorkList is empty, shodanScheduledTask is end!"
                )

                with open("server_status.json", "r") as wf:
                    data = json.load(wf)
                    data[engine] = maxID
                with open("server_status.json", "w") as wf:
                    json.dump(data, wf)

                break


def zoomeyeScheduledTask(target=None, newServer=False, typePara=None):
    global semaphore, stop_threads, shodan_key_count, all_clean_server_db
    engine = "zoomeye"
    max_workers = 3
    print("Zoomeye ScheduledTask start!")
    global server_db, client_db, server_stauts_db
    exitFlag = 0
    while True:

        if target is None:
            maxID = getMaxTimes(engine)
        else:
            maxID = target
        # maxID=getMaxTimes(engine)
        maxWorkNums = 20000

        if newServer:
            remainQuery = {
                f"{engine}.times": {"$exists": False},
            }
            # remainQuery={f"{engine}.times": 1,}
        else:
            remainQuery = {
                f"{engine}.client_ips": {"$exists": True, "$ne": []},
                "$or": [
                    {f"{engine}.times": {"$exists": False}},
                    {f"{engine}.times": {"$lt": maxID}},
                ],
            }

        if typePara is not None:
            if typePara != "plain":
                remainQuery = {f"type": typePara, f"{engine}.times": {"$exists": False}}

            else:
                remainQuery = {f"{engine}.client_ips": {"$exists": True, "$ne": []}}
                exitFlag = 1

        remains = server_stauts_db.find(remainQuery).limit(maxWorkNums)

        work_list = []
        for work_server in remains:
            queryData = {
                "server_ip": work_server["server_ip"],
                "server_port": work_server["server_port"],
                "engine": engine,
            }
            try:
                server_info = all_clean_server_db.find(queryData)[0]
            except Exception as e:
                # logging.exception(e)
                print_error_log(e)
                continue
            if server_info not in work_list:
                work_list.append(server_info)

        notice(f"{engine}'s WorkList Ready, work_list length is {len(work_list)}")

        try:
            semaphore = threading.Semaphore(max_workers)
            threads = []
            server_infos = work_list
            for res in server_infos:
                # print(res)
                # exit()
                th = threading.Thread(
                    target=singleJob,
                    args=(
                        res,
                        engine,
                    ),
                )
                th.start()
                threads.append(th)
            for th in threads:
                th.join()
        except Exception as e:
            # print(e)
            info = engine + " " + str(e)
            notice(f"Error in get_records_by_server.py is {info}")

        if exitFlag == 1:
            break

        if len(work_list) == 0:
            notice(
                f"current times is {maxID}, {engine}'s WorkList is empty, {engine}ScheduledTask is end!"
            )

            # with open('server_status.json','r') as wf:
            #     data = json.load(wf)
            #     data[engine] = maxID
            # with open('server_status.json','w') as wf:
            #     json.dump(data,wf)

            break


def fofaScheduledTask(target=None):
    engine = "fofa"
    if target is None:
        with open("server_status.json", "r") as wf:
            data = json.load(wf)
            target = data[engine] + 1

    notice(f"fofaScheduledTask start, current target is {target}")
    global semaphore, stop_threads, shodan_key_count

    global server_db, client_db, server_stauts_db

    while True:
        if target is None:
            maxID = getMaxTimes(engine)
            # with open()
        else:
            maxID = target
        maxWorkNums = 20000

        remainQuery = {
            f"{engine}.client_ips": {"$exists": True, "$ne": []},
            "$or": [
                {f"{engine}.times": {"$exists": False}},
                {f"{engine}.times": {"$lt": maxID}},
            ],
        }
        

                
        remains = server_stauts_db.find(remainQuery).limit(maxWorkNums)

        work_list = []

        # inital
        for work_server in remains:
            queryData = {
                'server_ip': work_server['server_ip'], 'server_port': work_server['server_port']}
            try:
                server_info = server_db.find(queryData)[0]
            except Exception as e:
                # logging.exception(e)
                print_error_log(e)
                continue
            if server_info not in work_list:
                work_list.append(server_info)


        # clean 
        # for work_server in remains:
        #     queryData = {
        #         "server_ip": work_server["server_ip"],
        #         "server_port": work_server["server_port"],
        #         "engine": engine,
        #     }
        #     try:
        #         server_info = all_clean_server_db.find(queryData)[0]
        #     except Exception as e:
        #         # logging.exception(e)
        #         print_error_log(e)
        #         continue
        #     if server_info not in work_list:
        #         work_list.append(server_info)

        notice(f"{engine}'s WorkList Ready, work_list length is {len(work_list)}")
        # exit()
        
        server_infos = work_list
        try:
            length = len(server_infos)
            step_length = 12
            # print(work_list)
            for i in range(0, length, step_length):
                try:
                    results = server_infos[i : i + step_length]
                    multiJob(results, engine)
                except Exception as e:
                    # print(e)
                    # import logging
                    print_error_log(e)
                    notice(
                        f"Error in get_records_by_server.py in fofaScheduledTask func is {e}"
                    )
                    # exit()
                    return

        except Exception as e:
            # print(e)
            info = engine + " " + str(e)
            notice(f"Error in get_records_by_server.py is {info}")

        if len(work_list) == 0:
            notice(
                f"current times is {maxID}, {engine}'s WorkList is empty, {engine}ScheduledTask is end!"
            )

            with open("server_status.json", "r") as wf:
                data = json.load(wf)
                data[engine] = maxID
            with open("server_status.json", "w") as wf:
                json.dump(data, wf)

            break


def scheduledTask(engine="fofa", currentTarget=0, typePara="plain"):
    import time

    import schedule

    global semaphore, stop_threads, shodan_key_count
    # engine='fofa'
    global server_db, client_db, server_stauts_db, target
    global target
    # def Task(target):
    #     # 在这里编写您的任务逻辑
    #     # print("执行 Task,并且参数 target =", target)
    #     target

    # def increment_target(engine:str):
    #     # 在这里编写每到24点递增 target 的逻辑
    #     global target
    #     target += 1
    #     notice(f'{engine} start increment target, current target is {target}')

    # 初始的 target 值
    if currentTarget is not None:
        target = currentTarget
    else:
        target = None

    # 每到24点执行任务 Task
    if engine == "zoomeye":
        zoomeyeScheduledTask(target, typePara=typePara)
        schedule.every().day.at("00:05").do(
            zoomeyeScheduledTask, target, False, typePara
        )

    else:
        # schedule.every().day.at("21:18").do(increment_target, engine)
        if engine == "fofa":
            fofaScheduledTask(target)
            schedule.every().day.at("00:05").do(fofaScheduledTask, target)

        if engine == "shodan":
            shodanScheduledTask(target)
            schedule.every().day.at("00:10").do(shodanScheduledTask, target)
        # target += 1

    # 每到24点递增 target
    #

    # 循环执行调度任务
    while True:
        schedule.run_pending()
        time.sleep(1)




def get_record_and_store(query: str, name: str):
    h = CensysHosts()
    test = h.search(query, per_page=20, pages=1)
    res = test.view_all()
    with open(f"{name}.json", "w") as wf:
        json.dump(res, wf, indent=4)


def extract_from_record(content):
    import re

    pattern = "# ([0-9a-zA-z_]+) = ['\"]([^\n]+)['\"]\n"
    matches = re.findall(pattern, content, re.I)
    return matches


def get_value_by_name(patternName, key):
    global old_pattern_lists
    for opl in old_pattern_lists:
        if opl["patternName"] == patternName:
            return opl[key]


def set_config():
    global h, db, ip_leak_pattern, old_pattern_lists, censys_patterns
    h = CensysHosts()
    db = DB()
    ip_leak_pattern = ''
    old_pattern_lists = list(ip_leak_pattern.find())

    censys_patterns = []
    with open("censys_query.txt", "r") as rb:
        cts = rb.readlines()
    for ct in cts:
        ms = extract_from_record(ct)
        if len(ms):
            application = get_value_by_name(ms[0][0], "application")
            record = {
                "patternName": ms[0][0],
                "censys_query": ms[0][1],
                "application": application,
            }
            censys_patterns.append(record)
            if application is None:
                print(f"{ms[0][0]} is None")


def get_censys_query_by_patternName(patternName: str):
    global censys_patterns
    for cp in censys_patterns:
        if cp["patternName"] == patternName:
            return cp["censys_query"]
    return None


def get_banner_from_name(service, patternName):
    body_lists = [
        "http_400_node_information",
        "http_proxy_server_ip",
        "http_407_white_ip",
    ]
    # banner_lists = ['http_api_user_ip']
    application = get_value_by_name(patternName, "application")
    censys_query = get_censys_query_by_patternName(patternName)
    if censys_query is None:
        return None
    try:
        if application == "smtp":
            if patternName not in ["smtp_no_valid_ptr"] and "ehlo" in service["smtp"]:
                banner = service["smtp"]["ehlo"]
            else:
                banner = service["banner"]
        elif application == "http" and "http" in service:
            if patternName in body_lists:
                if "body" in service["http"]["response"]:
                    banner = service["http"]["response"]["body"]
                else:
                    banner = service["banner"]
            else:
                banner = service["banner"]
        elif application == "mysql":
            if "error_message" in service["mysql"]:
                banner = service["mysql"]["error_message"]
            else:
                banner = service["banner"]
        elif application == "redis":
            banner = service["redis"]["ping_response"]
        else:
            banner = service["banner"]
    except Exception as e:
        print(f"get banner from name error {e} in service: {service}")
        exit()
        return None
    return banner


def process_record_file(fp: str, patternName: str):
    global all_valid_servers,all_records_sp
    import json, re

    censys_ip_list = []
    error_ip_list = []

    with open(fp, "r") as f:
        records = json.load(f)
    if len(records) == 0:
        print(f"{patternName} is null")
        return [], [], {}, []
    valid_records = [ip for ip in records if "error" not in records.get(ip, {})]

    for server_ip in records:
        item = records[server_ip]
        if "error" in item:
            continue
        for service in item["services"]:
            server_ip = item['ip']
            server_port = service['port']
            
            if ((server_ip,server_port) not in all_records_sp):
                all_records_sp.append((server_ip,server_port))
            
            
            
            application = get_value_by_name(patternName, "application")
            if service["service_name"] == application.upper() or (
                service["service_name"] == "UNKNOWN"
                and patternName == "tenor_connected_ipaddr"
            ):
                banner = get_banner_from_name(service, patternName)
                matchPattern = get_value_by_name(patternName, "matchPattern")
                banner_ips = re.findall(matchPattern, banner, re.I)
                source_ip = service["source_ip"]

                if ":" in source_ip:  # ipv6
                    continue

                # print(banner)

                if banner_ips == []:
                    reverse_source_ip = ".".join(source_ip.split(".")[::-1])
                    encoded_source_ip = source_ip.replace(".", "%2E")

                    # if source_ip in banner or reverse_source_ip in banner or encoded_source_ip in banner:
                    #     print(f"To Be Check in {patternName} match {server_ip} {matchPattern} {banner}")
                    # print(f"{patternName} not match {server_ip} {matchPattern} {banner}")

                else:
                    plain_ip = banner_ips[0]
                    banner_ip = banner_ips[0].replace("%2E", ".")
                    if patternName == "smtp_no_valid_ptr":
                        banner_ip = ".".join(banner_ip.split(".")[::-1])

                    reverse_ip = ".".join(banner_ip.split(".")[::-1])
                    if reverse_ip == source_ip:
                        banner_ip = reverse_ip

                    if source_ip == banner_ip:
                        # mark a valid server
                        server_ip = item['ip']
                        server_port = service['port']
                        if reverse_ip == source_ip or patternName == "smtp_no_valid_ptr":
                            flag = 'R'
                        elif '%2E' in plain_ip:
                            flag = 'E'
                        else:
                            flag = 'P'
                        
                        valid_server = (server_ip, server_port, matchPattern, flag)
                        all_valid_servers.append(valid_server)
                        
                        
                        if source_ip not in censys_ip_list:
                            censys_ip_list.append(source_ip)
                    else:

                        error_ip_list.append(banner_ip)
                        # print(f"To Be Check in {patternName} match {server_ip} {matchPattern} {banner} {source_ip} {banner_ip}")
                        # print(banner_ip, source_ip, banner)

                    # assert(banner_ip[0] == source_ip)
    return censys_ip_list, error_ip_list, records, valid_records


def extrat_UA_from_HTTP(records):
    valid_http_server = []
    user_agents = []
    for ip in records:
        if "error" in records[ip]:
            continue
        for service in records[ip]["services"]:
            if service["service_name"] == "HTTP" and "http" in service:
                try:
                    ua = service["http"]["request"]["headers"]["User_Agent"][0]
                    valid_http_server.append(f'{ip}:{service["port"]}')
                    user_agents.append(ua)
                    # print(ua)
                except Exception as e:
                    print(e)
                    # print(service['http']['response']['headers'])
                    # print(service['source_ip'])
                    return
                break
    return valid_http_server, user_agents


# 遍历文件夹
def traverse_files(target_dir: str):
    global all_valid_servers,all_records_sp
    res_dict = {}

    file_lists = os.listdir(target_dir)

    csvfile = open("output_v2.csv", "w", newline="")

    # Create a CSV writer
    csvwriter = csv.writer(csvfile)

    csvwriter.writerow(
        ["PatternName", "All Record", "Valid Record", "Censys IP", "Error IP", "Rate"]
    )

    sum_all_records = []
    sum_valid_records = []
    sum_censys_ip = []
    sum_error_ip = []

    all_http_ip_port = []
    all_user_agent = []

    valid_pattern_number = 0
    for fileName in file_lists:
        if fileName.endswith(".json"):
            patternName = fileName[:-5]
            # print(file[:-5])
            fp = os.path.join(target_dir, fileName)
            # if fileName == "smtp_not_accept.json":

            # if time_pass != 0:
            #     time_pass -= 1
            #     continue
            # print(fileName)
            # try:
            censys_ip_list, error_ip_list, all_records, valid_records = (
                process_record_file(fp, patternName)
            )

            if len(all_records) == 0:
                continue

            valid_pattern_number += 1
            # except Exception as e:
            #     print(e)
            # continue
            # exit()
            VHS, UA = extrat_UA_from_HTTP(all_records)
            all_http_ip_port.extend(VHS)
            all_user_agent.extend(UA)
            # print(name)
            # print(censys_ip_list)
            # print(error_ip_list)
            # print(allCount)
            # print(validCount)
            # print()
            # Write data to CSV
            sum_all_records.extend(list(all_records.keys()))
            sum_valid_records.extend(list(valid_records))
            sum_censys_ip.extend(list(censys_ip_list))
            sum_error_ip.extend(list(error_ip_list))
            # 百分制的比例
            rate = len(censys_ip_list) / len(valid_records)

            res_dict[patternName] = censys_ip_list

            csvwriter.writerow(
                [
                    patternName,
                    len(all_records),
                    len(valid_records),
                    len(censys_ip_list),
                    len(error_ip_list),
                    rate,
                ]
            )

        # Close the CSV file
    name = "all"
    rate = len(set(sum_censys_ip)) / len(set(sum_valid_records))
    csvwriter.writerow(
        [
            name,
            len(set(sum_all_records)),
            len(set(sum_valid_records)),
            len(set(sum_censys_ip)),
            len(set(sum_error_ip)),
            rate,
        ]
    )

    # print(sum_error_ip)
    print(valid_pattern_number)
    print(len(set(all_http_ip_port)))
    print(set(all_user_agent))
    csvfile.close()

    # sort by rate
    with open("output_v2.csv", "r") as f:
        reader = csv.reader(f)
        data = [row for row in reader]
        data = sorted(data, key=lambda x: x[5], reverse=True)
        with open("output_v2.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(data)

    # select len(valud_records) >= 20 to generate a new csv
    with open("output_v2.csv", "r") as f:
        reader = csv.reader(f)
        data = [row for row in reader]

        data = [row for row in data if row[2] == "Valid Record" or int(row[2]) >= 20]
        with open("output_v2_more_than_20.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(data)

    with open("resDict.json", "w") as wf:
        json.dump(res_dict, wf, indent=4)
    return (
        list(set(sum_all_records)),
        list(set(sum_valid_records)),
        list(set(sum_censys_ip)),
        list(set(sum_error_ip)),
    )


### 2. 检测一下是否存在IP段隐藏的情况
def check_ip_range(ip_lists: list):
    censys_ip_ranges = [

    ]
    for ip in ip_lists:
        ip_segment = ".".join(ip.split(".")[:3]) + ".0"
        if ip_segment not in censys_ip_ranges:
            print(f"{ip_segment} 是Censys未公开的IP段")


### 3. 检查一下哪些censys IP交集比较少
def check_censys_ip_intersection():
    with open("resDict.json", "r") as rf:
        resDict = json.load(rf)
    maxPatternName = "http_400_node_information"
    for pn in resDict:
        if len(resDict[pn]) > len(resDict[maxPatternName]):
            maxPatternName = pn

    # 差集长度保存为csv表格形式
    csv_file = open("censys_ip_difference.csv", "w", newline="")
    csvwriter = csv.writer(csv_file)
    csvwriter.writerow(["PatternName", "Difference Length"])

    for pn in resDict:
        if pn != maxPatternName:
            # print(set(resDict[pn]) & set(resDict[maxPatternName]))
            intersection = set(resDict[pn]) & set(resDict[maxPatternName])
            # 计算差集
            difference = set(resDict[pn]) - set(resDict[maxPatternName])

            # 写入csv表格
            csvwriter.writerow([pn, len(difference)])

            # print(f"{pn} 与 {maxPatternName} 的交集长度为 {len(intersection)}")
            # print(f"{pn} 与 {maxPatternName} 的差集长度为 {len(difference)}")

    csv_file.close()


### 4. 检查蜜罐数据流量VSpattern迭代发现的记录的效果差异
def check_ip_intersection():
    with open("censys_.txt", "r") as rf:
        hp_ips = rf.readlines()
    hp_ips = [x.strip() for x in hp_ips]
    with open("resDict.json", "r") as rf:
        resDict = json.load(rf)
    pn_ips = []
    for pn in resDict:
        pn_ips.extend(resDict[pn])
    pn_ips = list(set(pn_ips))

    # 轮换差集计算，print差集数量
    print(len(set(hp_ips) - set(pn_ips)))  # 2
    print(len(set(pn_ips) - set(hp_ips)))  # 4


### 5. 修改config文件
def change_api_key(api_id, api_secret):
    from censys.common.config import DEFAULT, get_config, write_config

    config = get_config()
    config.set(DEFAULT, "api_id", api_id)
    config.set(DEFAULT, "api_secret", api_secret)
    write_config(config)


### 6. 获取账号信息
def get_account_info(api_id, api_secret):
    from censys.cli.utils import console
    from censys.common.exceptions import CensysUnauthorizedException
    from censys.search.v2.api import CensysSearchAPIv2
    from rich import box
    from rich.table import Table

    """Account subcommand.

    Args:
        args: Argparse Namespace.
    """
    try:
        client = CensysSearchAPIv2(api_id, api_secret)
        account = client.account()
        table = Table("Key", "Value", show_header=False, box=box.SQUARE, highlight=True)
        table.add_row("Email", account["email"])
        table.add_row("Login ID", account["login"])
        table.add_row("First Login", account["first_login"])
        table.add_row("Last Login", account["last_login"][:-7])
        quota = account["quota"]
        table.add_row(
            "Query Quota",
            f"{quota['used']} / {quota['allowance']} ({quota['used']/quota['allowance'] * 100 :.2f}%)",
        )
        table.add_row("Quota Resets At", quota["resets_at"])
        console.print(table)
        # sys.exit(0)
    except CensysUnauthorizedException:
        console.print("Failed to authenticate")
        # sys.exit(1)


### 7. 检查所有账号的额度信息
def get_all_account_info():
    with open("token.json", "r") as rf:
        tokens = json.load(rf)
    for token in tokens["censys_token"]:
        get_account_info(token["api_id"], token["api_secret"])


### 8.集中力量办大事，账号2-6: 每个下载200条，账号7看完1000个IP
def get_ten_pages(patternName: str, get_view=False):
    with open("censys_query.json", "r") as rf:
        censys_patterns = json.load(rf)
    censys_query = None
    for cp in censys_patterns:
        if cp["patternName"] == patternName:
            censys_query = cp["censys_query"]
            break
    with open("token.json", "r") as rf:
        tokens = json.load(rf)["censys_token"]

    if get_view:
        view_token = tokens[-1]
        change_api_key(view_token["api_id"], view_token["api_secret"])
        h = CensysHosts()
        test = h.search(censys_query, per_page=10, pages=1)
        all_pages = []
        for page in test:
            all_pages.append(page)
        with open(f"{patternName}_1000.json", "w") as wf:
            json.dump(all_pages, wf, indent=4)

        # with open(f"{patternName}_1000.json", "w") as wf:
        #     data =test.view_all()
        #     json.dump(data, wf, indent=4)
        # print(test.view_all())

    #     with open(f"{patternName}_1000.json", "w") as wf:
    #         data =test()
    #         json.dump(data, wf, indent=4)

    with open(f"{patternName}_1000.json", "r") as rf:
        data = json.load(rf)
    iplists = []
    for ds in data:
        for d in ds:
            iplists.append(d["ip"])

    # get_200_records(tokens[-1],iplists[:2])
    # 1000个IP分为5个200
    for i in range(5):
        targetIps = iplists[200 * i : 200 * (i + 1)]
        get_200_records(tokens[i + 1], targetIps)


### 9. task: 每个token分200条,一次看20个
def get_200_records(token: dict, targetIps: list):
    store_dir = ''

    # 一次分20个IP
    for i in range(0, len(targetIps), 20):
        targetIps_ = targetIps[i : i + 20]
        filename = f"_{targetIps_[0]}_{targetIps_[-1]}.json"
        fp = os.path.join(store_dir, filename)
        if os.path.exists(fp):
            continue
        change_api_key(token["api_id"], token["api_secret"])
        h = CensysHosts()
        hosts = h.bulk_view(targetIps_)
        with open(fp, "w") as wf:
            json.dump(hosts, wf, indent=4)


### 10. 处理1000条记录
def process_all_record():
    store_dir = ''
    patternName = "http_400_node_information"
    files = os.listdir(store_dir)
    all_censys_ips = []
    for fileName in files:
        if fileName.endswith(".json"):
            fp = os.path.join(store_dir, fileName)
            censys_ip_list, error_ip_list, all_records, valid_records = (
                process_record_file(fp, patternName)
            )
            # print(f"{fileName} {len(censys_ip_list)} {len(error_ip_list)} {len(valid_records)}")
            all_censys_ips.extend(censys_ip_list)
            # print(censys_ip_list)
    # = process_record_file(store_dir, "http_400_node_information")

    return list(set(all_censys_ips))


### 11. 检测IP数据集的交集
def check_cross():
    with open("censys_1000_ips.json", "r") as rf:
        censys_ips = json.load(rf)
    with open("one_years_ip.txt", "r") as rf:
        one_years_ips = rf.readlines()
    one_years_ips = [x.strip() for x in one_years_ips]

    ### 计算两者的差集
    print(len(set(censys_ips) - set(one_years_ips)))
    print(len(set(one_years_ips) - set(censys_ips)))

    ### 交集个数
    print(len(set(censys_ips) & set(one_years_ips)))
    remains = [x for x in one_years_ips if x not in censys_ips]
    return remains
    # print(data)

    # for token in tokens[1:6]:
    #     h = CensysHosts()
    #     test = h.search(censys_query, pages=)
    #     res = test.view_all()
    #     with open(f"{patternName}_{token['api_id']}.json", "w") as wf:
    #         json.dump(res, wf, indent=4)

    # h = CensysHosts()
    # http_400_node_information = 'services.http.response.body="*400 Bad Request*IP:*"'
    # test = h.search(censys_query, per_page=20, pages=1)
    # res = test.view_all()
    # with open(f"{name}.json", "w") as wf:
    #     json.dump(res, wf, indent=4)


### 数据库查询语句
def query_statement():
    import json

    # 输入的IP列表
    ip_list = [

    ]

    # 构建查询语句
    query = {"query": {"bool": {"minimum_should_match": 1, "should": []}}}

    # 添加每个IP地址到查询语句中
    for ip in ip_list:
        query["query"]["bool"]["should"].append({"match_phrase": {"src_ip": ip}})

    # 输出查询语句
    print(json.dumps(query, indent=2))


### 14 统计src_ip对应的IP段，用字符串处理方法实现
### 例如 1.1.1.1 所属IP段位 1.1.1.0/24


def get_ip_segment(ip: str):
    ip_segment = ".".join(ip.split(".")[:3]) + ".0"
    return ip_segment


def ua_src_ip_segment():

    with open("one_year_src_ip_by_ua.txt", "r") as rf:
        one_years_ips = rf.readlines()
    one_years_ips = [x.strip() for x in one_years_ips if x != ""]
    countDict = {}
    for ip in one_years_ips:
        ip_segment = get_ip_segment(ip)
        if ip_segment not in countDict:
            countDict[ip_segment] = 1
        else:
            countDict[ip_segment] += 1

    censys_sum = 0
    censys_ip_ranges = [

    ]

    countDict = dict(sorted(countDict.items(), key=lambda x: x[1], reverse=True))

    for ip in countDict:
        if ip in censys_ip_ranges:
            print("Censys IPSegment: ", ip, "Count: ", countDict[ip])
            censys_sum += countDict[ip]
        # else:
    for ip in countDict:
        if ip not in censys_ip_ranges:
            print("Not Censys IPSegment: ", ip, "Count: ", countDict[ip])

    print(censys_sum, len(one_years_ips) - censys_sum)
    return countDict


### 15.合并所有的censys Ip
def merge_all_censys_ip():
    censys_ip_ranges = [

    ]

    censys_ips = []
    with open("one_year_src_ip_by_ua.txt", "r") as rf:
        ips = rf.readlines()
    ips = [x.strip() for x in ips if get_ip_segment(x) in censys_ip_ranges]
    censys_ips.extend(ips)

    with open("censys_1000_ips.json", "r") as rf:
        censys_1000_ips = json.load(rf)
    
    with open("one_years_ip.txt", "r") as rf:
        one_years_ips = rf.readlines()
    one_years_ips = [x.strip() for x in one_years_ips]

    censys_ips.extend(censys_1000_ips)
    censys_ips.extend(one_years_ips)
    censys_ips = [x for x in list(set(censys_ips)) if get_ip_segment(x) in censys_ip_ranges]

    return censys_ips


### 16. 插入数据库
def insert_censys_ip_to_db():
    with open("all_censys_ips_to_db.json", "r") as rf:
        censys_ips = json.load(rf)
    db = DB()
    client_ip_db = ''
    for ip in censys_ips:
        client_ip_db.insert_one({"client_ip": ip, "engine": "censys"})


### 17. 分析UA得到的Censys IP
def get_ua_censys(save_flag = False):
    censys_header_after_0306_one_year = ''
    results = censys_header_after_0306_one_year.find()
    
    if save_flag:
        with open('not_censys_ip_but_censys_ua.json','w') as wf:
            data = [x for x in results]
            
            # 移除__id属性
            data = [{k: v for k, v in x.items() if k != "_id"} for x in data]
            
            json.dump(data,wf,indent=4)
        # for result in results:
            # print(result["client_ip"])
    
    with open('not_censys_ip_but_censys_ua.json','r') as rf:
        data = json.load(rf)

    not_xff_dict = {}

    XFF_RECORDS = []
    NOT_XFF_RECORDS = []
    x_forward_ips = []
    # proxy_ips = []
    
    
    for record in data:
        src_ip = record['src_ip']
        if 'header_content' in record:
            if 'X-Forwarded-For' in record['header_content']:
                xff_ip = record['header_content']['X-Forwarded-For']
                if ':' not in xff_ip:
                    check_ip_range([xff_ip])    # 带有x_forward_for属性的全是censys 公开的IP段
                    x_forward_ips.append(xff_ip)
                XFF_RECORDS.append(src_ip)
            
            else:
                NOT_XFF_RECORDS.append(src_ip)
                if src_ip not in not_xff_dict:
                    not_xff_dict[src_ip] = 1
                else:
                    not_xff_dict[src_ip] += 1
                
                
                
                # print(record)
        else:
            print('No header_content')
        
    # print(set(x_forward_ips))
    
    
    countDict = {}
    for ip in x_forward_ips:
        ip_segment = get_ip_segment(ip)
        if ip_segment not in countDict:
            countDict[ip_segment] = 1
        else:
            countDict[ip_segment] += 1
            
    countDict = dict(sorted(countDict.items(), key=lambda x: x[1], reverse=True))        
    # print(countDict)        
    
    # print(set(NOT_XFF_RECORDS))
    with open('xff_ips.json','w') as wf:
        json.dump(list(set(x_forward_ips)),wf,indent=4)
    
    
    
    print(XFF_RECORDS)
    

def insert_xff_ip_to_db():
    with open('xff_ips.json','r') as rf:
        xff_ips = json.load(rf)
    db = DB()
    client_ip_db = ''
    for ip in xff_ips:
        count = client_ip_db.count_documents({"client_ip": ip, "engine": "censys"})
        if count == 0:
            print({"client_ip": ip, "engine": "censys"})
            # client_ip_db.insert_one({"client_ip": ip, "engine": "censys"})



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("please input the first argument!")
        exit(-1)
    arg = sys.argv[1]
    if len(sys.argv) == 3:
        typePara = sys.argv[2]
    else:
        typePara = None

    if arg in ["zoomeye", "fofa", "shodan"]:
        scheduledTask(arg, None, typePara=typePara)

    # if arg == 'zoomeye':
    #     zoomeyeScheduledTask(target=17,typePara=typePara)
    # elif arg == 'shodan':
    #     shodanScheduledTask(target= 20,typePara=typePara)
    # elif arg == 'fofa':
    #     fofaScheduledTask(target = 16)
    # scheduledTask(15)
    # fofaScheduledTask(target = 14)

    elif arg == "merge":
        collection = ''
        merge_new_encoded_server(collection, "pattern_turn1")
    
    elif arg == 'tf':
        fofaScheduledTask(target=59)
    
    
    else:
        print("please input the right argument!")
        exit(-1)

