
import sys,os,json
from util import *

threshold = 1

def get_records_by_pattern(engine: str, patternName: str, recordNum=10000, startPage=1):
    # leak_pattern = enginePattern[engine][patternName]
    save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    record_num = get_record_number(workdir, engine)
    if record_num > threshold:
        return record_num, workdir

    if engine == "zoomeye":
        get_zoomeye_crwaler_ip(patternName, save_dir,
                               recordNum=recordNum, startPage=startPage)
    elif engine == 'fofa':
        get_fofa_crawler_ip(patternName, save_dir)
    elif engine == 'shodan':
        get_shodan_crawler_ip(patternName, save_dir)
    record_num = get_record_number(workdir, engine)
    return record_num, workdir


def get_records_by_pattern_improved(engine: str, patternName: str, recordNum=10000, startPage=1):
    # leak_pattern = enginePattern[engine][patternName]
    save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    record_num = get_record_number(workdir, engine)
    if record_num > threshold:
        return record_num, workdir

    if engine == "zoomeye":
        get_zoomeye_crwaler_ip_improved(patternName, save_dir,
                               recordNum=recordNum, startPage=startPage)
    elif engine == 'fofa':
        get_fofa_crawler_ip_improved(patternName, save_dir)
    elif engine == 'shodan':
        get_shodan_crawler_ip_improved(patternName, save_dir)
    record_num = get_record_number(workdir, engine)
    return record_num, workdir

def extract_info_from_record_improved(engine: str, patternName: str, save_dir=None):
    if save_dir is None:
        save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    raw_record_tuples = set()
    for root, _, fs in os.walk(workdir):
        for f in fs:
            fp = os.path.join(root, f)
            results = read_from_json(fp)
            records = process_res_from_engine(results, engine)
            for record in records:
                server_ip, server_port, banner, time = extract_info(
                    engine, record)
                res = matchSourceIPImproved(banner, patternName)
                # print(res)
                for client_ip in res:
                    if len(client_ip):
                        raw_record_tuples.add(
                            (server_ip, server_port, client_ip, time))
    return raw_record_tuples



def extract_info_from_record(engine: str, patternName: str, save_dir=None):
    if save_dir is None:
        save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    raw_record_tuples = set()
    for root, _, fs in os.walk(workdir):
        for f in fs:
            fp = os.path.join(root, f)
            results = read_from_json(fp)
            records = process_res_from_engine(results, engine)
            for record in records:
                server_ip, server_port, banner, time = extract_info(
                    engine, record)
                res = matchSourceIP(banner, patternName)
                # print(res)
                for client_ip in res:
                    if len(client_ip):
                        raw_record_tuples.add(
                            (server_ip, server_port, client_ip, time))
    return raw_record_tuples


# check_valid = static_filter + dynamic_valid + extract_valid_ip
def static_filter(raw_record_tuples: set, engine: str, patternName: str, save_dir=None):
    if save_dir is None:
        save_dir = f''
    # workdir = set_work_dir(save_dir, patternName)
    client_ips = set()
    server_ips = set()
    server_ip_ports = set()
    server_ip_port_patterns = set()
    record_tuples = set()
    for server_ip, server_port, client_ip, time in raw_record_tuples:
        if is_ipv4_address(client_ip) and is_public_ip(client_ip) and client_ip != server_ip:
            client_ips.add(client_ip)
            server_ips.add(server_ip)
            server_ip_ports.add((server_ip, server_port))
            server_ip_port_patterns.add(
                (server_ip, server_port, patternName))
            record_tuples.add(
                (server_ip, server_port, client_ip, time))
    return client_ips, server_ips, server_ip_ports, server_ip_port_patterns, record_tuples


def dynamic_valid_improved(engine: str, patternName: str, server_ips: set, record_dir: str, save_dir=None):
    if save_dir is None:
        save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    for root, _, fs in os.walk(record_dir):
        for f in fs:
            fp = os.path.join(root, f)
            with open(fp, 'r') as wf:
                data = json.load(wf)
            results = process_res_from_engine(data, engine)
            threads = []
            for record in results:
                host, port = extract_info_from_file(record, engine)
                if host not in server_ips:
                    continue

                if patternName.lower() in ['http_x_ms_forbidden_ip'] and engine == 'fofa':
                    host = record[1]

                # extract_info_from_file(record,engine)
                # exit(0)
                t = Thread(target=pingImproved,
                           args=(host, port, engine, patternName, save_dir))
                threads.append(t)
                t.start()
            # wait for the threads to complete
            for t in threads:
                t.join()
    return workdir


def dynamic_valid(engine: str, patternName: str, server_ips: set, record_dir: str, save_dir=None):
    if save_dir is None:
        save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    for root, _, fs in os.walk(record_dir):
        for f in fs:
            fp = os.path.join(root, f)
            with open(fp, 'r') as wf:
                data = json.load(wf)
            results = process_res_from_engine(data, engine)
            threads = []
            for record in results:
                host, port = extract_info_from_file(record, engine)
                if host not in server_ips:
                    continue

                if patternName.lower() in ['http_x-ms-forbidden-ip'] and engine == 'fofa':
                    host = record[1]

                # extract_info_from_file(record,engine)
                # exit(0)
                t = Thread(target=ping,
                           args=(host, port, engine, patternName, save_dir))
                threads.append(t)
                t.start()
            # wait for the threads to complete
            for t in threads:
                t.join()
    return workdir


def getFOFAUrl2Port():
    rootDir = ''
    allDict = dict()

    for root, ds, fs in os.walk(rootDir):
        for f in fs:
            fp = os.path.join(root, f)
            with open(fp, 'r') as rf:
                data = json.load(rf)
            for record in data['results']:
                # print(record)
                value = record[1]+':'+record[2]
                # print(key)
                key = record[0]+':'+record[2]
                # print(record)
                # exit()
                allDict[key] = value
    with open('', 'w') as wf:
        json.dump(allDict, wf, ensure_ascii=True, indent=4)


def fofaUrl2ipPort(key: str):
    with open('', 'r') as rf:
        data = json.load(rf)
    if key in data:
        return data[key]
    else:
        return ''


def ping(host: str, port: int, engine: str, patternName: str, save_dir=None):
    # host,port=extract_info_from_file(record,engine)
    if save_dir is None:
        save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    dst_ip = (host).replace('.', '_')
    dst_ip = dst_ip.replace(':', '_')
    dst_ip = dst_ip.replace('/', '_')

    save_filename = os.path.join(workdir, f'{dst_ip}_{port}.txt')
    if os.path.exists(save_filename):
        return
    if patternName.lower() in ['mysql', 'tenor', 'http_400_node', 'http_400_watchguard', 'smtp_not_accept', 'esmtp_connection', 'http_proxy_ip']:
        output = nc_ping(host, port)
    elif patternName.lower() in ['http_407', 'http_x_forwarded_for', 'http_x_real_ip', 'http_src_ip', 'http_client_ip', 'http_cip', 'http_login_ip', 'http_header_sip', 'http_header_access_deny', 'http_dsc_real_ip', 'http_bd_ip', 'http_remote_addr', 'http_cdn_user_ip', 'http_xhs-real-ip', 'http_remote_ip', 'http_x_remote_addr', 'http_tc_web_cookies', 'http_snkz', 'http_ip_address', 'http_client_address', 'http_source_ip', 'http_x-ms-forbidden-ip', 'http_kt_ips', 'http_x-remote-ip', 'http_flowip', 'http-x-rate-limit-request-remote-addr', 'http-api-user-ip', 'http_wx-client', 'http_real_ipd', 'http_yhip',
                                 'http_x_source_ip', 'http-x-response-cinfo', 'http-x-your-address-is', 'http-x-wbx-about'
                                 ]:
        output = curl_ping(host, port)
    elif patternName.lower() in ['http_x-ms-forbidden-ip']:
        output = curl_ping_domain(host, port)

    elif patternName.lower() in ['http_block_ip']:
        output = curl_ping_09(host, port)

    elif patternName.lower() in ['http_body1']:
        output = web_ping(host, port)
    elif patternName.lower() in ['ms_smtp_hello', 'smtp_client_reject']:
        output = telnet_ping(host, port)

    elif patternName.lower() in ['zxfs_ftp']:
        output = ftp_ping(host, port)

    elif patternName.lower() in ['esmtp_hello', 'smtp_ptr']:
        output = smtp_ping(host, port)

    elif patternName.lower() in ['esmtp_mailenable']:
        output = esmtp_windows_ping(host, port)

    with open(save_filename, 'w') as wf:
        wf.write(output)
    return output

def pingImproved(host: str, port: int, engine: str, patternName: str, save_dir=None):
    # host,port=extract_info_from_file(record,engine)
    if save_dir is None:
        save_dir = f''
    workdir = set_work_dir(save_dir, patternName)
    dst_ip = (host).replace('.', '_')
    dst_ip = dst_ip.replace(':', '_')
    dst_ip = dst_ip.replace('/', '_')

    save_filename = os.path.join(workdir, f'{dst_ip}_{port}.txt')
    if os.path.exists(save_filename):
        return
    command=patternDB[patternName]['interactionMethod'].format(host,port)
    output=command_execute(command)

    with open(save_filename, 'w') as wf:
        wf.write(output)
    return output



def extract_valid_ip(engine: str, patternName: str, pingResPath: str, record_tuples: set, save_dir=None):
    if save_dir is None:
        save_dir = f''
    valid_client_ips = set()
    valid_server_ips = set()
    valid_server_ip_ports = set()
    valid_server_ip_port_flags = dict()
    valid_server_ip_port_patterns = set()
    valid_record_tuples = set()
    # protocol = patternName.split('_')[0].lower()
    for root, _, fs in os.walk(pingResPath):
        for f in fs:
            fp = os.path.join(root, f)
            flag = checkLeakImproved(fp, patternName)
            if flag:
                server_ip = ".".join(f.split('_')[:-1])
                port = int((f.split('_')[-1]).split('.')[0])
                valid_server_ips.add(server_ip)
                valid_server_ip_ports.add((server_ip, port))
                valid_server_ip_port_flags[f'{server_ip}_{port}'] = flag

                valid_server_ip_port_patterns.add(
                    (server_ip, port, patternName))

    for server_ip, server_port, client_ip, time in record_tuples:

        if patternName.lower() in ['http_x-ms-forbidden-ip'] and engine == 'fofa':
            value = fofaUrl2ipPort(f'{server_ip}:{server_port}')
            # print(value)
            if not len(value):
                print(f'{server_ip}:{server_port} not in fofaUrl2ipPort_v1')
                continue
            try:

                vslt = value.split(':')
                server_port = vslt[-1]
                server_ip = ':'.join(vslt[:-1])
            except Exception as e:
                # print(e)
                # print(f'{value}----{server_ip}:{server_port} not in fofaUrl2ipPort_v2')
                continue

        if (str(server_ip), int(server_port)) in valid_server_ip_ports:
            if valid_server_ip_port_flags[f'{server_ip}_{server_port}'] == 3:
                client_ip = '.'.join(client_ip.split('.')[
                                     ::-1])  # reverse=True
            valid_client_ips.add(client_ip)
            valid_record_tuples.add((server_ip, server_port, client_ip, time))
    return valid_client_ips, valid_server_ips, valid_server_ip_ports, valid_server_ip_port_patterns, valid_record_tuples


def all_process_improved(engine: str, patternName: str, save_dir=None, recordNum=10000, startPage=1):
    if save_dir is None:
        save_dir = f''
    work_dir = set_work_dir(save_dir, patternName)

    save_info_file = os.path.join(work_dir, f'{engine}_{patternName}_info.txt')
    save_record_tuple_file = os.path.join(
        work_dir, f'{engine}_{patternName}_record_tuple.txt')

    if not os.path.exists(save_info_file):
        os.system(
            f'echo "engine is {engine}, pattern is {patternName}" > {save_info_file}')

    print("step1: get record from three search engine")
    # print(123)
    # step1: get record from three search engine
    recordNum, recordDir = get_records_by_pattern_improved(
        engine, patternName, startPage=startPage)
    os.system(
        f'echo "recordDir is {recordDir}, recordNum is {recordNum}" >> {save_info_file}')

    # if not os.path.exists(save_record_tuple_file):
    print("step2: extract client_ip and server_ip and filter")
    # step2: extract client_ip and server_ip and filter
    raw_record_tuples = extract_info_from_record_improved(
        engine, patternName)

    client_ips, server_ips, server_ip_ports, server_ip_port_patterns, record_tuples = static_filter(
        raw_record_tuples, engine, patternName)


    with open(save_record_tuple_file, 'w') as wf:
        wf.write(str(record_tuples))
    os.system(
        f'echo "length of client_ips is {len(client_ips)}, length of server_ip_ports is {len(server_ip_ports)}" >> {save_info_file}')

    print("step3 check valid through interaction")
    # step3 check valid through interaction

    print('dynamic_valid.....')
    pingResPath = dynamic_valid_improved(engine, patternName, server_ips, recordDir)

    print('extract valid client_ip and server_ip....')

    valid_client_ips, valid_server_ips, valid_server_ip_ports, valid_server_ip_port_patterns, valid_record_tuples = extract_valid_ip(
        engine, patternName, pingResPath, record_tuples)

    save_valid_client_ips = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_client_ips.txt')
    with open(save_valid_client_ips, 'w') as wf:
        wf.write(str(valid_client_ips))

    save_valid_server_ips = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_server_ips.txt')
    with open(save_valid_server_ips, 'w') as wf:
        wf.write(str(valid_server_ips))

    save_valid_server_ip_ports = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_server_ip_ports.txt')

    with open(save_valid_server_ip_ports, 'w') as wf:
        wf.write(str(valid_server_ip_ports))

    save_valid_server_ip_port_patterns = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_server_ip_port_patterns.txt')

    with open(save_valid_server_ip_port_patterns, 'w') as wf:
        wf.write(str(valid_server_ip_port_patterns))

    save_valid_record_tuples = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_record_tuples.txt')

    with open(save_valid_record_tuples, 'w') as wf:
        wf.write(str(valid_record_tuples))

    os.system(
        f'echo "length of valid_client_ips is {len(valid_client_ips)} , length of valid_server_ips is {len(valid_server_ips)}" >> {save_info_file}')
    os.system(
        f'echo "length of valid_server_ip_ports is {len(valid_server_ip_ports)} , length of valid_server_ip_port_patterns is {len(valid_server_ip_port_patterns)}" >> {save_info_file}')
    os.system(
        f'echo "length of valid_record_tuples is {len(valid_record_tuples)} " >> {save_info_file}')


def all_process(engine: str, patternName: str, save_dir=None, recordNum=10000, startPage=1):
    if save_dir is None:
        save_dir = f''
    work_dir = set_work_dir(save_dir, patternName)

    save_info_file = os.path.join(work_dir, f'{engine}_{patternName}_info.txt')
    save_record_tuple_file = os.path.join(
        work_dir, f'{engine}_{patternName}_record_tuple.txt')

    if not os.path.exists(save_info_file):
        os.system(
            f'echo "engine is {engine}, pattern is {patternName}" > {save_info_file}')

    print("step1: get record from three search engine")
    # step1: get record from three search engine
    recordNum, recordDir = get_records_by_pattern(
        engine, patternName, startPage=startPage)
    os.system(
        f'echo "recordDir is {recordDir}, recordNum is {recordNum}" >> {save_info_file}')

    # if not os.path.exists(save_record_tuple_file):
    print("step2: extract client_ip and server_ip and filter")
    # step2: extract client_ip and server_ip and filter
    raw_record_tuples = extract_info_from_record(
        engine, patternName)

    client_ips, server_ips, server_ip_ports, server_ip_port_patterns, record_tuples = static_filter(
        raw_record_tuples, engine, patternName)


    with open(save_record_tuple_file, 'w') as wf:
        wf.write(str(record_tuples))
    os.system(
        f'echo "length of client_ips is {len(client_ips)}, length of server_ip_ports is {len(server_ip_ports)}" >> {save_info_file}')

    print("step3 check valid through interaction")
    # step3 check valid through interaction

    print('dynamic_valid.....')
    pingResPath = dynamic_valid(engine, patternName, server_ips, recordDir)

    print('extract valid client_ip and server_ip....')

    valid_client_ips, valid_server_ips, valid_server_ip_ports, valid_server_ip_port_patterns, valid_record_tuples = extract_valid_ip(
        engine, patternName, pingResPath, record_tuples)

    save_valid_client_ips = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_client_ips.txt')
    with open(save_valid_client_ips, 'w') as wf:
        wf.write(str(valid_client_ips))

    save_valid_server_ips = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_server_ips.txt')
    with open(save_valid_server_ips, 'w') as wf:
        wf.write(str(valid_server_ips))

    save_valid_server_ip_ports = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_server_ip_ports.txt')

    with open(save_valid_server_ip_ports, 'w') as wf:
        wf.write(str(valid_server_ip_ports))

    save_valid_server_ip_port_patterns = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_server_ip_port_patterns.txt')

    with open(save_valid_server_ip_port_patterns, 'w') as wf:
        wf.write(str(valid_server_ip_port_patterns))

    save_valid_record_tuples = os.path.join(
        work_dir, f'{engine}_{patternName}_valid_record_tuples.txt')

    with open(save_valid_record_tuples, 'w') as wf:
        wf.write(str(valid_record_tuples))

    os.system(
        f'echo "length of valid_client_ips is {len(valid_client_ips)} , length of valid_server_ips is {len(valid_server_ips)}" >> {save_info_file}')
    os.system(
        f'echo "length of valid_server_ip_ports is {len(valid_server_ip_ports)} , length of valid_server_ip_port_patterns is {len(valid_server_ip_port_patterns)}" >> {save_info_file}')
    os.system(
        f'echo "length of valid_record_tuples is {len(valid_record_tuples)} " >> {save_info_file}')


def main_old():
    engines = ['shodan', 'fofa', 'zoomeye']
    patternNames = ['HTTP_X_Source_Ip', 'http_source_ip', 'http_client_address', 'http_yhip',
                    'http_real_ipd', 'HTTP-Api-User-Ip', 'HTTP_Wx-Client', 'http_X-Remote-Ip',
                    'http_kt_ips', 'http_ip_address',
                    'http_snkz', 'http_tc_web_cookies_1',
                    'HTTP_X_Remote_Addr', 'HTTP_Remote_Ip', 'HTTP_Xhs-Real-Ip',
                    'HTTP_CDN_User_IP', 'HTTP_client_ip', 'http-x-wbx-about']
    patternNames = ['HTTP_SRC_IP', 'HTTP_client_ip', 'HTTP_CIP', 'HTTP_Login_IP', 'HTTP_Header_SIP', 'HTTP_Header_Access_Deny',
                    'HTTP_DSC_Real_IP', 'HTTP_BD_IP', 'HTTP_Remote_Addr', 'HTTP_CDN_User_IP',
                    'HTTP_Xhs-Real-Ip', 'HTTP_Remote_Ip', 'HTTP_X_Remote_Addr', 'http_tc_web_cookies',
                    'http_snkz', 'http_ip_address', 'http_client_address', 'http_source_ip', 'http_kt_ips',
                    'http_X-Remote-Ip', 'HTTP-X-Rate-Limit-Request-Remote-Addr', 'HTTP-Api-User-Ip',
                    'HTTP_Wx-Client', 'http_real_ipd', 'http_yhip',
                    'HTTP_X_Source_Ip', 'http-x-response-cinfo', 'http-x-your-address-is', 'http-x-wbx-about']

    patternNames = ['HTTP_DSC_REAL_IP','HTTP_Remote_Ip',
                    'http_snkz', 'http_ip_address', 'http_client_address', 'http_source_ip', 'http_kt_ips',
                    'http_X-Remote-Ip', 'HTTP-X-Rate-Limit-Request-Remote-Addr', 'HTTP-Api-User-Ip',
                    'HTTP_Wx-Client', 'http_real_ipd', 'http_yhip',
                    'HTTP_X_Source_Ip', 'http-x-response-cinfo', 'http-x-your-address-is', 'http-x-wbx-about']

    for engine in engines[0:1]:
        for patternName in patternNames:
            try:
                all_process(engine, patternName)
            except Exception as e:
                print(e)
                continue
            notice(f'finish {engine} {patternName}')


def main_improved():
    engines=['shodan']
    with open('','r') as rf:
        http_encode_patternInfos=json.load(rf)
    
    for patternName in http_encode_patternInfos:
    
        # patternName='http_encode_user_ip'    
        for engine in engines:
            try:
                all_process_improved(engine, patternName)
            except Exception as e:
                # print(e)
                notice(f'error {engine} {patternName} : {e}')
                continue
            notice(f'finish {engine} {patternName}')


    notice('finish all')
if __name__ == "__main__":
    main_improved()

