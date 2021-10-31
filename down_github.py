import threading, requests
from queue import Queue
from lxml import etree
import pymysql, datetime

lock = threading.Lock()
lock2 = threading.Lock()

month = {
    'Jan': '01',
    'Feb': '02',
    'Mar': '03',
    'Apr': '04',
    'May': '05',
    'Jun': '06',
    'Jul': '07',
    'Aug': '08',
    'Sep': '09',
    'Oct': '10',
    'Nov': '11',
    'Dec': '12',
}

ioc_data = {
    '蠕虫': ['iw_wormlist.ipset'],
    '欺诈': ['hphosts_fsa.ipset'],
    '漏洞利用': ['hphosts_exp.ipset'],
    '广告服务器': ['hphosts_ats.ipset', 'hphosts_mmt.ipset', 'iblocklist_yoyo_adservers.netset'],
    '网络机器人': ['botscout_30d.ipset', 'graphiclineweb.netset', 'myip.ipset', 'socks_proxy_30d.ipset',
              'sslproxies_30d.ipset', ],
    # https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset,'firehol_proxies.netset',
    '代理节点': ['maxmind_proxy_fraud.ipset', 'proxylists_30d.ipset', 'proxz_30d.ipset'],
    '扫描节点': ['normshield_all_webscan.ipset', 'normshield_all_dnsscan.ipset'],
    '勒索软件': ['cta_cryptowall.ipset', 'normshield_all_wannacry.ipset', 'ransomware_feed.ipset'],
    '垃圾邮件': ['cleanmx_phishing.ipset', 'cleanmx_viruses.ipset', 'cleantalk_30d.ipset', 'cleantalk_new_30d.ipset',
             'gpf_comics.ipset', 'hphosts_grm.ipset', 'iw_spamlist.ipset', 'lashback_ubl.ipset', 'nixspam.ipset',
             'sblam.ipset', ],
    '色情': ['iblocklist_pedophiles.netset'],
    '钓鱼网址': ['hphosts_psh.ipset'],
    'web攻击': ['cruzit_web_attacks.ipset'],
    '矿池': ['bitcoin_blockchain_info_30d.ipset', 'bitcoin_nodes_30d.ipset', 'coinbl_hosts.ipset', 'coinbl_ips.ipset'],
    'tor': ['dm_tor.ipset'],
    'C2': ['bambenek_c2.ipset', 'asprox_c2.ipset', 'et_botcc.ipset'],
}
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36'
}
session = requests.Session()
session.trust_env = False
g_t_response = requests.get(url='https://github.com/firehol/blocklist-ipsets', headers=headers)
html = etree.HTML(g_t_response.text)
update_time = ''
switch = 0
for i in range(10):
    global_time = html.xpath(
        '/html/body/div[4]/div/main/div[2]/div/div/div[2]/div[1]/div[2]/div[1]/div/div[2]/div[1]//span/a/text()')
    # /html/body/div[4]/div/main/div[2]/div/div/div[2]/div[1]/div[2]/div[1]/div/div[2]/div[1]/span/a
    if global_time:
        time_list = global_time[0].strip().split()
        update_time = time_list[-2] + '-' + time_list[1].replace(time_list[1], month.get(time_list[1])) + '-' + \
                      time_list[2] + ' ' + time_list[3]
        break


class Download(threading.Thread):
    def __init__(self, page_queue, ip_queue):
        threading.Thread.__init__(self)
        self.page_queue = page_queue
        self.time = update_time
        self.ip_queue = ip_queue

    def run(self):
        while True:
            if self.page_queue.empty():
                break
            all_page = [all for all in self.page_queue.get().values()]
            type = all_page[0]
            url = all_page[1]

            self.get_ip(url, type)

    def get_ip(self, url, type):
        session = requests.Session()
        session.trust_env = False

        full_url = f'https://github.com/firehol/blocklist-ipsets/blob/master/{url}'
        response = requests.get(url=full_url, headers=headers)
        html = etree.HTML(response.text)
        update_time = html.xpath(
            '//*[@id="repo-content-pjax-container"]/div/div[2]/div[1]/div/div[1]/div//span/a/text()')
        if update_time != []:
            update_list = update_time[0].strip().split()
            update_time = update_list[-2] + '-' + update_list[1].replace(update_list[1],
                                                                         month.get(update_list[1])) + '-' + update_list[
                              2] + ' ' + update_list[3]
        else:
            update_time = self.time

        ip_list = html.xpath('/html/body//table/tr')
        is_null = []
        l = []
        for ip_obj in ip_list:
            ip_all = ip_obj.xpath('./td[2]/text()')[0]
            is_null.append(ip_all)
        is_ip = [ip for ip in is_null if ip.find('#') == -1]
        if is_ip:
            for ip in is_ip:
                lock.acquire()
                if ip.find('#') == -1:
                    dic = {}
                    dic['ip'] = ip
                    dic['type'] = type
                    dic['update_time'] = update_time
                    dic['insert_time'] = datetime.datetime.now().replace(microsecond=0)
                    dic['download_address'] = full_url
                    self.ip_queue.put(dic)
                lock.release()
        else:
            lock.acquire()
            dic = {}
            dic['type'] = type
            dic['update_time'] = update_time
            dic['insert_time'] = datetime.datetime.now().replace(microsecond=0)
            dic['download_address'] = full_url
            self.ip_queue.put(dic)
            lock.release()


class Storage(threading.Thread):
    def __init__(self, ip_queue, page_queue):
        threading.Thread.__init__(self)
        self.ip_queue = ip_queue
        self.page_queue = page_queue

    def run(self):
        while True:
            if self.ip_queue.empty() and self.page_queue.empty() and switch == 1:
                break
            try:
                data = self.ip_queue.get(timeout=10)
                # print(data)
                self.save(data)

            except Exception as e:
                print(e)
                break

    def save(self, data):
        lock2.acquire()
        all_data = [allip for allip in data.values()]
        if len(all_data)==5:
            ip = str(all_data[0])
            type_a = str(all_data[1])
            update_time = str(all_data[2])
            insert_time = str(all_data[3])
            download_address = str(all_data[4])
            sql = f"insert into threat_intelligence(ip,type,update_time,insert_time,download_address) values('{ip}','{type_a}','{update_time}','{insert_time}','{download_address}')"
            print(ip, type_a, update_time, insert_time, download_address)
        else:
            type_a = str(all_data[0])
            update_time = str(all_data[1])
            insert_time = str(all_data[2])
            download_address = str(all_data[3])
            sql = f"insert into threat_intelligence(type,update_time,insert_time,download_address,information) values('{type_a}','{update_time}','{insert_time}','{download_address}','暂无数据')"
        count = db.execute(sql)
        client.commit()


        lock2.release()
if __name__ == '__main__':
    client = pymysql.Connection(
        user='root',
        passwd='root',
        port=3306,
        host='localhost',
        database='test11'

    )
    db = client.cursor()
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36'
    }
    page_queue = Queue(1000)
    ip_queue = Queue(1000)
    for ioc_type, ioc_url in ioc_data.items():
        for ioc_a_url in ioc_url:
            ioc_all = {}
            ioc_all['type'] = ioc_type
            ioc_all['ioc_a_url'] = ioc_a_url
            page_queue.put(ioc_all)
    d_list = []
    for i in range(42):
        d = Download(page_queue, ip_queue)
        d.start()
        d_list.append(d)

    for i in range(42):
        s = Storage(ip_queue, page_queue)
        s.start()
    for d in d_list:
        d.join()
    switch = 1
