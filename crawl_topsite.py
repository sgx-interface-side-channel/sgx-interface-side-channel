#-*- coding:utf-8 -*-
import requests
from bs4 import BeautifulSoup
import cpabe


def retrive_url(url: str, name : str):
    try:
        res = requests.get(url)
        with open(name,"w") as f:
            f.write(res.text)
    except requests.RequestException:
        url_split = url.split('//')
        if 'www.' not in url_split[1]:
            formated_url = url_split[0]+"//www."+url_split[1]
            try:
                res = requests.get(formated_url)
                with open(name, "w") as f:
                    f.write(res.text)
            except Exception as e:
                print(e)


if __name__ == '__main__':
    # r = requests.get('http://stuffgate.com/stuff/website/top-1000-sites')
    r = requests.get('http://stuffgate.com/stuff/website/top-2000-sites')
    # print(r.headers)
    content = r.content
    soup = BeautifulSoup(content, 'lxml')
    tbody = soup.find('tbody')
    url_list = []
    for tr in tbody.find_all('tr'):
        td = tr.find_all('td')[1]
        url_split = td.a['href'].split('//')
        retrive_url(td.a['href'], 'Web/'+url_split[1]+'.pcap')

