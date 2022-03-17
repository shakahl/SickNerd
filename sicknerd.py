#!/usr/bin/env python

import argparse
import os
import re
import sys
import time
import urllib.error
from datetime import datetime
from random import randint
from random import shuffle
from random import uniform

import googlesearch as gsearch
import pandas as pd
import requests
from bs4 import BeautifulSoup
from colorama import init


def kill_cookie():
    """
    Removes generated google cookie file
    """
    if os.path.exists('.google-cookie'):
        os.remove('.google-cookie')


def message(msg, title=False, stat=False, word=False, banner=False):
    """
    Prints formatted text to CLI
    """

    class Colors:
        BLUE = '\033[94m'
        GREEN = "\033[32m"
        YELLOW = '\033[93m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    banner_text = """.▄▄ · ▪   ▄▄· ▄ •▄  ▐ ▄ ▄▄▄ .▄▄▄  ·▄▄▄▄  
▐█ ▀. ██ ▐█ ▌▪█▌▄▌▪•█▌▐█▀▄.▀·▀▄ █·██▪ ██ 
▄▀▀▀█▄▐█·██ ▄▄▐▀▀▄·▐█▐▐▌▐▀▀▪▄▐▀▀▄ ▐█· ▐█▌
▐█▄▪▐█▐█▌▐███▌▐█.█▌██▐█▌▐█▄▄▌▐█•█▌██. ██ 
 ▀▀▀▀ ▀▀▀·▀▀▀ ·▀  ▀▀▀ █▪ ▀▀▀ .▀  ▀▀▀▀▀▀• """

    if title:
        print(f'{Colors.GREEN}{Colors.BOLD}[*] {msg}{Colors.ENDC}')
    elif stat:
        print(f'{Colors.BLUE}{msg}{Colors.ENDC}')
    elif word:
        return f'{Colors.YELLOW}{Colors.BOLD}{msg}{Colors.ENDC}{Colors.BLUE}'
    elif banner:
        print(f'{Colors.YELLOW}{banner_text}{Colors.ENDC}')


def fetch_ghdb(dork_str, years_int):
    """
    Fetches list of dorks from GHDB and filters them
    :param dork_str:
    :param years_int:
    :return:
    """
    url = "https://www.exploit-db.com/google-hacking-database"
    message(f'Requesting data from {message(str(url), word=True)}...', stat=True)

    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Encoding": "deflate, gzip, br",
        "Accept-Language": "en-US",
        "User-Agent": str(gsearch.get_random_user_agent().decode("utf-8")),
        "X-Requested-With": "XMLHttpRequest",
    }
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        message('Got 429 while fetching! Sleeping!', title=True)
        time.sleep(randint(60, 90))
        return fetch_ghdb(dork_str, years_int)

    ghdb_data = pd.read_json(response.text, orient='values')
    ghdb_data = pd.json_normalize(ghdb_data['data'])

    category_dict = {
        'all': ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
        'footholds': ['1'],
        'dir': ['3'],
        'web': ['4'],
        'usernames': ['2'],
        'servers': ['6'],
        'errors': ['7'],
        'juicy': ['8'],
        'passwords': ['9'],
        'shopping': ['10'],
        'login': ['12'],
        'devices': ['13'],
        'vulns': ['5', '11', '14'],
        'tothemoon': ['1', '3', '5', '8', '9', '11', '14']
    }

    if category_dict.get(str(dork_str)) is not None:
        pass
    else:
        message('Key not found! Defaulting to standard list.', stat=True)
        category_dict[str(dork_str)] = ['']

    message(
        f'Searching for {message(str(dork_str), word=True)} dorks from the past {message(str(int(years_int)), word=True)} years...',
        stat=True)
    ghdb_data['date'] = pd.to_datetime(ghdb_data['date'])
    ghdb_data = ghdb_data[(ghdb_data['date'] > datetime.today() - pd.Timedelta(weeks=int(years_int) * 52)) & ghdb_data[
        'category.cat_id'].isin(category_dict[str(dork_str)])]
    rtrn_dork_lst = \
        pd.DataFrame(
            ghdb_data['url_title'].apply(lambda x: (BeautifulSoup(str(x), features="html.parser").get_text())))[
            'url_title'].to_list()
    return rtrn_dork_lst


class SickNerd:
    def __init__(self, hosts_df, dorks_lst, passive=False):
        self.df = hosts_df
        self.df.drop_duplicates(subset=['HOSTNAME'], inplace=True)
        self.int429 = 0

        # check if it exists in cwd and then read in else make empty
        if os.path.exists(os.path.join(args.output, 'sicknerd-output.csv')):
            self.output_df = pd.read_csv(os.path.join(args.output, 'sicknerd-output.csv'))
            try:
                self.output_df.drop(columns=['HTTP CODE', 'TITLE', 'CONTENT LENGTH'], inplace=True)
            except KeyError:
                pass
            message(f'Loaded output file with {message(len(self.output_df), word=True)} records', stat=True)
        else:
            self.output_df = pd.DataFrame(columns=['QUERY', 'URL'])

        # check if it exists in cwd and then read in else make empty
        if os.path.exists(os.path.join(args.output, 'sicknerd-attempts.csv')):
            self.attempt_df = pd.read_csv(os.path.join(args.output, 'sicknerd-attempts.csv'))
            message(f'Loaded attempt file with {message(len(self.attempt_df), word=True)} records', stat=True)
        else:
            self.attempt_df = pd.DataFrame(columns=['QUERY'])

        self.validate_bool = passive
        if len(dorks_lst) > 0:
            self.dorks_lst = dorks_lst
        else:
            self.dorks_lst = ['filetype:doc', 'filetype:docx', 'filetype:odp', 'filetype:ods', 'filetype:ott',
                              'filetype:rtf', 'filetype:txt', 'filetype:ppt', 'filetype:pptx', 'filetype:csv',
                              'filetype:pdf', 'filetype:xls', 'filetype:xlsx', 'filetype:7z', 'filetype:bz2',
                              'filetype:gz', 'filetype:rar', 'filetype:sql', 'filetype:sql.7z', 'filetype:sql.bz2',
                              'filetype:sql.gz', 'filetype:sql.rar', 'filetype:sql.sql', 'filetype:sql.tar',
                              'filetype:sql.tar.bz2',
                              'filetype:sql.tar.bzip2', 'filetype:sql.tar.gz', 'filetype:sql.tar.gzip',
                              'filetype:sql.tgz', 'filetype:sql.zip',
                              'filetype:sqlite', 'filetype:tar', 'filetype:tar.bz2', 'filetype:tar.bzip2',
                              'filetype:tar.gz', 'filetype:tar.gzip', 'filetype:tgz', 'filetype:zip', 'filetype:bat',
                              'filetype:key', 'filetype:env', 'filetype:log', 'filetype:ini',
                              'filetype:yaml', 'filetype:swagger', 'filetype:mail', 'filetype:config']
        message(f'Loaded {message(str(len(self.dorks_lst)), word=True)} dorks...', stat=True)

    def start_query(self):
        """
        Starts searching the dorks
        :return: none
        """
        message('Starting searches...', title=True)
        message(f'Max {message(str(args.max), word=True)} results per query', stat=True)
        shuffle(self.dorks_lst)
        for d in self.dorks_lst:
            for h in self.df['HOSTNAME']:
                tld_str = self.df.HOSTNAME.str.split('.').iloc[0][1]
                site_str = f'site:{str(h)} '
                # checks if it has been queried already
                if self.output_df.loc[self.output_df['QUERY'].str.fullmatch(site_str + str(d), case=False)].shape[
                    0] == 0 and self.attempt_df.loc[
                    self.attempt_df['QUERY'].str.fullmatch(site_str + str(d), case=False)].shape[0] == 0:
                    try:
                        self.search(site_str + str(d), tld_str)
                    except urllib.error.URLError as e:
                        message(
                            f'Failed to query {message(str(site_str + str(d)), word=True)} reason {message(str(e.reason), word=True)}',
                            stat=True)
            self.write_output()

        if not self.validate_bool:
            self.start_validation()

    def start_validation(self):
        message('Validating results...', title=True)
        valid_df = pd.DataFrame(self.output_df['URL'].apply(lambda x: self.validate(x)).tolist(),
                                columns=['HTTP CODE', 'TITLE', 'CONTENT LENGTH'])
        self.output_df = pd.concat([self.output_df, valid_df], axis=1)
        self.write_output(final=True)

    def write_output(self, final=False):
        """
        Writes output df to csv file
        :param final: bool if final output
        :return: none
        """
        self.output_df.to_csv('sicknerd-output.csv', index=False)
        self.attempt_df.to_csv('sicknerd-attempts.csv', index=False)
        if final:
            message(f'Writing {message(str(self.output_df.shape[0]), word=True)} results to file', stat=True)
            self.output_df.to_csv(os.path.join(args.output, 'sicknerd-output.csv'), index=False)
            self.attempt_df.to_csv('sicknerd-attempts.csv', index=False)

    def search(self, search_str, tld_str, sleep_int=120):
        """
        Searches via the google api. If 429 sleep then recall recursively.
        :param search_str: string to search
        :param tld_str: string of tld
        :return: none, appends to df
        """
        kill_cookie()
        ua_str = gsearch.get_random_user_agent().decode("utf-8")
        wait_int = randint(5, 10)
        wait_flux = uniform(5, 30)
        count = 0
        try:
            for i in gsearch.search(str(search_str), tld=str(tld_str), num=30, stop=int(args.max),
                                    pause=wait_int + wait_flux,
                                    user_agent=ua_str):
                self.output_df.loc[self.output_df.shape[0]] = [search_str, str(i)]
                count += 1
            message(f'Found {message(str(count), word=True)} results from {message(search_str, word=True)}', stat=True)
            if count <= 0:
                self.attempt_df.loc[self.attempt_df.shape[0]] = [search_str]
        except urllib.error.HTTPError as e:
            message(f'Got {message(str(e), word=True)} while searching {message(str(search_str), word=True)}',
                    stat=True)
            message(f'Sleeping for atleast {message(str(int(sleep_int / 60)), word=True)} minutes', stat=True)
            time.sleep(randint(sleep_int, sleep_int + 240) + wait_flux)
            self.search(search_str, tld_str, sleep_int * 2)

    def validate(self, url):
        """
        Requests url and returns information. If 429 recursively calls again.
        :param url: str
        :return: list containing status code, title, and content-length
        """
        ua_str = gsearch.get_random_user_agent().decode("utf-8")
        try:
            resp = requests.get(str(url), headers={'User-Agent': str(ua_str)}, timeout=10)
        except requests.exceptions.RequestException:
            return ['ERROR', 'ERROR', 'ERROR']

        if resp.status_code == 429:
            message('Got 429 while validating! Sleeping!', title=True)
            time.sleep(randint(60, 90))
            self.int429 += 1
            if self.int429 < 3:
                return self.validate(url)
            else:
                return ['ERROR', 'ERROR', 'ERROR']
        else:
            try:
                title = re.search('<\W*title\W*(.*)</title', resp.text, re.IGNORECASE).group(1)
            except AttributeError:
                title = 'NONE'
            try:
                return [resp.status_code, str(title), resp.headers['Content-length']]
            except KeyError:
                return [resp.status_code, str(title), 'NONE']


if __name__ == '__main__':
    # colorama
    init()
    parser = argparse.ArgumentParser(description='CLI tool for making Google Dorking a passive recon experience')
    dork_grp = parser.add_mutually_exclusive_group()
    parser.add_argument("-i", "--input", action="store", default='yourfilenamehere',
                        help='Input list of domains (no subdomains).')
    parser.add_argument("-o", "--output", action="store", default=os.getcwd(),
                        help="Prints and loads CSV files to directory. The default is cwd.")
    dork_grp.add_argument("-f", "--fetch", action="store", default=False,
                          help="Fetches lists of dorks from GHDB. Accepts one of the following: all, footholds, dir, "
                               "web, usernames, servers, errors, juicy, passwords, shopping, login, devices, "
                               "vulns (optional)")
    dork_grp.add_argument("-d", "--dorks", action="store", default=[],
                          help="List of Dorks to test (optional)")
    parser.add_argument("-p", "--passive", action="store_true", default=False,
                        help="Skip the validation requests and only do passive checks.")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                        help="Hides banner")
    parser.add_argument("-y", "--years", action="store", default=2,
                        help="Number of years to fetch dorks from. Default is 2.")
    parser.add_argument("-m", "--max", action="store", default=30,
                        help="Max number of results per query. Default is 30.")
    args = parser.parse_args()

    if args.output:
        if args.output == '-':
            args.output = os.getcwd()

    if args.dorks:
        args.dorks = open(args.dorks, "r").read().split('\n')

    if not sys.stdin.isatty() and args.input:
        args.input = sys.stdin

    try:
        if not args.quiet:
            message('', banner=True)
        if args.input:
            df = pd.read_table(args.input, header=None, names=['HOSTNAME'])
            df['HOSTNAME'] = df['HOSTNAME'].astype(str)
    except FileNotFoundError:
        print('No input file found')
        exit()
    try:
        if args.fetch:
            dork_df = fetch_ghdb(args.fetch, args.years)
            dorker = SickNerd(df, dork_df, args.passive)
            dorker.start_query()
            kill_cookie()
        else:
            dorker = SickNerd(df, args.dorks, args.passive)
            dorker.start_query()
            kill_cookie()
    except KeyboardInterrupt:
        if args.passive:
            message('CTRL + C pressed! Writing output then ending...', title=True)
            kill_cookie()
            dorker.write_output(final=True)
            exit()
        else:
            message('CTRL + C pressed! Starting validation then writing output...', title=True)
            dorker.start_validation()
            kill_cookie()
            dorker.write_output(final=True)
            exit()
