#  Copyright (c) 2023.
#
#  @Bin4xin. SENTINEL CYBER SEC All Rights Reserved.
#  @Link https://github.com/Bin4xin


import mmh3
import sys
import codecs
import requests
import hashlib
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ExceptionReturn(Exception):

    def __init__(self, exception_message=None):
        self.exception_message = exception_message

    def returnException(self):
        error_info = Fore.RED + '[ERROR]: {}'.format(self.exception_message)
        return error_info

    def returnInformation(self):
        Information_info = Fore.GREEN + '[INFO]: {}'.format(self.exception_message)
        return Information_info

    def returnRunning(self):
        Running_info = Fore.BLUE + '[RUNNING]: {}'.format(self.exception_message)
        return Running_info

    def returnAssetsInfo(self):
        Assets_Info = Fore.YELLOW + '[DB INFO]: {}'.format(self.exception_message)
        return Assets_Info


def download_favicon(url):
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        return response.content
    else:
        return None


def calculate_md5(content):
    md5_hash = hashlib.md5()
    md5_hash.update(content)
    return md5_hash.hexdigest()


def travelDictParser(node, target_key):
    results = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == target_key:
                results.append(value)
            results.extend(travelDictParser(value, target_key))
    elif isinstance(node, list):
        for item in node:
            results.extend(travelDictParser(item, target_key))
    return results


def finger_print_detected(fofa_hash, censys_hash):
    import yaml
    with open('./finger-prints.yaml', 'rb') as f:
        finger_print_data = yaml.load(f, Loader=yaml.SafeLoader)
    task_names = travelDictParser(finger_print_data, 'favicon_name')
    task_fofa_hashes = travelDictParser(finger_print_data, 'fofa_hash')
    task_censys_hashes = travelDictParser(finger_print_data, 'censys_hash')
    task_assets_urls = travelDictParser(finger_print_data, 'url_desc')
    print(ExceptionReturn(f"{task_names}:{task_assets_urls}").returnAssetsInfo())

    for task_name, task_fofa_hash, task_censys_hash, task_assets_url in zip(task_names,
                                                                            task_fofa_hashes,
                                                                            task_censys_hashes,
                                                                            task_assets_urls):
        if str(fofa_hash).strip() == str(task_fofa_hash).strip():
            print(ExceptionReturn(f"DETECTED FINGERPRINT BY FOFA HASHES: [{fofa_hash}]: [{task_name}], "
                                  f"desc url: [{task_assets_url}]").returnInformation())
        elif str(censys_hash).strip() == str(task_censys_hash).strip():
            print(ExceptionReturn(f"DETECTED FINGERPRINT BY CENSYS HASHES: [{censys_hash}]: [{task_name}], "
                                  f"desc url: [{task_assets_url}]").returnInformation())

        else:
            print(ExceptionReturn(f"HASHES {fofa_hash} or {censys_hash} UNMATCH {task_name}. "
                                  f"PLZ Check by API, or HELP US GREATER.").returnRunning())


if len(sys.argv) != 2:
    print(ExceptionReturn(f"Usage: {sys.argv[0]} [Favicon URL]").returnException())
    sys.exit(0)

try:
    favicon_content = download_favicon(sys.argv[1])
    favicon = codecs.encode(favicon_content, 'base64')
    hash = mmh3.hash(favicon)
    hash_string = str(hash)
    md5_hash = hashlib.md5(hash_string.encode('utf-8')).hexdigest()
    md5_hash_Censys = calculate_md5(favicon_content)
    print(ExceptionReturn(f"Fofa api: [\"icon_hash={hash}\"]").returnRunning())
    print(ExceptionReturn(f"Censys api: [\"services.http.response.favicons.md5_hash={md5_hash_Censys}\"]").returnRunning())

    finger_print_detected(hash, md5_hash_Censys)
except Exception as e:
    print(ExceptionReturn(f"Error occurred as: {e}").returnException())
