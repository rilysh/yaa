import requests
from bs4 import BeautifulSoup

RED, GREEN, WHITE, ENDCOLOR = "\033[0;91m", "\033[0;92m", "\033[0;97m", "\033[0m"
MAIN_API_URL = "https://mb-api.abuse.ch/api/v1"
BATCH_API_URL = "https://datalake.abuse.ch/malware-bazaar"
VERSION = "0.1"

class MalwareBazaar:
    def yaa_help(self):
        print(
            f"yaa (Yet Another Artefact) - Version {VERSION}\n\n"
            "Usage:\n"
            "   [--dl-hourly]                       -- Download hourly batch of samples\n"
            "   [--dl-daily]                        -- Download daily batch of samples\n"
            "   [--recent-sha256]                   -- Get SHA-256 hash of recent uploaded samples\n"
            "   [--recent-filenames]                -- Get file names of recent uploaded samples\n"
            "   [--recent-reporter]                 -- Get reporter usernames of recent uploaded samples\n"
            "   [--recent-compact]                  -- Get a compact list of recent uploaded samples\n"
            "   [--get-sample SHA256]               -- Download a sample based on the SHA-256 hash\n"
            "   [--get-sample-info SHA256]          -- Get various information about a sample based on the SHA-256 hash\n"
            "   [--list-cscb-info]                  -- Get a list of CSCB based on the sample\n"
            "   [--get-tagged-sample TAG]           -- Get samples based on the tag\n"
            "   [--get-signature-sample SIGNATURE]  -- Get samples based on the signature\n"
            "   [--get-filetype-sample FILETYPE]    -- Get samples based on the filetype\n"
            "   [--get-clamavsig-sample CLAMAVSIG]  -- Get samples based on the ClamAV sugnature\n"
            "   [--get-imphash-sample IMPHASH]      -- Get samples based on the imphash\n"
            "   [--get-tlsh-sample TLSHHASH]        -- Get samples based on the TLSH hash\n"
            "   [--get-telf-sample TELFHASH]        -- Get samples based on the telfhash\n"
            "   [--get-gimp-sample GIMPHASH]        -- Get samples based on the gimphash\n"
            "   [--get-dhash-sample DHASH]          -- Get samples based on the dhash\n"
            "   [--get-yara-sample YARARULE]        -- Get samples based on the yara rule\n\n"

            "Optional arguments (not applicable for all main arguments):\n"
            "   [--limit LIMIT]     -- Specify the limit of the output result\n"
            "   [--save]            -- Write the file to the disk\n"
            "   [--silence]         -- Add a little silence when downloading a sample\n"
            "   [--color]           -- Add color on compact result"
        )

    # Info: Function to download batches from the HTTP server (private)
    # Usage: __batch_download__(string)
    def __batch_download__(self, batch):
        req = requests.get(f"{BATCH_API_URL}/{batch}")
        if req.status_code != 200:
            req.raise_for_status()

        soup = BeautifulSoup(req.content, "html.parser")

        for each_soup in soup.find_all("td"):
            for eat_soup in each_soup.find_all("a"):
                # Ignore any string starts with "/"
                each = eat_soup.get("href")
                if each.startswith("/"):
                    continue

                req = requests.get(f"{BATCH_API_URL}/{batch}/{each}")
                if req.status_code != 200:
                    req.raise_for_status()

                print(f"Got: {each}")

                with open(each, "wb") as f:
                    f.write(req.content)

    # Info: Function to get information about queries (private)
    # Usage: __get_info__()
    def __get_info__(self):
        data = {
            "query": "get_recent",
            "selector": "time"
        }
        req = requests.post(MAIN_API_URL, data=data)
        if req.status_code != 200:
            req.raise_for_status()

        return req.json()["data"]

    # Info: Function to get explanation about a query (private)
    # Usage: __query_type__(string, string, string, integer, boolean)
    def __query_type__(self, type, query, filter, limit = 10, save = False):
        data = {
            "query": query,
            type: filter,
            "limit": limit
        }

        req = requests.post(MAIN_API_URL, data=data)
        if req.status_code != 200:
            req.raise_for_status()

        query_error = req.json()["query_status"]
        if query_error != "ok":
            print(f"API error: {query_error}")
            exit(1)

        data = req.json()["data"]
        for each in data:
            print(
                f"File:         {each['file_name']}\n"
                f"SHA-256:      {each['sha256_hash']}\n"
                f"TLSH:         {each['tlsh']}\n"
                f"First Seen:   {each['first_seen']}\n"
                f"Size:         {each['file_size']}\n"
                f"Mime:         {each['file_type_mime']}\n"
                f"Type:         {each['file_type']}\n"
                f"Reporter:     {each['reporter']}\n"
                f"ClamAV:       {each['intelligence']['clamav'][0] if each['intelligence']['clamav'] != None else None}\n"
                f"Downloads:    {each['intelligence']['downloads']}\n"
            )
            if save == True:
                self.get_sample(each["sha256_hash"], True)
                print(f"Got: {each['sha256_hash']}.zip\n")

    # Info: Function to download hourly batch
    # Usage: download_hourly_batch()
    def download_hourly_batch(self):
        self.__batch_download__("hourly")

    # Info: Function to download daily batch
    # Usage: download_daily_batch()  
    def download_daily_batch(self):
        self.__batch_download__("daily")

    # Info: Function to get recent uploaded files SHA-256 hash
    # Usage: get_recent_sha256() 
    def get_recent_sha256(self):
        json = self.__get_info__()
        for resj in json:
            print(f"SHA-256: {resj['sha256_hash']}")

    # Info: Function to get recent uploaded file names
    # Usage: get_recent_filenames()
    def get_recent_filenames(self):
        json = self.__get_info__()
        for resj in json:
            print(f"File: {resj['file_name']}")

    # Info: Function to get recent uploaded reporter username
    # Usage: get_recent_reporter() 
    def get_recent_reporter(self):
        json = self.__get_info__()
        for resj in json:
            print(f"Reporter: {resj['reporter']}")

    # Info: Function to get a compact information (including SHA-256, TLSH, etc.)
    # Usage: get_recent_compact(boolean (optional))
    def get_recent_compact(self, color = True):
        json = self.__get_info__()
        for resj in json:
            if color == True:
                print(f"{RED}·{ENDCOLOR} {RED}{resj['file_name']}{ENDCOLOR}\n"
                        f"--> {WHITE}{resj['sha256_hash']}{ENDCOLOR}\n"
                        f"--> {GREEN}{resj['reporter']}{ENDCOLOR}")
            else:
                print(f"· {resj['file_name']}\n"
                        f"--> {resj['sha256_hash']}\n"
                        f"--> {resj['reporter']}")

    # Info: Function to download a sample based on SHA-256 hash
    # Usage: get_sample(string, boolean (optional))
    def get_sample(self, sha256, silence = False):
        data = {
            "query": "get_file",
            "sha256_hash": sha256
        }

        req = requests.post(MAIN_API_URL, data=data)
        """
            Alternatively
            re.findall("filename=(.*)", req.headers['Content-Disposition'])[0]
        """
        with open(f"{sha256}.zip", "wb") as w:
            w.write(req.content)

        if silence == False:
            print(f"Got: {sha256}.zip")

    # Info: Function to get information about a sample based on SHA-256 hash
    # Usage: get_sample_info(string)
    def get_sample_info(self, sha256):
        data = {
            "query": "get_info",
            "hash": sha256
        }

        req = requests.post(MAIN_API_URL, data=data)
        if req.status_code != 200:
            req.raise_for_status()

        query_error = req.json()["query_status"]
        if query_error != "ok":
            print(f"API error: {query_error}")
            exit(1)

        json = req.json()["data"][0]
        print(req.json())
        print(
            f"File:         {json['file_name']}\n"
            f"SHA-256:      {json['sha256_hash']}\n"
            f"TLSH:         {json['tlsh']}\n"
            f"First Seen:   {json['first_seen']}\n"
            f"Size:         {json['file_size']}\n"
            f"Mime:         {json['file_type_mime']}\n"
            f"Type:         {json['file_type']}\n"
            f"Reporter:     {json['reporter']}\n"
            f"Origin:       {json['origin_country']}\n"
            f"ClamAV:       {json['intelligence']['clamav'][0] if json['intelligence']['clamav'][0] != None else None}\n"
            f"Downloads:    {json['intelligence']['downloads']}\n"
            f"Sandbox:      {json['file_information'][0]['value'] if json['file_information'] != None else None}"
        )

    # Info: Function to get CSCB info of recently uploaded samples
    # Usage: list_cscb_info()
    def list_cscb_info(self):
        req = requests.post(MAIN_API_URL, data={"query": "get_cscb"})
        if req.status_code != 200:
            req.raise_for_status()

        data = req.json()["data"]
        for each in data:
            print(
                f"Subject:    {each['subject_cn']}\n"
                f"Issuer:     {each['issuer_cn']}\n"
                f"Valid from: {each['valid_from']}\n"
                f"Valid to:   {each['valid_to']}\n"
                f"Timestamp:  {each['time_stamp']}\n"
                f"Serial:     {each['serial_number']}\n"
                f"Thumbprint: {each['thumbprint']}\n"
                f"Reason:     {each['cscb_reason']}\n"
            )

    # Info: Function to get information or download a specifically tagged sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_tagged_sample(self, tag, limit = 10, save = False):
        self.__query_type__("tag", "get_taginfo", tag, limit, save)

    # Info: Function to get information or download a specifically signatuRED sample
    # Usage: get_signature_sample(string, integer (optional), boolean (optional))
    def get_signature_sample(self, signature, limit = 10, save = False):
        self.__query_type__("signature", "get_siginfo", signature, limit, save)

    # Info: Function to get information or download a specific filetype sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_filetype_sample(self, filetype, limit = 10, save = False):
        self.__query_type__("file_type", "get_file_type", filetype, limit, save)

    # Info: Function to get information or download a specific clamav sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_clamavsig_sample(self, clamsig, limit = 10, save = False):
        self.__query_type__("clamav", "get_clamavinfo", clamsig, limit, save)

    # Info: Function to get information or download a specific imphash sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_imphash_sample(self, imphash, limit = 10, save = False):
        self.__query_type__("imphash", "get_imphash", imphash, limit, save)

    # Info: Function to get information or download a specific TLSH hash sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_tlsh_sample(self, tlsh, limit = 10, save = False):
        self.__query_type__("tlsh", "get_tlsh", tlsh, limit, save)

    # Info: Function to get information or download a specific telf hash sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_telfhash_sample(self, telfhash, limit = 10, save = False):
        self.__query_type__("telfhash", "get_telfhash", telfhash, limit, save)

    # Info: Function to get information or download a specific gimphash sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_gimphash_sample(self, gimphash, limit = 10, save = False):
        self.__query_type__("gimphash", "get_gimphash", gimphash, limit, save)

    # Info: Function to get information or download a specific dhash sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_dhashicon_sample(self, dhashicon, limit = 10, save = False):
        self.__query_type__("dhash_icon", "get_dhash_icon", dhashicon, limit, save)

    # Info: Function to get information or download a specific yara sample
    # Usage: get_tagged_sample(string, integer (optional), boolean (optional))
    def get_yararule_sample(self, yararule, limit = 10, save = False):
        self.__query_type__("yara_rule", "get_yarainfo", yararule, limit, save)
