#!/usr/bin/env python3

from argparse import ArgumentParser, SUPPRESS
from sys import argv
from core.bazaar import MalwareBazaar

def main():
    parser = ArgumentParser(
        add_help=False,
        usage=SUPPRESS
    )
    yaa = MalwareBazaar()

    # Info: Download hourly batch of samples
    # Usage: --dl-hourly 
    parser.add_argument(
        "--dl-hourly",
        action="store_true",
        dest="dl_hourly",
        help="Download hourly batch samples"
    )

    # Info: Download daily batch of samples
    # Usage: --dl-daily
    parser.add_argument(
        "--dl-daily",
        action="store_true",
        dest="dl_daily",
        help="Download daily batch samples",
    )

    # Info: Get SHA-256 hash of recent uploaded samples
    # Usage: --recent-sha256
    parser.add_argument(
        "--recent-sha256",
        action="store_true",
        dest="recent_sha256",
        help="Get a list of SHA-256 of recently uploaded samples"
    )

    # Info: Get file names of recent uploaded samples
    # Usage: --recent-filenames
    parser.add_argument(
        "--recent-filenames",
        action="store_true",
        dest="recent_filename",
        help="Get a list of file name of recently uploaded samples"
    )

    # Info: Get reporter usernames of recent uploaded samples
    # Usage: --recent-reporter
    parser.add_argument(
        "--recent-reporter",
        action="store_true",
        dest="recent_reporter",
        help="Get a list of reporter name of recently uploaded samples"    
    )

    # Info: Get a compact list of recent uploaded samples (includes filenames and SHA-256 hash)
    # Usage: --recent-compact
    parser.add_argument(
        "--recent-compact",
        action="store_true",
        dest="recent_compact",
        help="Get a compact list with all addition information about a sample"
    )
    # Info: Optional argument, if you want to enable colors
    # Parent: --recent-compact
    parser.add_argument("--color", action="store_true")

    # Info: Download a sample based on the SHA-256 hash
    # Usage: --get-sample [HASH]
    # Example: --get-sample a8674ded41983f51be7ee80e61d5f42746f7052aaf9faad34c572fedcfcd203c
    parser.add_argument(
        "--get-sample",
        type=str,
        dest="get_sample",
        help="Get sample based on the SHA-256 hash"
    )

    # Info: Optional argument, if you want to silent some output info
    # Parent: --get-sample
    parser.add_argument("--silence", action="store_true")

    # Info: Get various information about a sample based on the SHA-256 hash
    # Usage: --get-sample-info [HASH]
    # Example: --get-sample-info a8674ded41983f51be7ee80e61d5f42746f7052aaf9faad34c572fedcfcd203c
    parser.add_argument(
        "--get-sample-info",
        type=str,
        dest="get_sample_info",
        help="Get information about a sample based on the SHA-256 hash"
    )

    # Info: Get a list of CSCB based on the sample
    # Usage: --list-cscb-info
    parser.add_argument(
        "--list-cscb-info",
        action="store_true",
        dest="list_cscb_info",
        help="Get a list of CSCB based on the sample"
    )

    # Info: Get samples based on the tag
    # Usage: --get-tagged-sample [TAG] --limit [LIMIT = 10] (Optional) --save (Optional)
    # Example: --get-tagged-sample TrickBot
    parser.add_argument(
        "--get-tagged-sample",
        type=str,
        dest="get_tagged_sample",
        help="Get a list of samples based on the tag"
    )

    # Info: Get samples based on the signature
    # Usage: --get-signature-sample [SIGNATURE] --limit [LIMIT = 10] (Optional) --save (Optional)
    # Example: --get-signature-sample TrickBot
    parser.add_argument(
        "--get-signature-sample",
        type=str,
        dest="get_signature_sample",
        help="Get a list of samples based on the signature"
    )

    # Info: Get samples based on the filetype
    # Usage: --get-signature-sample [SIGNATURE] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-signature-sample elf
    parser.add_argument(
        "--get-filetype-sample",
        type=str,
        dest="get_filetype_sample",
        help="Get a list of samples based on the filetype"
    )

    # Info: Get samples based on the ClamAV sugnature
    # Usage: --get-clamavsig-sample [SIGNATURE] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-clamavsig-sample Doc.Downloader.Emotet-7580152-0
    parser.add_argument(
        "--get-clamavsig-sample",
        type=str,
        dest="get_clamavsig_sample",
        help="Get a list of samples based on the clamav signature"
    )

    # Info: Get samples based on the imphash
    # Usage: --get-imphash-sample [HASH] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-imphash-sample 45d579faec0eaf279c0841b2233727cf
    parser.add_argument(
        "--get-imphash-sample",
        type=str,
        dest="get_imphash_sample",
        help="Get a list of samples based on the imphash"
    )

    # Info: Get samples based on the TLSH hash
    # Usage: --get-tlsh-sample [HASH] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-tlsh-sample 4FB44AC6A19643BBEE8766FF358AC55DBC13D91C1B4DB4FBC789AA020A31B05ED12350
    parser.add_argument(
        "--get-tlsh-sample",
        type=str,
        dest="get_tlsh_sample",
        help="Get a list of samples based on the TLSH hash"
    )

    # Info: Get samples based on the telfhash
    # Usage: --get-telf-sample [HASH] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-telf-sample ea2106f51e7e58d9b7e4a400c29b5f623d5df13b299037a00463e93033abe466069c7a
    parser.add_argument(
        "--get-telf-sample",
        type=str,
        dest="get_telf_sample",
        help="Get a list of samples based on the TELF hash"
    )

    # Info: Get samples based on the gimphash
    # Usage: --get-gimp-sample [HASH] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-gimp-sample 50f5783c2188897815d9b34a77aa4df70ac96a71542ddc79b94fef8ce7ba2120
    parser.add_argument(
        "--get-gimp-sample",
        type=str,
        dest="get_gimp_sample",
        help="Get a list of samples based on the GIMP hash"
    )

    # Info: Get samples based on the dhash
    # Usage: --get-dhash-sample [HASH] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-dhash-sample 48b9b2b0e8c18c90
    parser.add_argument(
        "--get-dhash-sample",
        type=str,
        dest="get_dhash_sample",
        help="Get a list of samples based on the DHASH"
    )

    # Info: Get samples based on the yara rule
    # Usage: --get-yara-sample [RULE] --limit [LIMIT = 10 default] (Optional) --save (Optional)
    # Example: --get-yara-sample win_remcos_g0
    parser.add_argument(
        "--get-yara-sample",
        type=str,
        dest="get_yara_sample",
        help="Get a list of samples based on the YARA rule"
    )

    # Info: Other optional parameters 
    # Parents:  --get-tagged-sample, --get-signature-sample, --get-filetype-sample
    #           --get-clamavsig-sample, --get-imphash-sample, --get-tlsh-sample
    #           --get-telf-sample, --get-gimp-sample, --get-dhash-sample
    #           --get-yara-sample
    parser.add_argument("--limit", type=int)
    parser.add_argument("--save", action="store_true")

    # Info: Help command
    # Usage: --help
    # Note: There are no help descriptions for a specific command
    parser.add_argument(
        "--help",
        action="store_true",
        dest="yaa_help"
    )

    # Argparse doesn't wrap argument counting function...
    if argv.__len__() < 2:
        yaa.yaa_help()
        exit(1)

    args = parser.parse_args()

    # We don't have any options, but it looks much better than an if-else loop, isn't it?
    # Commands
    yaa.download_hourly_batch() if args.dl_hourly == True else None
    yaa.download_daily_batch() if args.dl_daily == True else None 
    yaa.get_recent_sha256() if args.recent_sha256 == True else None
    yaa.get_recent_filenames() if args.recent_filename == True else None
    yaa.get_recent_reporter() if args.recent_reporter == True else None
    yaa.get_recent_compact(color=args.color) if args.recent_compact == True else None
    yaa.get_sample(sha256=args.get_sample, silence=args.silence) if args.get_sample != None else None
    yaa.get_sample_info(sha256=args.get_sample_info) if args.get_sample_info != None else None
    yaa.list_cscb_info() if args.list_cscb_info == True else None
    yaa.get_tagged_sample(tag=args.get_tagged_sample, limit=args.limit, save=args.save) if args.get_tagged_sample != None else None
    yaa.get_signature_sample(signature=args.get_signature_sample, limit=args.limit, save=args.save) if args.get_signature_sample != None else None
    yaa.get_filetype_sample(filetype=args.get_filetype_sample, limit=args.limit, save=args.save) if args.get_filetype_sample != None else None
    yaa.get_clamavsig_sample(clamsig=args.get_clamavsig_sample, limit=args.limit, save=args.save) if args.get_clamavsig_sample != None else None
    yaa.get_imphash_sample(imphash=args.get_imphash_sample, limit=args.limit, save=args.save) if args.get_imphash_sample != None else None
    yaa.get_tlsh_sample(tlsh=args.get_tlsh_sample, limit=args.limit, save=args.save) if args.get_tlsh_sample != None else None
    yaa.get_telfhash_sample(telfhash=args.get_telf_sample, limit=args.limit, save=args.save) if args.get_telf_sample != None else None
    yaa.get_gimphash_sample(gimphash=args.get_gimp_sample, limit=args.limit, save=args.save) if args.get_gimp_sample != None else None
    yaa.get_dhashicon_sample(dhashicon=args.get_dhash_sample, limit=args.limit, save=args.save) if args.get_dhash_sample != None else None
    yaa.get_yararule_sample(yararule=args.get_yara_sample, limit=args.limit, save=args.save) if args.get_yara_sample != None else None
    yaa.yaa_help() if args.yaa_help == True else None

# Call the main function
main()
