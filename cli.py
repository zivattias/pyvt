from concurrent.futures import ThreadPoolExecutor, as_completed
from analyzer import *
import argparse
import pickle
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="URL Reputation Check, Powered by VirusTotal's API",
                                     description="The program allows you to check URL(s)",
                                     epilog="By Ziv Attias")
    parser.add_argument('url', nargs='*',
                        help='one or more URLs, separated by a whitespace')
    parser.add_argument('-k', '--apikey',
                        help='followed by custom VT API key')
    parser.add_argument('-s', '--scan', action='store_true',
                        help='force URL scan')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose prints throughout the process')
    parser.add_argument('-a', '--age', default=182,
                        help='declare cache max age (days), default = 182')

    args = parser.parse_args(['https://whatsapp.com/', 'https://facebook.com', '-a', '1', '-v'])

    analyzer = Analyzer(urls=args.url, apikey=args.apikey, age=args.age,
                        cache_dir='./cache/')

    with ThreadPoolExecutor() as executor:
        futures = list()
        for url in args.url:
            print(f"Processing URL {url}...") if args.verbose else None
            futures.append(executor.submit(analyzer.full_scan if args.scan else analyzer.analyze, url))

        for future in as_completed(futures):
            print(f"Processed URL {future.result().url}") if args.verbose else None
            print(future.result())

    with open(os.path.join(analyzer.cache_dir, 'cache.pickle'), 'wb') as cache:
        pickle.dump(analyzer.cache, cache)
