#!/usr/bin/env python3

import http.server
import os

server_class = getattr(http.server, 'ThreadingHTTPServer', None) or getattr(http.server, 'HTTPServer')

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', default=None)
    ap.add_argument('--port', type=int, default=8111)
    args = ap.parse_args()

    if args.pid:
        with open(args.pid, 'w') as fout:
            fout.write(str(os.getpid()))
    server = server_class(('', args.port), http.server.SimpleHTTPRequestHandler)
    server.serve_forever()

if __name__ == '__main__':
    main()
