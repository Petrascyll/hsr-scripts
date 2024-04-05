# ----------------------------------------------------------------------------------
# Reads and displays
#   - vertex color hex values 
#   - usage % of each vcolor
#       (number of vertices the vcolor is used/total number of vertices)%
# directly from the .txt vbs of dumped characters
#
# Usage
# - Place this script in the same directory as the dump of the character and run it
# or
# - Provide the path to the .txt vb present in a dump's folder
#       Example: python ./vcolor_usage.py AventurineBodyA-vb0=1a4a96c3.txt
#
#                                                              Written by petrascyll
# ----------------------------------------------------------------------------------

import re
import os
import argparse
import traceback

def main():
    parser = argparse.ArgumentParser(
        prog="vcolor_usage",
        description="Displays vertex color values and their usage % for .txt vbs",
    )
    parser.add_argument('vbs', nargs='*', type=str)
    args = parser.parse_args()
    
    if len(args.vbs) > 0: vbs = args.vbs
    else:
        # Change the CWD to the directory this script is in
        os.chdir(os.path.dirname(__file__))

        # Find all part A merged vb .txt files inside the CWD
        vbs = [
            f for f in os.listdir()
            if '-vb' in f
            and f.endswith('.txt')
            and f.split('-')[0][-1] == 'A'
        ]

        if len(vbs) == 0:
            print()
            print('No .txt vbs present in the same directory as the script.')

    # Get VColor Usage
    for vb in vbs:
        get_vcolor_usage(vb)


def get_vcolor_usage(filename):
    vcolors = {}
    vcount = 0
    p = re.compile(r'^vb\d\[\d+\]\+\d+ COLOR: (.*?), (.*?), (.*?), .*?$')

    with open(filename, 'r') as file: file = file.read()
    if file[:6] != 'stride': raise Exception('Invalid vb .txt file: {}', filename)

    vertex_data = file.split('vertex-data', maxsplit=1)[1]
    for line in vertex_data.splitlines():
        m = p.match(line)
        if not m: continue

        vc = ''.join('{:02X}'.format(round(float(c)*255)) for c in m.groups())
        if vc not in vcolors: vcolors[vc] = 1
        else: vcolors[vc] += 1
        vcount += 1

    print('\n'.join([
        '',
        '{}'.format(filename),
        '',
        '\t{}\t\t{}'.format('VColor', 'Usage %'),
        '\t{}'.format('-'*23),
        *[
            '\t{}\t\t{:6.2%}'.format(vc, vcolors[vc]/vcount)
            for vc in sorted(vcolors.keys())
        ],
        '',
    ]))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Error Occurred:\n')
        print(traceback.format_exc())
    finally:
        input('\nPress "Enter" to quit...\n')
