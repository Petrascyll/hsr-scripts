import argparse
from os import listdir
from re import search

vb = {}
frames = {}


def get_vertex_count(vb_filepath):
    with open(vb_filepath, "rb") as buf:
        return len(buf.read())//(10*4)


def get_latest_frame_dump_folder():
    frame_dump_folder = [x for x in listdir(".") if "FrameAnalysis" in x][-1]
    return frame_dump_folder


def parse_frame(frame_dump_folder, file_name):
    frame = int(file_name.split(".", 1)[0])
    hash = search("vb0=(.*?)\.buf", file_name).group(1)
    
    if hash not in vb:
        vb[hash] = get_vertex_count(f"{frame_dump_folder}/{file_name}")
    
    if frame not in frames:
        frames[frame] = [(hash, file_name)]
    else:
        frames[frame] += [(hash, file_name)]


def print_parsed_frames():
    for i in range(1, len(frames) + 1):
        print(f'Frame {i}:')
        for (hash, file_name) in frames[i]:
            print(f"\t({hash}, {vb[hash]})")
        print()



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-vb', type=str, help="Must be a vb present in the frame dump folder. Used for returning vbs with similar vertex count.")
    args = parser.parse_args()

    frame_dump_folder = get_latest_frame_dump_folder()
    print(f"Reading \"{frame_dump_folder}\"")

    for file_name in listdir(frame_dump_folder):
        if file_name in ['ShaderUsage.txt', 'deduped', 'log.txt']:
            continue
        parse_frame(frame_dump_folder, file_name)

    print_parsed_frames()

    if args.vb:
        if args.vb not in vb:
            print(f"Passed vb ({args.vb}) not present in dump!")
        else:
            equal_vc_vb_hash = [
                hash for hash in vb
                if vb[hash] == vb[args.vb]
                and hash != args.vb
            ]
            if len(equal_vc_vb_hash) == 0:
                print(
                    f"No other vertex buffer with the same vertex count ({vb[args.vb]})"
                    f" as that of {args.vb} is present in the dump."
                    " Perhaps the \"broken\" animation didn't occur during the dump?"
                    " Could be due to game lag. Try dumping again!"
                )
            elif 1 < len(equal_vc_vb_hash):
                print(f"More than 1 vertex buffer has the same vertex count ({vb[args.vb]}) as that of {args.vb}.")
                print("One (or more) of the hashes may be wrong")
                print(equal_vc_vb_hash)
            else:
                print(f"Found vb hash {equal_vc_vb_hash[0]}")
                print(f"\twith vertex count ({vb[equal_vc_vb_hash[0]]}) equal to that of {args.vb}")

    print()


if __name__ == '__main__':
    main()
