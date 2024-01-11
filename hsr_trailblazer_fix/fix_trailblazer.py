# Written by scyll
# Thanks to Yudokubos for help with Caelus
#   And AGMG Discord
 
import os
import re

hash_data = {
    'Stelle': {
        '<1.6': {
            'position_vb': '6949f854',
            'blend_vb': '7f4e899b',
            'texcoord_vb': '01df48a6',
            'ib': '85ad43b3'
        },
        '1.6': {
            'destruction': {
                'position_vb': '6949f854',
                'blend_vb': '97b058a3',
                'texcoord_vb': 'a68ffeb1',
                'ib': '174a08d4',
                'first_index': [0, 32967]
            },
            'preservation': {
                'position_vb': '6949f854',
                'blend_vb': '51f8a8af',
                'texcoord_vb': '2dcd5dc0',
                'ib': 'e0d86dc8',
                'first_index': [0, 33081]
            },
        }
    },
    'Caelus': {
        '<1.6': {
            'position_vb': '22f597ef',
            'blend_vb': '145fa311',
            'texcoord_vb': '0bbb3448',
            'ib': 'fd65164c'
        },
        '1.6': {
            'destruction': {
                'position_vb': '22f597ef',
                'blend_vb': 'f00b031a',
                'texcoord_vb': '97c34928',
                'ib': 'e3ffef9a',
                'first_index': [0, 38178]
            },
            'preservation': {
                'position_vb': '22f597ef',
                'blend_vb': '9e7ca423',
                'texcoord_vb': '44da446d',
                'ib': 'a270e292',
                'first_index': [0, 37674]
            },
        }
    }
}

template = lambda title, hash, rest: (
        '[TextureOverride{}]\n'
        '\thash = {}\n'
        '{}'
    ).format(title, hash, rest)


def main():
    folder_files = os.listdir('.')
    ini_file = [
        file 
        for file in folder_files
        if file.endswith('.ini')
    ]

    if len(ini_file) == 0:
        print('No .ini file in current directory. Place and run this script in the same folder as the trailblazer\'s mod .ini file.')
        input()
        exit()
    elif len(ini_file) > 1:
        print('Too many .ini files detected in current directory. There must only be one! Place and run this script in the same folder as the trailblazer\'s mod .ini file.')
        input()
        exit()

    ini_file = ini_file[0]
    print('Found .ini file:', ini_file)

    char = ''
    with open(ini_file, 'r') as ini:
        f = ini.read()
        if hash_data['Stelle']['<1.6']['position_vb'] in f:
            char = 'Stelle'
            print('Stelle mod detected!')
        elif hash_data['Caelus']['<1.6']['position_vb'] in f:
            char = 'Caelus'
            print('Caelus mod detected')
        else:
            print('Unrecognized mod .ini. Stelle/Caelus vb position hash not found!')
            input()
            exit()


    # I'm not going to remember how this regex works...
    #
    #
    # \[.*?\s*hash\s*=\s*{}
    #   Starts matching from the [ that has its immediate next line starting with our desired hash
    #   skipping whitespaces in between 
    #
    # [\s\S]*?
    #   Match all lines non greedily (i.e. match as much as required to make the pattern true)
    #
    # (?=\s*(?:\s*;.*\n)*\s*\[)
    #   Positive Look Ahead: The pattern will only match if the enclosed pattern is ahead
    #
    #   \s*
    #   White Space Skip
    #
    #   (?:\s*;.*\n)*
    #       Non capturing group: match lines with ; (skipping whitespaces) until the end of the line
    #       as many times as possible
    #
    #   \s*\[
    #       Match until [ (and fail if it can't be reached) skipping whitespaces
    #
    # Rough Explanation is that the look ahead group is not allowed to match non-comment lines
    # so if there indeed is a non-comment line, the non greedy [\s\S]*? will match it instead
    # meaning the look ahead group will match all comment lines up to [, but not if there
    # are non-comment lines between
    # Example
    #       [TextureOverride_Test]
    #       hash = 12345678
    #       ; comment
    #       this = Resource_Test
    #
    #       ; Resources ----------
    #
    #       [Resource_Test]
    #       ...
    # Assuming I'm matching the 12345678 hash, the regex should match up to the 4th line and not any further
    #
    section_pattern = lambda h: re.compile(r'\[.*?\s*hash\s*=\s*{}[\s\S]*?(?=\s*(?:\s*;.*\n)*\s*\[)'.format(h))


    match = re.search(section_pattern(hash_data[char]['<1.6']['ib']), f)
    if match:
        print('Assuming both Destruction and Preservation hashes missing.')
    
        # The section blocks BodyA and BodyIB override can be extremely similiar
        # and in the case of merged mods the only way we can differentiate them is by the presence of match_first_index
        # Fix BodyA Override first then fix BodyIB override
        if 'match_first_index' in match.group():
            f = fix_bodyA_override(match, f, char)
            match = re.search(section_pattern(hash_data[char]['<1.6']['ib']), f)
            f = fix_bodyIB_override(match, f, char)
        else:
            f = fix_bodyIB_override(match, f, char)
            match = re.search(section_pattern(hash_data[char]['<1.6']['ib']), f)
            f = fix_bodyA_override(match, f, char)
            
        match = re.search(section_pattern(hash_data[char]['<1.6']['texcoord_vb']), f)
        f = fix_body_texcoord_override(match, f, char)

        match = re.search(section_pattern(hash_data[char]['<1.6']['blend_vb']), f)
        f = fix_body_blend_override(match, f, char)
    else:
        print('Unimplemented!')
        input()
        exit()


    print(f'Renamed the original ini to "{ini_file[:-4]}.txt" and generated fixed "{ini_file}".')
    os.rename(ini_file, f'{ini_file[:-4]}.txt')
    with open(ini_file, 'w') as w:
        w.write(f)

    print('Done.')
    print('Press any key to exit.')
    input()


def fix_bodyIB_override(match, f, char):
    print('Found outdated BodyIB override:')
    lines = match.group().splitlines()
    print('\n'.join(f'\t{l}' for l in lines))

    i, j = match.span()
    rest = '\n'.join([
        f'\t{line}'
        for line in lines
        if '[' not in line
        and 'hash' not in line
        and 'match_first_index' not in line
    ])

    s = ''
    for path in ['destruction', 'preservation']:
        s += template(
            title=f'{char}BodyIB_{path.capitalize()}',
            hash=hash_data[char]['1.6'][path]['ib'],
            rest=rest
        ) + '\n'
    print('Replacing with:')
    print('\n'.join(f'\t{l}' for l in s.splitlines()))
    print()

    return ''.join([f[:i], s, f[j:]])


def fix_bodyA_override(match, f, char):
    print('Found outdated BodyA override:')
    lines = match.group().splitlines()
    print('\n'.join(f'\t{l}' for l in lines))

    i, j = match.span()
    rest = '\n'.join([
        f'\t{line}'
        for line in lines
        if '[' not in line
        and 'hash' not in line
        and 'match_first_index' not in line
    ])
    
    s = ''
    for path in ['destruction', 'preservation']:
        first_index = hash_data[char]['1.6'][path]['first_index']
        bodyA = template(
            title=f'{char}BodyA_{path.capitalize()}',
            hash=hash_data[char]['1.6'][path]['ib'],
            rest=(
                '\tfirst_index = {}\n'.format(first_index[0])+
                '\tib = null\n'
            )
        )
        bodyB = template(
            title=f'{char}BodyB_{path.capitalize()}',
            hash=hash_data[char]['1.6'][path]['ib'],
            rest=(
                '\tfirst_index = {}\n'.format(first_index[1])+
                rest
            )
        )
        s += bodyA + bodyB + '\n\n'
    print('Replacing with:')
    print('\n'.join(f'\t{l}' for l in s.splitlines()))
    print()
    
    return ''.join([f[:i], s, f[j:]])


def fix_body_texcoord_override(match, f, char):
        print('Found outdated Body Texcoord override:')
        lines = match.group().splitlines()
        print('\n'.join(f'\t{l}' for l in lines))

        i, j = match.span()
        rest = '\n'.join([
            f'\t{line}'
            for line in lines
            if '[' not in line
            and 'hash' not in line
        ])

        s = ''
        for path in ['destruction', 'preservation']:
            s += template(
                title=f'{char}BodyTexcoord_{path.capitalize()}',
                hash=hash_data[char]['1.6'][path]['texcoord_vb'],
                rest=rest
            ) + '\n'
        print('Replacing with:')
        print('\n'.join(f'\t{l}' for l in s.splitlines()))
        print()

        return ''.join([f[:i], s, f[j:]])

# These methods are very similar.....
# Could optimize but its not bad enough to warrant it tbh so eh its readable... later
def fix_body_blend_override(match, f, char):
    print('Found outdated Body Blend override:')
    lines = match.group().splitlines()
    print('\n'.join(f'\t{l}' for l in lines))

    i, j = match.span()
    rest = '\n'.join([
        f'\t{line}'
        for line in lines
        if '[' not in line
        and 'hash' not in line
    ])

    s = ''
    for path in ['destruction', 'preservation']:
        s += template(
            title=f'{char}BodyBlend_{path.capitalize()}',
            hash=hash_data[char]['1.6'][path]['blend_vb'],
            rest=rest
        ) + '\n'
    print('Replacing with:')
    print('\n'.join(f'\t{l}' for l in s.splitlines()))
    print()

    return ''.join([f[:i], s, f[j:]])


if __name__ == '__main__':
    main()
