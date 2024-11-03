# Written by petrascyll
#   thanks to zlevir for help dumping and adding fixes during 2.3
# 	thanks to sora_ for help collecting the vertex explosion extra position hashes
# 	and AGMG discord and everone there for being helpful
# 
# HSR Version 2.5 Fix
# 	- Updates all outdated HSR character mods from HSRv1.6 up to HSRv2.3
# 	- Edits Caelus mods to work on both Destruction/Preservation paths.
# 	- Adds the extra position hash on the mods that need it.
# 
# .exe Fofo icon source: https://www.hoyolab.com/article/22866306
# 

import os
import re
import sys
import time
import struct
import argparse
import traceback


def main():
	parser = argparse.ArgumentParser(
		prog="HSR Fix v2.5",
		description=(
			"- Updates all outdated HSR character mods from HSRv1.6 up to HSRv2.4.\n"
			"- Edits Caelus mods to work on both Destruction/Preservation paths.\n"
			"- Adds the extra position hash on the mods that need it.\n"
		)
	)

	parser.add_argument('ini_filepath', nargs='?', default=None, type=str)
	args = parser.parse_args()

	if args.ini_filepath:
		if args.ini_filepath.endswith('.ini'):
			print('Passed .ini file:', args.ini_filepath)
			upgrade_ini(args.ini_filepath)
		else:
			raise Exception('Passed file is not an Ini')

	else:
		# Change the CWD to the directory this script is in
		# Nuitka: "Onefile: Finding files" in https://nuitka.net/doc/user-manual.pdf 
		# I'm not using Nuitka anymore but this distinction (probably) also applies for pyinstaller
		# os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
		print('CWD: {}'.format(os.path.abspath('.')))
		process_folder('.')

	print('Done!')


# SHAMELESSLY (mostly) ripped from genshin fix script
def process_folder(folder_path):
	for filename in os.listdir(folder_path):
		if 'DESKTOP' in filename.upper():
			continue
		if filename.upper().startswith('DISABLED') and filename.endswith('.ini'):
			continue

		filepath = os.path.join(folder_path, filename)
		if os.path.isdir(filepath):
			process_folder(filepath)
		elif filename.endswith('.ini'):
			print('Found .ini file:', filepath)
			upgrade_ini(filepath)


def upgrade_ini(filepath):
	try:
		# Errors occuring here is fine as no write operations to the ini nor any buffers are performed
		ini = Ini(filepath).upgrade()
	except Exception as x:
		print('Error occurred: {}'.format(x))
		print('No changes have been applied to {}!'.format(filepath))
		print()
		print(traceback.format_exc())
		print()
		return False

	try:
		# Content of the ini and any modified buffers get written to disk in this function
		# Since the code for this function is more concise and predictable, the chance of it failing
		# is low, but it can happen if Windows doesn't want to cooperate and write for whatever reason.
		ini.save()
	except Exception as X:
		print('Fatal error occurred while saving changes for {}!'.format(filepath))
		print('Its likely that your mod has been corrupted. You must redownload it from the source before attempting to fix it again.')
		print()
		print(traceback.format_exc())
		print()
		return False

	return True


# MARK: Ini
class Ini():
	def __init__(self, filepath):
		with open(filepath, 'r', encoding='utf-8') as f:
			self.content = f.read()
			self.filepath = filepath

		# The random ordering of sets is annoying
		# I'll use a list for the hashes that will be iterated on
		# and a set for the hashes I already iterated on
		self.hashes = []
		self.touched = False
		self.done_hashes = set()

		# I must decrease the chance that this script will fail while fixing a mod
		# after it already went ahead and modified some buffers for the fix.
		# 	=> Only write the modified buffers at the very end after I saved the ini, since I
		# 	   can provide a backup for the ini, but backing up buffers is not reasonable.
		# If I need to fix the same buffer multiple times: the first time the buffer will 
		# be read from the mod directory, and subsequent fixes for the same buffer filepath
  		# will use the modified buffer in the dict
		self.modified_buffers = {
			# buffer_filepath: buffer_data
		}

		# Get all (uncommented) hashes in the ini
		hash_pattern = re.compile(r'\s*hash\s*=\s*([A-Fa-f0-9]*)\s*', flags=re.IGNORECASE)
		for line in self.content.splitlines():
			m = hash_pattern.match(line)
			if m: self.hashes.append(m.group(1))

	def upgrade(self):
		while len(self.hashes) > 0:
			hash = self.hashes.pop()
			if hash not in self.done_hashes:
				if hash in hash_commands:
					print(f'\tUpgrading {hash}')
					self.execute(hash, hash_commands[hash], {}, tabs=2)
				else:
					print(f'\tSkipping {hash}: - No upgrade available')
			else:
				print(f'\tSkipping {hash}: / Already Checked/Upgraded')
			self.done_hashes.add(hash)
		return self

	def execute(self, hash, commands, jail: dict, tabs=0):

		for command, kwargs in commands:
			if command == 'info':
				print('{}-{}'.format('\t'*tabs, kwargs))
				continue

			if is_Command_Generator(command):
				print('{}-{}'.format('\t'*tabs, command.__name__))
				generated_commands = command(**kwargs)
				sub_jail = self.execute(hash, generated_commands, jail, tabs=tabs+1)
				jail.update(sub_jail)

			elif is_Hash_Generator(command):
				new_hashes = kwargs
				print('{}-{}: {}'.format('\t'*tabs, command.__name__, new_hashes))

				# Only add the hashes that I haven't already iterated on
				self.hashes.extend(new_hashes.difference(self.done_hashes))

			elif is_Ini_Check(command):
				is_check_passed = command(self, **kwargs)
				if not is_check_passed:
					print('{}-Upgrade not needed'.format('\t'*tabs))
					return jail
				
			elif is_Buffer_Command(command):
				self.touched = True
				print('{}-{}'.format('\t'*tabs, command.__name__))
				self.content, new_modified_buffers = command( 
					ini_content = self.content,
					ini_filepath = self.filepath,
					modified_buffers = self.modified_buffers,
					hash = hash,
					**kwargs
				)
				self.modified_buffers.update(new_modified_buffers)

			elif is_Command(command):
				self.touched = True
				print('{}-{}'.format('\t'*tabs, command.__name__))

				self.content, jail = command(
					ini_content=self.content, 
					hash=hash,
					jail=jail,
				**kwargs)

			else:
				raise Exception('Huh?', command)

		return jail

	def save(self):
		if self.touched:
			basename = os.path.basename(self.filepath).split('.ini')[0]
			dir_path = os.path.abspath(self.filepath.split(basename+'.ini')[0])
			backup_filename = f'DISABLED_BACKUP_{int(time.time())}.{basename}.ini'
			backup_fullpath = os.path.join(dir_path, backup_filename)

			os.rename(self.filepath, backup_fullpath)
			print(f'Created Backup: {backup_filename} at {dir_path}')
			with open(self.filepath, 'w', encoding='utf-8') as updated_ini:
				updated_ini.write(self.content)
			# with open('DISABLED_debug.ini', 'w', encoding='utf-8') as updated_ini:
			# 	updated_ini.write(self.content)

			if len(self.modified_buffers) > 0:
				print('Writing updated buffers')
				for filepath, data in self.modified_buffers.items():
					with open(filepath, 'wb') as f:
						f.write(data)
					print('\tSaved: {}'.format(filepath))

			print('Updates applied')
		else:
			print('No changes applied')
		print()


# MARK: Regex
# Match the whole section (under the first group) that contains
# a certain uncommented hash at any line. For example:
# Using hash 12345678 matches
# 	[TextureOverrideWhatever1_Match]
# 	hash = 12345678
# 	this = whatever
# and
# 	[TextureOverrideWhatever2_Match]
# 	; hash = 87654321
# 	hash = 12345678
# 	this = whatever
# but not
# 	[TextureOverrideWhatever3_NoMatch]
# 	; hash = 12345678
# 	hash = 87654321
# 	this = whatever
# 
# Last section of an ini won't match since the pattern must match until the next [
# Easy hack is to add '\n[' to the end of the string being matched
# Using VERBOSE flag to ignore whitespace
# https://docs.python.org/3/library/re.html#re.VERBOSE
def get_section_hash_pattern(hash) -> re.Pattern:
	return re.compile(
		r'''
			(
				\[.*\]
				[^\[]*?
				\n\s*hash\s*=\s*{}
				[\s\S]*?
			)
			(?=\s*(?:\s*;.*\n)*\s*\[)\s*
		'''.format(hash),
		flags=re.VERBOSE|re.IGNORECASE
	)

# Can only match Commandlist and Resource sections by title
# Could be used for Override sections as well
# case doesn't matter for titles right? hmm TODO
def get_section_title_pattern(title) -> re.Pattern:
	return re.compile(
		r'''
			(
				\[{}\]
				[\s\S]*?
			)
			(?=\s*(?:\s*;.*\n)*\s*\[)\s*
		'''.format(title),
		flags=re.VERBOSE|re.IGNORECASE
	)

# MARK: Commands

def Command_Generator(func):
	func.command_generator = True
	return func
def is_Command_Generator(func):
	return getattr(func, 'command_generator', False)

def Hash_Generator(func):
	func.hash_generator = True
	return func
def is_Hash_Generator(func):
	return getattr(func, 'hash_generator', False)

def Ini_Check(func):
	func.ini_check = True
	return func
def is_Ini_Check(func):
	return getattr(func, 'ini_check', False)

def Command(func):
	func.command = True
	return func
def is_Command(func):
	return getattr(func, 'command', False)

def Buffer_Command(func):
	func.buffer_command = True
	return func
def is_Buffer_Command(func):
	return getattr(func, 'buffer_command', False)

def get_critical_content(section):
	hash = None
	match_first_index = None
	critical_lines = []
	pattern = re.compile(r'^\s*(.*?)\s*=\s*(.*?)\s*$', flags=re.IGNORECASE)

	for line in section.splitlines():
		line_match = pattern.match(line)
		
		if line.strip().startswith('['):
			continue
		elif line_match and line_match.group(1).lower() == 'hash':
			hash = line_match.group(2)
		elif line_match and line_match.group(1).lower() == 'match_first_index':
			match_first_index = line_match.group(2)
		else:
			critical_lines.append(line)

	return '\n'.join(critical_lines), hash, match_first_index

@Command
def comment_sections(ini_content, hash, jail):
	pattern = get_section_hash_pattern(hash)
	new_ini_content = ''   # ini with all matching sections commented

	prev_j = 0
	section_matches = pattern.finditer(ini_content + '\n[')
	for section_match in section_matches:
		i, j = section_match.span(1)
		commented_section = '\n'.join([';' + line for line in section_match.group(1).splitlines()])

		new_ini_content += ini_content[prev_j:i] + commented_section
		prev_j = j
	
	new_ini_content += ini_content[prev_j:]
	return new_ini_content, jail

@Command
def remove_section(ini_content, hash, jail, *, capture_content=None, capture_position=None):
	pattern = get_section_hash_pattern(hash)
	section_match = pattern.search(ini_content + '\n[')
	if not section_match: raise Exception('Bad regex')
	start, end = section_match.span(1)

	if 'capture_content':
		jail[capture_content] = get_critical_content(section_match.group(1))[0]
	if 'capture_position':
		jail[capture_position] = str(start)

	return ini_content[:start] + ini_content[end:], jail


@Command
def remove_indexed_sections(ini_content, hash, jail, *, capture_content=None, capture_position=None):
	pattern = get_section_hash_pattern(hash)
	new_ini_content = ''   # ini with ib sections removed
	position = -1  		   # First Occurence Deletion Start Position

	all_section_matches = {}

	prev_j = 0
	section_matches = pattern.finditer(ini_content + '\n[')
	for section_match in section_matches:
		if 'match_first_index' not in section_match.group(1):
			jail['_unindexed_ib_exists'] = True
			if capture_content:
				jail[capture_content] = get_critical_content(section_match.group(1))[0]
		else:
			critical_content, _, match_first_index = get_critical_content(section_match.group(1))
			placeholder = '🤍{}🤍'.format(match_first_index)

			if match_first_index in all_section_matches:
				# these borked inis are too common...
				# prompt the user to pick the correct section
				print('Duplicate IB indexed section found in ini:\n')

				print('Section 1:')
				print(all_section_matches[match_first_index])

				print('\n\nSection 2:')
				print(str(section_match.group(1)))

				print()
				print('Please pick the IB indexed section to be used in the upgrade.')
				print('(You probably want to pick the section without `ib = null` if it exists)')
				print('Type `1` to pick the first section or `2` to pick the second section, and')
				user_choice = input('Press `Enter` to confirm your choice: ')

				try:
					user_choice = int(user_choice)
					if user_choice not in [1, 2]:
						raise Exception()
				except Exception:
					raise Exception('Only valid input is `1` or `2`')

				if user_choice == 1:
					# existing section critical content is what the user wants to keep
					pass
				elif user_choice == 2:
					# overwrite existing section critical content
					jail[placeholder] = critical_content
					all_section_matches[match_first_index] = section_match.group(1)

			else:
				jail[placeholder] = critical_content
				all_section_matches[match_first_index] = section_match.group(1)
	


		i = section_match.span()[0]
		if position == -1: position = i
		new_ini_content += ini_content[prev_j:i]
		prev_j = i + len(section_match.group(1)) + 1

	new_ini_content += ini_content[prev_j:]
	if capture_position:
		jail[capture_position] = str(position)

	return new_ini_content, jail


@Command
def swap_hash(ini_content, hash, jail, *, trg_hash):
	hash_pattern = re.compile(r'^\s*hash\s*=\s*{}\s*$'.format(hash), flags=re.IGNORECASE)

	new_ini_content = []
	for line in ini_content.splitlines():
		m = hash_pattern.match(line)
		if m:
			new_ini_content.append('hash = {}'.format(trg_hash))
			new_ini_content.append(';'+line)
		else:
			new_ini_content.append(line)

	return '\n'.join(new_ini_content), jail


@Command
def create_new_section(ini_content, hash, jail, *, at_position=-1, capture_position=None, jail_condition=None, content):

	# Don't create section if condition must be satisfied but isnt
	if jail_condition and jail_condition not in jail:
		return ini_content, jail

	# Relatively slow but it doesn't matter
	if content[0] == '\n': content = content[1:]
	content = content.replace('\t', '')
	for placeholder, value in jail.items():
		if placeholder.startswith('_'):
			# conditions are not to be used for substitution
			continue

		content = content.replace(placeholder, value)
		if placeholder == at_position: at_position = int(value)

	# Half broken/fixed mods' ini will not have the object indices we're expecting
	# Could also be triggered due to a typo in the hash commands
	for emoji in ['🍰', '🌲', '🤍']:
		if emoji in content:
			print(content)
			raise Exception('Section substitution failed')

	if capture_position:
		jail[capture_position] = str(len(content) + at_position)

	ini_content = ini_content[:at_position] + content + ini_content[at_position:]

	return ini_content, jail


@Buffer_Command
def modify_buffer(ini_content, ini_filepath, modified_buffers, hash, *, operation, payload):

	# Compute new stride value of buffer according to new format
	if operation == 'add_texcoord1':
		stride = struct.calcsize(payload['format'] + payload['format'][-2:])
	elif operation == 'convert_format':
		stride = struct.calcsize(payload['format_conversion'][1])
	else:
		raise Exception('Unimplemented')

	# Need to find all Texcoord Resources used by this hash directly
	# through TextureOverrides or run through Commandlists... 
	pattern = get_section_hash_pattern(hash)
	section_match = pattern.search(ini_content+'\n[')
	resources = process_commandlist(ini_content, section_match.group(1))

	# - Match Resource sections to find filenames of buffers 
	# - Update stride value of resources early instead of iterating again later
	buffer_filenames = []
	line_pattern = re.compile(r'^\s*(filename|stride)\s*=\s*(.*)\s*$', flags=re.IGNORECASE)
	for resource in resources:
		pattern = get_section_title_pattern(resource)
		resource_section_match = pattern.search(ini_content + '\n[')
		if not resource_section_match: continue

		modified_resource_section = []
		for line in resource_section_match.group(1).splitlines():
			line_match = line_pattern.match(line)
			if not line_match:
				modified_resource_section.append(line)
			
			# Capture buffer filename
			elif line_match.group(1) == 'filename':
				modified_resource_section.append(line)
				buffer_filenames.append(line_match.group(2))

			# Update stride value of resource in ini
			elif line_match.group(1) == 'stride':
				modified_resource_section.append('stride = {}'.format(stride))
				modified_resource_section.append(';'+line)

		# Update ini
		modified_resource_section = '\n'.join(modified_resource_section)
		i, j = resource_section_match.span(1)
		ini_content = ini_content[:i] + modified_resource_section + ini_content[j:]


	for buffer_filename in buffer_filenames:
		# Get full buffer filepath using filename and ini filepath 
		buffer_filepath = os.path.abspath(os.path.join(os.path.dirname(ini_filepath), buffer_filename))
		if buffer_filepath not in modified_buffers:
			with open(buffer_filepath, 'rb') as bf:
				buffer = bf.read()
		else:
			buffer = modified_buffers[buffer_filepath]
		
		# Create new modified buffer using existing
		new_buffer = bytearray()
		if operation == 'add_texcoord1':
			old_format = payload['format']
			new_format = old_format + old_format[-2:]

			x, y = 0, 0
			for chunk in struct.iter_unpack(old_format, buffer):
				if payload['value'] == 'copy': x, y = chunk[-2], chunk[-1]
				new_buffer.extend(struct.pack(new_format, *chunk, x, y))

		elif operation == 'convert_format':
			old_format, new_format = payload['format_conversion']
			for chunk in struct.iter_unpack(old_format, buffer):
				new_buffer.extend(struct.pack(new_format, *chunk))
	
		# Modified buffers will be written at the end of this ini's upgrade
		modified_buffers[buffer_filepath] = new_buffer
	
	line_pattern = re.compile(r'^\s*stride\s*=\s*(.*)\s*$', flags=re.IGNORECASE)

	return ini_content, modified_buffers


# Returns all resources used by a commandlist
# Hardcoded to only return vb1 i.e. texcoord resources for now
# (TextureOverride sections are special commandlists)
def process_commandlist(ini_content: str, commandlist: str):
	line_pattern = re.compile(r'^\s*(run|vb1)\s*=\s*(.*)\s*$', flags=re.IGNORECASE)
	resources = []

	for line in commandlist.splitlines():
		line_match = line_pattern.match(line)
		if not line_match: continue

		if line_match.group(1) == 'vb1':
			resources.append(line_match.group(2))

		# Must check the commandlists that are run within the
		# the current commandlist for the resource as well
		# Recursion yay
		elif line_match.group(1) == 'run':
			commandlist_title = line_match.group(2)
			pattern = get_section_title_pattern(commandlist_title)
			commandlist_match = pattern.search(ini_content + '\n[')
			if commandlist_match:
				sub_resources = process_commandlist(ini_content, commandlist_match.group(1))
				resources.extend(sub_resources)

	return resources



@Ini_Check
def check_hash_not_in_ini(ini: Ini, *, hash):
	return (
		(hash not in ini.hashes)
		and
		(hash not in ini.done_hashes)
	)

# @Ini_Check
# def check_main_ib_in_ini(ini: Ini, *, hash):



@Hash_Generator
def try_upgrade():
	pass

@Command_Generator
def upgrade_hash(*, to):
	return [
		(swap_hash, {'trg_hash': to}),
		(try_upgrade, {to})
	]

# Silvermane guard npc vs enemy model have all hashes except for diffuse/lightmap different
# but we can't use the same texcoord file for both variants because the formats differ.
# Create a command that creates new buffer using the existing, but with the modified format
# Not very simple :terifallen:
# Need to identify all usages of the texcoord in the Override and any run Commandlists
# and to recreate the critical content using the new modified buffer. Also need to create 
# resource sections for the new buffer
# 
# Consider this case:
# 	[TextureOverride_NPC_Texcoord]
# 	hash = 12345678
# 	run = CommandList_NPC_Texcoord
# 	if $heh == 1
# 		vb1 = ResourceTexcoord.3
# 	endif
# 
# 	[CommandList_NPC_Texcoord]
# 	if $whatever == 0
# 		vb1 = ResourceTexcoord.0
# 	elif $whatever == 1
# 		vb1 = ResourceTexcoord.1
# 	endif
#
# - Create new override section using the new hash
# - Set its critical content to that of the original section BUT
# 	- Replace all Resource mentions with the newly modified resource
# 	- If there is a run CommandList:
# 		- Replace it with a new CommandList with all Resource mentions replaced by new Resource
# 		- If there is a run Commandlist:
# 			- Recursion.. fun..
# 
# @Command_Generator
# def multiply_buffer_section(*, titles, hashes, modify_buffer_operation):


@Command_Generator
def multiply_section(*, titles, hashes):
	content = ''
	for i, (title, hash) in enumerate(zip(titles, hashes)):
		content += '\n'.join([
			f'[TextureOverride{title}]',
			f'hash = {hash}',
			'🍰',
			''
		])
		if i < len(titles) - 1:
			content += '\n'

	return [
		(remove_section, {'capture_content': '🍰', 'capture_position': '🌲'}),
		(create_new_section, {'at_position': '🌲', 'content': content}),
		(try_upgrade, set(hashes))
	]

# TODO: Rename this function.
# 	- It does not "multiply" similarly to how `multiply_section` creates multiple sections out of one
# 	+ A true "multiply_indexed_section" is needed to simplify some character fixes (Stelle/Caelus/Yanqing)
@Command_Generator
def multiply_indexed_section(*, title, hash, trg_indices, src_indices):
	unindexed_ib_content = f'''
		[TextureOverride{title}IB]
		hash = {hash}
		🍰

	'''

	alpha = [
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
		'U', 'V', 'W', 'X', 'Y', 'Z'
	]
	content = ''
	for i, (trg_index, src_index) in enumerate(zip(trg_indices, src_indices)):
		content += '\n'.join([
			f'[TextureOverride{title}{alpha[i]}]',
			f'hash = {hash}',
			f'match_first_index = {trg_index}',
			f'🤍{src_index}🤍' if src_index != '-1' else 'ib = null',
			''
		])
		if i < len(trg_indices) - 1:
			content += '\n'

	return [
		(remove_indexed_sections, {'capture_content': '🍰', 'capture_position': '🌲'}),
		(create_new_section, {'at_position': '🌲', 'content': content}),
		(create_new_section, {'at_position': '🌲', 'content': unindexed_ib_content, 'jail_condition': '_unindexed_ib_exists'}),
		(try_upgrade, {hash})
	]


hash_commands = {
	# MARK: Acheron
	'ca948c6c': [('info', 'v2.1 -> v2.2: Acheron HairA Diffuse Hash'),  (upgrade_hash, {'to': '5ee5cc8d'})],
	'15cacc23': [('info', 'v2.1 -> v2.2: Acheron HairA LightMap Hash'), (upgrade_hash, {'to': 'ba560779'})],

	'18425cc1': [('info', 'v2.2 -> v2.3: Acheron Hair Draw Hash'),         (upgrade_hash, {'to': '111d47a6'})],
	'e775bf51': [('info', 'v2.2 -> v2.3: Acheron Hair Position Hash'),     (upgrade_hash, {'to': '9745dc50'})],
	'f83652e0': [('info', 'v2.2 -> v2.3: Acheron Hair Texcoord Hash'),     (upgrade_hash, {'to': '439a6fd7'})],
	'cb7fd896': [('info', 'v2.2 -> v2.3: Acheron Hair IB Hash'),           (upgrade_hash, {'to': '22284dcd'})],
	'5ee5cc8d': [('info', 'v2.2 -> v2.3: Acheron Hair Diffuse Hash'),      (upgrade_hash, {'to': '6288c7ce'})],
	'e341feb3': [('info', 'v2.2 -> v2.3: Acheron Hair Diffuse Ult Hash'),  (upgrade_hash, {'to': 'fbc56473'})],
	'ba560779': [('info', 'v2.2 -> v2.3: Acheron Hair LightMap Hash'),     (upgrade_hash, {'to': '020bb63f'})],
	'4f794c53': [('info', 'v2.2 -> v2.3: Acheron Hair LightMap Ult Hash'), (upgrade_hash, {'to': 'f0b6c0a5'})],

	'94d0ebac': [('info', 'v2.2 -> v2.3: Acheron Head Diffuse Hash'),      (upgrade_hash, {'to': '772da571'})],
	'f1d40d3b': [('info', 'v2.2 -> v2.3: Acheron Head Diffuse Ult Hash'),  (upgrade_hash, {'to': '19de522c'})],

	'95311311': [('info', 'v2.2 -> v2.3: Acheron Body Texcoord Hash'),     (upgrade_hash, {'to': '17e76a6a'})],
	'b2c64915': [('info', 'v2.2 -> v2.3: Acheron Body Diffuse Hash'),      (upgrade_hash, {'to': 'e88da4d0'})],
	'b8363627': [('info', 'v2.2 -> v2.3: Acheron Body Diffuse Ult Hash'),  (upgrade_hash, {'to': '5788d426'})],
	'2a42c5e4': [('info', 'v2.2 -> v2.3: Acheron Body LightMap Hash'),     (upgrade_hash, {'to': '1248799e'})],
	'60de0907': [('info', 'v2.2 -> v2.3: Acheron Body LightMap Ult Hash'), (upgrade_hash, {'to': 'ec57d1b8'})],

	'92bc6d3a': [('info', 'v2.3 -> v2.4: Acheron Body Draw Hash'),           (upgrade_hash, {'to': 'f6023c2b'})],
	'214bd15a': [('info', 'v2.3 -> v2.4: Acheron Body Position Hash'),       (upgrade_hash, {'to': '45f5804b'})],
	'7ffc98fa': [('info', 'v2.3 -> v2.4: Acheron Body Position Extra Hash'), (upgrade_hash, {'to': 'bc9d2d77'})],
	'17e76a6a': [('info', 'v2.3 -> v2.4: Acheron Body Texcoord Hash'),       (upgrade_hash, {'to': 'da5b680e'})],
	'36536e1b': [('info', 'v2.3 -> v2.4: Acheron Body IB Hash'),             (upgrade_hash, {'to': '6f8c993d'})],

	'45f5804b': [
		('info', 'v2.4: Acheron Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': 'bc9d2d77'}),
		(check_hash_not_in_ini, {'hash': '7ffc98fa'}),
		(multiply_section, {
			'titles': ['AcheronBodyPosition', 'AcheronBodyPosition_Extra'],
			'hashes': ['45f5804b', 'bc9d2d77']
		})
	],


	# MARK: Argenti
	'099cb678': [('info', 'v1.6 -> v2.0: Argenti Body Texcoord Hash'), (upgrade_hash, {'to': '18af7e1c'})],
	'9de080b0': [
		('info', 'v1.6 -> v2.0: Argenti Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'ArgentiBody',
			'hash': '7d57f432',
			'trg_indices': ['0', '58749'],
			'src_indices': ['0',    '-1'],
		})
	],

	'040c8f95': [('info', 'v2.2 -> v2.3: Argenti Hair Draw Hash'),     (upgrade_hash, {'to': 'ac883ae6'})],
	'3214c162': [('info', 'v2.2 -> v2.3: Argenti Hair Position Hash'), (upgrade_hash, {'to': '78c72ec8'})],
	'5eede219': [('info', 'v2.2 -> v2.3: Argenti Hair Texcoord Hash'), (upgrade_hash, {'to': '05b75400'})],
	'179d17fe': [('info', 'v2.2 -> v2.3: Argenti Hair IB Hash'),       (upgrade_hash, {'to': '5fab0ace'})],
	'd066d8b7': [('info', 'v2.2 -> v2.3: Argenti Hair Diffuse Hash'),  (upgrade_hash, {'to': '17948e68'})],
	'4925c9dd': [('info', 'v2.2 -> v2.3: Argenti Hair LightMap Hash'), (upgrade_hash, {'to': 'a13c6f7f'})],

	'705196e4': [('info', 'v2.2 -> v2.3: Argenti Head Diffuse Hash'),  (upgrade_hash, {'to': '2945bd23'})],

	'f94c8a7e': [('info', 'v2.2 -> v2.3: Argenti Body Diffuse Hash'),  (upgrade_hash, {'to': 'a4e4c7dc'})],
	'98b6f3be': [('info', 'v2.2 -> v2.3: Argenti Body LightMap Hash'), (upgrade_hash, {'to': '63bb1f26'})],



	# MARK: Arlan
	'efc1554c': [('info', 'v1.6 -> v2.0: Arlan BodyA LightMap Hash'), (upgrade_hash, {'to': '49f0a509'})],
	'b83d39c9': [('info', 'v1.6 -> v2.0: Arlan BodyB LightMap Hash'), (upgrade_hash, {'to': 'ffaf499a'})],
	'2b98f3d1': [('info', 'v1.6 -> v2.0: Arlan Body Texcoord Hash'),  (upgrade_hash, {'to': '40436908'})],
	'cb3a3965': [
		('info', 'v1.6 -> v2.0: Arlan Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'ArlanBody',
			'hash': '31ebfc6e',
			'trg_indices': ['0', '23412', '41721', '42429'],
			'src_indices': ['0', '23412',    '-1', '42429'],
		})
	],

	'21c2354a': [('info', 'v2.2 -> v2.3: Arlan Hair Diffuse Hash'),   (upgrade_hash, {'to': '72ad2a8b'})],
	'1fdfbbdc': [('info', 'v2.2 -> v2.3: Arlan Hair Lightmap Hash'),  (upgrade_hash, {'to': 'b4c6e6a0'})],

	'9a85af8a': [('info', 'v2.2 -> v2.3: Arlan Head Diffuse Hash'),   (upgrade_hash, {'to': 'a8c57de3'})],

	'52e4750b': [('info', 'v2.2 -> v2.3: Arlan BodyA Diffuse Hash'),  (upgrade_hash, {'to': '52b88238'})],
	'49f0a509': [('info', 'v2.2 -> v2.3: Arlan BodyA LightMap Hash'), (upgrade_hash, {'to': 'd8039952'})],
	'd1e827e0': [('info', 'v2.2 -> v2.3: Arlan BodyB Diffuse Hash'),  (upgrade_hash, {'to': 'f90343fb'})],
	'ffaf499a': [('info', 'v2.2 -> v2.3: Arlan BodyB LightMap Hash'), (upgrade_hash, {'to': '2f5ce8b7'})],



	# MARK: Asta
	'46c9c299': [('info', 'v1.6 -> v2.0: Asta Body Texcoord Hash'), (upgrade_hash, {'to': '337e94ce'})],
	'099dd85b': [
		('info', 'v1.6 -> v2.0: Asta Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'AstaBody',
			'hash': '8fb66ce1',
			'trg_indices': ['0',  '4791', '11823', '12510', '47880'],
			'src_indices': ['0', '40161', '49917',    '-1',    '-1'],
		})
	],

	'cde8d751': [('info', 'v2.2 -> v2.3: Asta Hair Draw Hash'),     (upgrade_hash, {'to': '1ca6cf3d'})],
	'4e29dad2': [('info', 'v2.2 -> v2.3: Asta Hair Position Hash'), (upgrade_hash, {'to': '967c0759'})],
	'6406c03e': [('info', 'v2.2 -> v2.3: Asta Hair Texcoord Hash'), (upgrade_hash, {'to': '4f796933'})],
	'84668635': [('info', 'v2.2 -> v2.3: Asta Hair IB Hash'),       (upgrade_hash, {'to': '36a13222'})],
	'9bd1710d': [('info', 'v2.2 -> v2.3: Asta Hair Diffuse Hash'),  (upgrade_hash, {'to': '2ec320aa'})],
	'8206809f': [('info', 'v2.2 -> v2.3: Asta Hair LightMap Hash'), (upgrade_hash, {'to': '7fd9c40d'})],

	'0fb34dc9': [('info', 'v2.2 -> v2.3: Asta Head Diffuse Hash'),  (upgrade_hash, {'to': 'a53efe63'})],

	'fb0f55f4': [('info', 'v2.2 -> v2.3: Asta BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'e290fff3'})],
	'088765db': [('info', 'v2.2 -> v2.3: Asta BodyA LightMap Hash'), (upgrade_hash, {'to': '687428e3'})],
	'3cc949c8': [('info', 'v2.2 -> v2.3: Asta BodyB Diffuse Hash'),  (upgrade_hash, {'to': '8f61660a'})],
	'701d9092': [('info', 'v2.2 -> v2.3: Asta BodyB LightMap Hash'), (upgrade_hash, {'to': '8893d921'})],


	# MARK: Aventurine
	'c4c588df': [('info', 'v2.2 -> v2.3: Aventurine Hair Draw Hash'),     (upgrade_hash, {'to': '2a1a1775'})],
	'015c8a86': [('info', 'v2.2 -> v2.3: Aventurine Hair Position Hash'), (upgrade_hash, {'to': '8de65cb9'})],
	'811fa2ca': [('info', 'v2.2 -> v2.3: Aventurine Hair Texcoord Hash'), (upgrade_hash, {'to': '32da43dd'})],
	'015f4887': [('info', 'v2.2 -> v2.3: Aventurine Hair IB Hash'),       (upgrade_hash, {'to': '59d6021b'})],
	'7f4af1d5': [('info', 'v2.2 -> v2.3: Aventurine Hair Diffuse Hash'),  (upgrade_hash, {'to': '7e21ce24'})],
	'3bbbdfcc': [('info', 'v2.2 -> v2.3: Aventurine Hair LightMap Hash'), (upgrade_hash, {'to': '4699613b'})],

	'c484fc3a': [('info', 'v2.2 -> v2.3: Aventurine Head Diffuse Hash'),  (upgrade_hash, {'to': 'd4874355'})],

	'982bd8c4': [('info', 'v2.2 -> v2.3: Aventurine Hair Texcoord Hash'), (upgrade_hash, {'to': '53bdb739'})],
	'53c4098f': [('info', 'v2.2 -> v2.3: Aventurine Hair Diffuse Hash'),  (upgrade_hash, {'to': 'b1cd8482'})],
	'6c801b21': [('info', 'v2.2 -> v2.3: Aventurine Hair LightMap Hash'), (upgrade_hash, {'to': '115d50a7'})],



	# MARK: Bailu
	'e5417fe2': [('info', 'v1.6 -> v2.0: Bailu Body Texcoord Hash'), (upgrade_hash, {'to': 'd7a8228a'})],
	'dbf90364': [
		('info', 'v1.6 -> v2.0: Bailu Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'BailuBody',
			'hash': '680253f0',
			'trg_indices': ['0', '33984', '56496', '62601'],
			'src_indices': ['0', '36429',    '-1',    '-1'],
		})
	],
	'5dfaf99e': [
		('info', 'v2.1: Bailu Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': 'e2fb7ce0'}),
		(multiply_section, {
			'titles': ['BailuBodyPosition', 'BailuBodyPosition_Extra'],
			'hashes': ['5dfaf99e', 'e2fb7ce0']
		})
	],

	'd1df61ab': [('info', 'v2.2 -> v2.3: Bailu Hair Diffuse Hash'),   (upgrade_hash, {'to': '1a6134dc'})],
	'dfe514d8': [('info', 'v2.2 -> v2.3: Bailu Hair LightMap Hash'),  (upgrade_hash, {'to': 'dcc96667'})],

	'52a50074': [('info', 'v2.2 -> v2.3: Bailu Head Diffuse Hash'),   (upgrade_hash, {'to': '75770ba0'})],
	
	'e3ea3823': [('info', 'v2.2 -> v2.3: Bailu BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'e430e059'})],
	'74d8fa7a': [('info', 'v2.2 -> v2.3: Bailu BodyA LightMap Hash'), (upgrade_hash, {'to': 'c42c0455'})],
	'de6e235f': [('info', 'v2.2 -> v2.3: Bailu BodyB Diffuse Hash'),  (upgrade_hash, {'to': 'e468513a'})],
	'bdab2370': [('info', 'v2.2 -> v2.3: Bailu BodyB LightMap Hash'), (upgrade_hash, {'to': '8d372ffc'})],




	# MARK: BlackSwan
	'96f25869': [('info', 'v2.0 -> v2.1: BlackSwan Body Texcoord Hash'), (upgrade_hash, {'to': '562fbdb4'})],
	'197e8353': [
		('info', 'v2.1: BlackSwan Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '10fb3cab'}),
		(multiply_section, {
			'titles': ['BlackSwanBodyPosition', 'BlackSwanBodyPosition_Extra'],
			'hashes': ['197e8353', '10fb3cab']
		})
	],

	'5d782765': [('info', 'v2.2 -> v2.3: BlackSwan Hair Diffuse Hash'),     (upgrade_hash, {'to': '9f71dd91'})],
	'4013a662': [('info', 'v2.2 -> v2.3: BlackSwan Hair LightMap Hash'),    (upgrade_hash, {'to': 'b97825d7'})],

	'057dfd1a': [('info', 'v2.2 -> v2.3: BlackSwan Head Diffuse Hash'),     (upgrade_hash, {'to': '7464fbfe'})],
	
	'4ce38332': [('info', 'v2.2 -> v2.3: BlackSwan Body Diffuse Hash'),     (upgrade_hash, {'to': 'a5727e55'})],
	'5527e772': [('info', 'v2.2 -> v2.3: BlackSwan Body LightMap Hash'),    (upgrade_hash, {'to': '7884691d'})],
	'028b385d': [('info', 'v2.2 -> v2.3: BlackSwan Body StockingMap AMD Hash'),   (upgrade_hash, {'to': 'ec1ba003'})],
	'01f66a63': [('info', 'v2.2 -> v2.3: BlackSwan Body StockingMap NVDIA Hash'), (upgrade_hash, {'to': 'd037ddd6'})],


	# MARK: Blade
	'b95b80ad': [('info', 'v1.5 -> v1.6: Blade BodyA LightMap Hash'), (upgrade_hash, {'to': '459ea4f3'})],
	'0b7675c2': [('info', 'v1.5 -> v1.6: Blade BodyB LightMap Hash'), (upgrade_hash, {'to': 'bdbde74c'})],
	
	# This is reverted in 2.3? Extremely weird, investigate later
	# '90237dd2': [('info', 'v1.6 -> v2.0: Blade Head Position Hash'),  (upgrade_hash, {'to': '9bc595ba'})],

	'b931dfc7': [('info', 'v1.6 -> v2.0: Blade Body Texcoord Hash'),  (upgrade_hash, {'to': 'f7896b3e'})],
	'5d03ae61': [
		('info', 'v1.6 -> v2.0: Blade Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'BladeBody',
			'hash': '0eb1e389',
			'trg_indices': ['0', '35790', '44814'],
			'src_indices': ['0', '35790',    '-1'],
		})
	],

	'419db05a': [('info', 'v2.2 -> v2.3: Blade Hair Draw Hash'),     (upgrade_hash, {'to': '89af9f25'})],
	'71b698d8': [('info', 'v2.2 -> v2.3: Blade Hair Position Hash'), (upgrade_hash, {'to': 'dd309961'})],
	'ff18d193': [('info', 'v2.2 -> v2.3: Blade Hair Texcoord Hash'), (upgrade_hash, {'to': 'f646a974'})],
	'60d6a2c4': [('info', 'v2.2 -> v2.3: Blade Hair IB Hash'),       (upgrade_hash, {'to': 'ab8b5a42'})],
	'7e354cb4': [('info', 'v2.2 -> v2.3: Blade Hair Diffuse Hash'),  (upgrade_hash, {'to': '7cbac9fe'})],
	'32919d62': [('info', 'v2.2 -> v2.3: Blade Hair LightMap Hash'), (upgrade_hash, {'to': 'bc05281a'})],

	'9bc595ba': [('info', 'v2.2 -> v2.3: Blade Head Position Hash'), (upgrade_hash, {'to': '90237dd2'})],
	'6fa7fbdc': [('info', 'v2.2 -> v2.3: Blade Head Diffuse Hash'),  (upgrade_hash, {'to': '929dfaee'})],

	'1082d394': [('info', 'v2.2 -> v2.3: Blade BodyA Diffuse Hash'),  (upgrade_hash, {'to': '6166ea57'})],
	'459ea4f3': [('info', 'v2.2 -> v2.3: Blade BodyA LightMap Hash'), (upgrade_hash, {'to': 'a273cfa3'})],
	'409cd5c1': [('info', 'v2.2 -> v2.3: Blade BodyB Diffuse Hash'),  (upgrade_hash, {'to': '3a1b9bb1'})],
	'bdbde74c': [('info', 'v2.2 -> v2.3: Blade BodyB LightMap Hash'), (upgrade_hash, {'to': '647809bd'})],



	# MARK: Boothill
	'1e9505b5': [('info', 'v2.2 -> v2.3: Boothill Hair Diffuse Hash'),   (upgrade_hash, {'to': '3b420073'})],
	'8dccfaa1': [('info', 'v2.2 -> v2.3: Boothill Hair LightMap Hash'),  (upgrade_hash, {'to': 'af56a76b'})],

	'4e49ef76': [('info', 'v2.2 -> v2.3: Boothill Head Diffuse Hash'),   (upgrade_hash, {'to': '704d65a9'})],
 
 	'845f6f6b': [('info', 'v2.2 -> v2.3: Boothill Draw Hash'),           (upgrade_hash, {'to': 'f261312e'})],
 	'37a8d30b': [('info', 'v2.2 -> v2.3: Boothill Position Hash'),       (upgrade_hash, {'to': '41968d4e'})],
 	'd0fb7df5': [('info', 'v2.2 -> v2.3: Boothill Texcoord Hash'),       (upgrade_hash, {'to': 'f8dd7e43'})],
 	'87f245a6': [('info', 'v2.2 -> v2.3: Boothill IB Hash'),             (upgrade_hash, {'to': '3c3ec92a'})],
 	'6d0a3848': [('info', 'v2.2 -> v2.3: Boothill BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'bd451832'})],
	'f914a7fe': [('info', 'v2.2 -> v2.3: Boothill BodyA LightMap Hash'), (upgrade_hash, {'to': 'f36e4a49'})],



	# MARK: Bronya
	'f25b360a': [('info', 'v1.5 -> v1.6: Bronya BodyA LightMap Hash'), (upgrade_hash, {'to': '066f1a5a'})],
	'6989bd40': [('info', 'v1.5 -> v1.6: Bronya BodyB LightMap Hash'), (upgrade_hash, {'to': '5161422e'})],
	'7f5e24df': [('info', 'v1.6 -> v2.0: Bronya Hair Draw Hash'), 	   (upgrade_hash, {'to': '4e327afb'})],
	'8123eaff': [('info', 'v1.6 -> v2.0: Bronya Hair Position Hash'),  (upgrade_hash, {'to': '4265a087'})],
	'd6153000': [('info', 'v1.6 -> v2.0: Bronya Hair Texcoord Hash'),  (upgrade_hash, {'to': '2ec44855'})],
	'70fd4690': [('info', 'v1.6 -> v2.0: Bronya Hair IB Hash'),		   (upgrade_hash, {'to': '2d03d71b'})],
	'39d9a850': [('info', 'v1.6 -> v2.0: Bronya Body Texcoord Hash'),  (upgrade_hash, {'to': '0d67a9c3'})],
	'1d057d1a': [
		('info', 'v1.6 -> v2.0: Bronya Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'BronyaBody',
			'hash': '29d03f40',
			'trg_indices': ['0', '34431', '36345', '60423'],
			'src_indices': ['0',    '-1', '36345',    '-1'],
		})
	],
	'198eb408': [
		('info', 'v2.1: Bronya Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '08f2d6dd'}),
		(multiply_section, {
			'titles': ['BronyaBodyPosition', 'BronyaBodyPosition_Extra'],
			'hashes': ['198eb408', '08f2d6dd']
		})
	],

	'79319861': [('info', 'v2.2 -> v2.3: Bronya Hair Diffuse Hash'),      (upgrade_hash, {'to': '7e9a40be'})],
	'c476c030': [('info', 'v2.2 -> v2.3: Bronya Hair LightMap Hash'),     (upgrade_hash, {'to': 'af5183a6'})],

	'901262ce': [('info', 'v2.2 -> v2.3: Bronya Head Diffuse Hash'),      (upgrade_hash, {'to': 'eea06253'})],

	'0b49e488': [('info', 'v2.2 -> v2.3: Bronya BodyA Diffuse Hash'),     (upgrade_hash, {'to': '3ed22aab'})],
	'066f1a5a': [('info', 'v2.2 -> v2.3: Bronya BodyA LightMap Hash'),    (upgrade_hash, {'to': 'b1117be0'})],
	'ac738042': [('info', 'v2.2 -> v2.3: Bronya BodyA StockingMap Hash'), (upgrade_hash, {'to': '45480a99'})],
	'e1c9d15e': [('info', 'v2.2 -> v2.3: Bronya BodyC Diffuse Hash'),     (upgrade_hash, {'to': 'da221a45'})],
	'5161422e': [('info', 'v2.2 -> v2.3: Bronya BodyC LightMap Hash'),    (upgrade_hash, {'to': '643fe76a'})],
	'720783d5': [('info', 'v2.2 -> v2.3: Bronya BodyC StockingMap Hash'), (upgrade_hash, {'to': '789f1abf'})],



	# MARK: Clara
	'7365de7c': [('info', 'v1.6 -> v2.0: Clara Hair Draw Hash'),  	 (upgrade_hash, {'to': 'bcfb045b'})],
	'8c56882c': [('info', 'v1.6 -> v2.0: Clara Hair Position Hash'), (upgrade_hash, {'to': '486f6900'})],
	'572f5b77': [('info', 'v1.6 -> v2.0: Clara Hair Texcoord Hash'), (upgrade_hash, {'to': '08caadac'})],
	'58982bbd': [('info', 'v1.6 -> v2.0: Clara Hair IB Hash'),  	 (upgrade_hash, {'to': '338bbeec'})],
	'da981c17': [('info', 'v1.6 -> v2.0: Clara Body Draw Hash'),  	 (upgrade_hash, {'to': '8c9c698e'})],
	'696fa077': [('info', 'v1.6 -> v2.0: Clara Body Draw Hash'),  	 (upgrade_hash, {'to': '3f6bd5ee'})],
	'5dfa8761': [('info', 'v1.6 -> v2.0: Clara Body Texcoord Hash'), (upgrade_hash, {'to': 'a444344c'})],
	'f92afebc': [
		('info', 'v1.6 -> v2.0: Clara Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'ClaraBody',
			'hash': '4a58be98',
			'trg_indices': ['0', '2016', '19290', '50910'],
			'src_indices': ['0',   '-1', '19293',    '-1'],
		})
	],

	'4c5e718d': [('info', 'v2.2 -> v2.3: Clara Hair Diffuse Hash'),   (upgrade_hash, {'to': 'e730fbcc'})],
	'7fe8d517': [('info', 'v2.2 -> v2.3: Clara Hair LightMap Hash'),  (upgrade_hash, {'to': '4ecb33c7'})],

	'b6ba0179': [('info', 'v2.2 -> v2.3: Clara Head Diffuse Hash'),   (upgrade_hash, {'to': '64cd257f'})],

	'af43bb7c': [('info', 'v2.2 -> v2.3: Clara BodyA Diffuse Hash'),  (upgrade_hash, {'to': '198363bb'})],
	'ffd2f41b': [('info', 'v2.2 -> v2.3: Clara BodyA LightMap Hash'), (upgrade_hash, {'to': 'd73982e5'})],
	'ff7a7e5e': [('info', 'v2.2 -> v2.3: Clara BodyC Diffuse Hash'),  (upgrade_hash, {'to': 'a646bdde'})],
	'6c866716': [('info', 'v2.2 -> v2.3: Clara BodyC LightMap Hash'), (upgrade_hash, {'to': '6f4c03fe'})],



	# MARK: DanHeng
	'de0264c6': [('info', 'v1.4 -> v1.6: DanHeng BodyA LightMap Hash'), (upgrade_hash, {'to': '5e3149d6'})],
	'f01e58df': [('info', 'v1.6 -> v2.0: DanHeng Head Texcoord Hash'),  (upgrade_hash, {'to': '0c5e8d34'})],
	'ab30fd81': [('info', 'v1.6 -> v2.0: DanHeng Body Texcoord Hash'),  (upgrade_hash, {'to': '8bdfb25d'})],
	'f256d83c': [('info', 'v1.6 -> v2.0: DanHeng BodyA Diffuse Hash'),  (upgrade_hash, {'to': '95212661'})],
	'be813760': [
		('info', 'v1.6 -> v2.0: DanHeng Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'DanHengBody',
			'hash': '457b4223',
			'trg_indices': ['0', '49005'],
			'src_indices': ['0',    '-1'],
		})
	],

	'02394eab': [('info', 'v2.2 -> v2.3: DanHeng Hair Diffuse Hash'),  (upgrade_hash, {'to': '62604aad'})],
	'98fd88ae': [('info', 'v2.2 -> v2.3: DanHeng Hair LightMap Hash'), (upgrade_hash, {'to': 'e4fd41ae'})],

	'1e764817': [('info', 'v2.2 -> v2.3: DanHeng Head Diffuse Hash'),  (upgrade_hash, {'to': '65a5afa5'})],

	'95212661': [('info', 'v2.2 -> v2.3: DanHeng Body Diffuse Hash'),  (upgrade_hash, {'to': '72b7f37b'})],
	'5e3149d6': [('info', 'v2.2 -> v2.3: DanHeng Body LightMap Hash'), (upgrade_hash, {'to': '01999151'})],



	# MARK: DanHengIL
	'9249f149': [('info', 'v1.4 -> v1.6: DanHengIL BodyA LightMap Hash'), (upgrade_hash, {'to': 'ef65d29c'})],
	'0ffb8233': [('info', 'v1.6 -> v2.0: DanHengIL Body Texcoord Hash'),  (upgrade_hash, {'to': '0f8da6ba'})],
	'1a7ee87c': [
		('info', 'v1.6 -> v2.0: DanHengIL Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'DanHengILBody',
			'hash': '7cb75a5e',
			'trg_indices': ['0', '47133'],
			'src_indices': ['0',    '-1'],
		})
	],

	'5f6f803e': [('info', 'v2.2 -> v2.3: DanHengIL Hair Diffuse Hash'),  (upgrade_hash, {'to': '779e60a8'})],
	'ec8baa47': [('info', 'v2.2 -> v2.3: DanHengIL Hair LightMap Hash'), (upgrade_hash, {'to': '41840f8a'})],

	'd64ab9dc': [('info', 'v2.2 -> v2.3: DanHengIL Head Diffuse Hash'),  (upgrade_hash, {'to': 'f1b129e2'})],

	'85486705': [('info', 'v2.2 -> v2.3: DanHengIL Body Diffuse Hash'),  (upgrade_hash, {'to': '9300840e'})],
	'ef65d29c': [('info', 'v2.2 -> v2.3: DanHengIL Body LightMap Hash'), (upgrade_hash, {'to': 'b0660300'})],



	# MARK: DrRatio
	'd1795906': [('info', 'v1.6 -> v2.0: DrRatio Hair Draw Hash'), 	   (upgrade_hash, {'to': 'fbcffe5a'})],
	'4d6e85c4': [('info', 'v1.6 -> v2.0: DrRatio Hair Position Hash'), (upgrade_hash, {'to': '5ca10450'})],
	'a8c25bde': [('info', 'v1.6 -> v2.0: DrRatio Hair Texcoord Hash'), (upgrade_hash, {'to': '26a8f257'})],
	'f205cf29': [('info', 'v1.6 -> v2.0: DrRatio Hair IB Hash'), 	   (upgrade_hash, {'to': '76d7d3f3'})],
	'70238f05': [('info', 'v1.6 -> v2.0: DrRatio Head Draw Hash'), 	   (upgrade_hash, {'to': '9857f892'})],
	'8dfb8014': [('info', 'v1.6 -> v2.0: DrRatio Head Position Hash'), (upgrade_hash, {'to': 'b88dc8c6'})],
	'874d30a8': [('info', 'v1.6 -> v2.0: DrRatio Head Texcoord Hash'), (upgrade_hash, {'to': '91f740da'})],
	'ad2be93d': [('info', 'v1.6 -> v2.0: DrRatio Head IB Hash'), 	   (upgrade_hash, {'to': '82bc4a2d'})],
	'dc2c9035': [('info', 'v1.6 -> v2.0: DrRatio Body Draw Hash'), 	   (upgrade_hash, {'to': 'd5f71e0e'})],
	'6fdb2c55': [('info', 'v1.6 -> v2.0: DrRatio Body Position Hash'), (upgrade_hash, {'to': '6600a26e'})],
	'32ccb687': [('info', 'v1.6 -> v2.0: DrRatio Body Texcoord Hash'), (upgrade_hash, {'to': 'e6b81399'})],
	'4a12ec28': [
		('info', 'v1.6 -> v2.0: DrRatio Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'DrRatioBody',
			'hash': '37c47042',
			'trg_indices': ['0', '56361'],
			'src_indices': ['0',    '-1'],
		})
	],

	'fbcffe5a': [('info', 'v2.2 -> v2.3: DrRatio Hair Draw Hash'),     (upgrade_hash, {'to': 'b310931e'})],
	'5ca10450': [('info', 'v2.2 -> v2.3: DrRatio Hair Position Hash'), (upgrade_hash, {'to': '7a9d0dac'})],
	'26a8f257': [('info', 'v2.2 -> v2.3: DrRatio Hair Texcoord Hash'), (upgrade_hash, {'to': '650888fc'})],
	'76d7d3f3': [('info', 'v2.2 -> v2.3: DrRatio Hair IB Hash'),       (upgrade_hash, {'to': '0a520e04'})],
	'013f4f5d': [('info', 'v2.2 -> v2.3: DrRatio Hair Diffuse Hash'),  (upgrade_hash, {'to': '521b3d2d'})],
	'8eccb31c': [('info', 'v2.2 -> v2.3: DrRatio Hair LightMap Hash'), (upgrade_hash, {'to': '5a50e9ba'})],

	'29a331d7': [('info', 'v2.2 -> v2.3: DrRatio Head Diffuse Hash'),  (upgrade_hash, {'to': '4c6a99ed'})],

	'd8ae56ba': [('info', 'v2.2 -> v2.3: DrRatio Body Diffuse Hash'),  (upgrade_hash, {'to': 'e80725f3'})],
	'9fa75d99': [('info', 'v2.2 -> v2.3: DrRatio Body LightMap Hash'), (upgrade_hash, {'to': '4329d27b'})],



	# MARK: Feixiao
	'1ef800bc': [
		('info', 'v2.5: Feixiao Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '85d02e23'}),
		(multiply_section, {
			'titles': ['FeixiaoBodyPosition', 'FeixiaoBodyPosition_Extra'],
			'hashes': ['1ef800bc', '85d02e23']
		})
	],



	# MARK: Firefly
	'81984c7b': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Hair Diffuse Hash'),  (upgrade_hash, {'to': 'cc46e8e8'})],
	'2cc928b2': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Hair LightMap Hash'), (upgrade_hash, {'to': '38ae656e'})],

	'9966e83e': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Head Diffuse Hash'),  (upgrade_hash, {'to': 'c61c087d'})],

	'8330592e': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Body Draw Hash'),     (upgrade_hash, {'to': 'da829543'})],
	'30c7e54e': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Body Position Hash'), (upgrade_hash, {'to': '69752923'})],
	'274d9c39': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Body Texcoord Hash'), (upgrade_hash, {'to': 'f57c4e74'})],
	'977bcde9': [
		('info', 'v2.2 -> v2.3 (npc/playable): Firefly Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'FireflyBody',
			'hash': '423c22f1',
			'trg_indices': ['0', '32547', '66561'],
			'src_indices': ['0', '32976', '66429'],
		})
	],
	'b5be8f4f': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Body Diffuse Hash'),  (upgrade_hash, {'to': '70c1071f'})],
	'04ea14b2': [('info', 'v2.2 -> v2.3 (npc/playable): Firefly Body LightMap Hash'), (upgrade_hash, {'to': '3f9e2b37'})],



	# MARK: FuXuan
	'71906b4e': [('info', 'v1.6 -> v2.0: FuXuan Body Texcoord Hash'), (upgrade_hash, {'to': '45b0663d'})],
	'7d77bdb5': [
		('info', 'v1.6 -> v2.0: FuXuan Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'FuXuanBody',
			'hash': 'c230f24a',
			'trg_indices': ['0', '39018', '57636', '65415'],
			'src_indices': ['0', '46797',     '-1',   '-1'],
		})
	],

	'73b1fe83': [('info', 'v2.2 -> v2.3: FuXuan Hair Texcoord Hash'),     (upgrade_hash, {'to': 'f498555d'})],
	'df067d4d': [('info', 'v2.2 -> v2.3: FuXuan Hair Diffuse Hash'),      (upgrade_hash, {'to': 'afb05dab'})],
	'dfc8fb64': [('info', 'v2.2 -> v2.3: FuXuan Hair LightMap Hash'),     (upgrade_hash, {'to': 'd4b96cd1'})],

	'0dd26508': [('info', 'v2.2 -> v2.3: FuXuan Head Diffuse Hash'),      (upgrade_hash, {'to': '0bf30362'})],

	'9e822610': [('info', 'v2.2 -> v2.3: FuXuan BodyA Diffuse Hash'),     (upgrade_hash, {'to': '6455fc0a'})],
	'50b30274': [('info', 'v2.2 -> v2.3: FuXuan BodyA LightMap Hash'),    (upgrade_hash, {'to': '4ba289bf'})],
	'0172c74d': [('info', 'v2.2 -> v2.3: FuXuan BodyB Diffuse Hash'),     (upgrade_hash, {'to': '09c78c66'})],
	'd9171ad6': [('info', 'v2.2 -> v2.3: FuXuan BodyB LightMap Hash'),    (upgrade_hash, {'to': 'ce81f2e6'})],
	'02291372': [('info', 'v2.2 -> v2.3: FuXuan BodyB StockingMap Hash'), (upgrade_hash, {'to': 'c7b3e7bd'})],



	# MARK: Gallagher
	'3464c771': [('info', 'v2.2 -> v2.3: Gallagher Hair Draw Hash'),     (upgrade_hash, {'to': '4ce0e733'})],
	'e2a6c3dd': [('info', 'v2.2 -> v2.3: Gallagher Hair Position Hash'), (upgrade_hash, {'to': 'b0198c11'})],
	'8a910c8c': [('info', 'v2.2 -> v2.3: Gallagher Hair Texcoord Hash'), (upgrade_hash, {'to': '9023270b'})],
	'f5c82676': [('info', 'v2.2 -> v2.3: Gallagher Hair IB Hash'),       (upgrade_hash, {'to': 'e9f3a740'})],
	'8590504d': [('info', 'v2.2 -> v2.3: Gallagher Hair Diffuse Hash'),  (upgrade_hash, {'to': '0adf3bf9'})],
	'69d380ac': [('info', 'v2.2 -> v2.3: Gallagher Hair LightMap Hash'), (upgrade_hash, {'to': 'b1f5a889'})],

	'6c2c7e1c': [('info', 'v2.2 -> v2.3: Gallagher Head Diffuse Hash'),  (upgrade_hash, {'to': '81a00110'})],

	'4902ec09': [('info', 'v2.2 -> v2.3: Gallagher Body Diffuse Hash'),  (upgrade_hash, {'to': '585134a8'})],
	'851877a3': [('info', 'v2.2 -> v2.3: Gallagher Body LightMap Hash'), (upgrade_hash, {'to': '39bf93ba'})],



	# MARK: Gepard
	'd62bbd0f': [('info', 'v1.6 -> v2.0: Gepard Body Texcoord Hash'), (upgrade_hash, {'to': '04094d7e'})],
	'30aa99d6': [
		('info', 'v1.6 -> v2.0: Gepard Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'GepardBody',
			'hash': '1e4f876c',
			'trg_indices': ['0', '27621', '55773', '57774'],
			'src_indices': ['0', '31266',     '-1',   '-1'],
		})
	],

	'71ba118e': [('info', 'v2.2 -> v2.3: Gepard Hair Diffuse Hash'),   (upgrade_hash, {'to': 'a4d9351f'})],
	'12718dd9': [('info', 'v2.2 -> v2.3: Gepard Hair LightMap Hash'),  (upgrade_hash, {'to': '00e5e932'})],

	'67bf8ce8': [('info', 'v2.2 -> v2.3: Gepard Head Diffuse Hash'),   (upgrade_hash, {'to': '32a6a2cc'})],

	'19731fb9': [('info', 'v2.2 -> v2.3: Gepard BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'e70c5ef2'})],
	'da172387': [('info', 'v2.2 -> v2.3: Gepard BodyA LightMap Hash'), (upgrade_hash, {'to': '2ca81203'})],
	'369fb8ef': [('info', 'v2.2 -> v2.3: Gepard BodyB Diffuse Hash'),  (upgrade_hash, {'to': 'aff5c287'})],
	'2482636f': [('info', 'v2.2 -> v2.3: Gepard BodyB LightMap Hash'), (upgrade_hash, {'to': '2ba5e966'})],



	# MARK: Guinaifen
	'de1f98c0': [('info', 'v1.6 -> v2.0: Guinaifen Body Draw Hash'), 		   (upgrade_hash, {'to': '637ad2db'})],
	'6de824a0': [('info', 'v1.6 -> v2.0: Guinaifen Body Position Hash'), 	   (upgrade_hash, {'to': 'd08d6ebb'})],
	'4b1cdcfc': [('info', 'v1.6 -> v2.0: Guinaifen Body Position Extra Hash'), (upgrade_hash, {'to': '506edd10'})],
	'6e216a03': [('info', 'v1.6 -> v2.0: Guinaifen Body Texcoord Hash'), 	   (upgrade_hash, {'to': '2eeff76f'})],
	'75d5ec54': [
		('info', 'v1.6 -> v2.0: Guinaifen Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'GuinaifenBody',
			'hash': '79900144',
			'trg_indices': ['0', '8907', '34146', '54723'],
			'src_indices': ['0',   '-1', '34146',    '-1'],
		})
	],
	'd08d6ebb': [
		('info', 'v2.1: Guinaifen Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '506edd10'}),
		(check_hash_not_in_ini, {'hash': '4b1cdcfc'}),
		(multiply_section, {
			'titles': ['GuinaifenBodyPosition', 'GuinaifenBodyPosition_Extra'],
			'hashes': ['d08d6ebb', '506edd10']
		})
	],

	'c88f1557': [('info', 'v2.2 -> v2.3: Guinaifen Hair Diffuse Hash'),      (upgrade_hash, {'to': 'fbd7db30'})],
	'33043521': [('info', 'v2.2 -> v2.3: Guinaifen Hair LightMap Hash'),     (upgrade_hash, {'to': 'c6e13e26'})],

	'7c097e20': [('info', 'v2.2 -> v2.3: Guinaifen Head Diffuse Hash'),      (upgrade_hash, {'to': '81dd54bc'})],

	'e73b9426': [('info', 'v2.2 -> v2.3: Guinaifen BodyA Diffuse Hash'),     (upgrade_hash, {'to': 'ae6de86c'})],
	'd6a8cff9': [('info', 'v2.2 -> v2.3: Guinaifen BodyA LightMap Hash'),    (upgrade_hash, {'to': '4092649e'})],
	'47551426': [('info', 'v2.2 -> v2.3: Guinaifen BodyA StockingMap Hash'), (upgrade_hash, {'to': 'caf58d2a'})],
	'd5d770b0': [('info', 'v2.2 -> v2.3: Guinaifen BodyC Diffuse Hash'),     (upgrade_hash, {'to': 'b710c78e'})],
	'a72e61d5': [('info', 'v2.2 -> v2.3: Guinaifen BodyC LightMap Hash'),    (upgrade_hash, {'to': '4463cc21'})],



	# MARK: Hanya
	'a73510da': [('info', 'v1.6 -> v2.0: Hanya Body Texcoord Hash'), (upgrade_hash, {'to': '69a81bdb'})],
	'42de1256': [
		('info', 'v1.6 -> v2.0: Hanya Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'HanyaBody',
			'hash': 'b1c2c937',
			'trg_indices': ['0', '28818', '51666', '52734'],
			'src_indices': ['0', '29886',    '-1',    '-1'],
		})
	],

	'8bc1d1db': [('info', 'v2.2 -> v2.3: Hanya Hair Diffuse Hash'),      (upgrade_hash, {'to': '7b9e82c5'})],
	'18503e31': [('info', 'v2.2 -> v2.3: Hanya Hair LightMap Hash'),     (upgrade_hash, {'to': '44c3983d'})],

	'19cae91f': [('info', 'v2.2 -> v2.3: Hanya Head Diffuse Hash'),      (upgrade_hash, {'to': '6d95729a'})],

	'b6dea863': [('info', 'v2.2 -> v2.3: Hanya BodyA Diffuse Hash'),     (upgrade_hash, {'to': '3a1da416'})],
	'b4d0253c': [('info', 'v2.2 -> v2.3: Hanya BodyA LightMap Hash'),    (upgrade_hash, {'to': '7c08d55d'})],
	'9233c696': [('info', 'v2.2 -> v2.3: Hanya BodyA StockingMap Hash'), (upgrade_hash, {'to': '162667f6'})],
	'e7afec9f': [('info', 'v2.2 -> v2.3: Hanya BodyB Diffuse Hash'),     (upgrade_hash, {'to': 'd927b45a'})],
	'c2817103': [('info', 'v2.2 -> v2.3: Hanya BodyB LightMap Hash'),    (upgrade_hash, {'to': '537979fe'})],
	'ca76ff40': [('info', 'v2.2 -> v2.3: Hanya BodyB StockingMap Hash'), (upgrade_hash, {'to': '61d0592b'})],



	# MARK: Herta
	'93835e8f': [('info', 'v1.6 -> v2.0: Herta Body Draw Hash'),     (upgrade_hash, {'to': 'c08327f8'})],
	'2074e2ef': [('info', 'v1.6 -> v2.0: Herta Body Position Hash'), (upgrade_hash, {'to': '73749b98'})],
	'c12363b4': [('info', 'v1.6 -> v2.0: Herta Body Texcoord Hash'), (upgrade_hash, {'to': '91c0cb8e'})],
	'5186a9b8': [
		('info', 'v1.6 -> v2.0: Herta Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'HertaBody',
			'hash': '9553ff35',
			'trg_indices': ['0',  '8814', '53166'],
			'src_indices': ['0',    '-1', '52458'],
		})
	],

	'd53e94bd': [('info', 'v2.2 -> v2.3: Herta Hair Diffuse Hash'),  (upgrade_hash, {'to': 'ee995067'})],
	'84c9c04b': [('info', 'v2.2 -> v2.3: Herta Hair LightMap Hash'), (upgrade_hash, {'to': '515a7733'})],

	'029aeabf': [('info', 'v2.2 -> v2.3: Herta Head Diffuse Hash'),  (upgrade_hash, {'to': 'e116363f'})],

	'01057b08': [('info', 'v2.2 -> v2.3: Herta Body Diffuse Hash'),  (upgrade_hash, {'to': 'e07c10c9'})],
	'22d89ecd': [('info', 'v2.2 -> v2.3: Herta Body LightMap Hash'), (upgrade_hash, {'to': 'b878ef55'})],



	# MARK: Himeko
	'5d98de11': [('info', 'v1.6 -> v2.0: Himeko Body Position Extra Hash'), (upgrade_hash, {'to': '3cfb3645'})],
	'77cb214c': [('info', 'v1.6 -> v2.0: Himeko Body Texcoord Hash'),       (upgrade_hash, {'to': 'b9e9ae3b'})],
	'e4640c8c': [
		('info', 'v1.6 -> v2.0: Himeko Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'HimekoBody',
			'hash': 'e79e4018',
			'trg_indices': ['0', '27381', '37002', '47634'],
			'src_indices': ['-1',    '0', '37002',    '-1'],
		})
	],

	'c08f4727': [('info', 'v2.2 -> v2.3: Himeko Hair Texcoord Hash'),  (upgrade_hash, {'to': 'fa440b40'})],
	'fc068361': [('info', 'v2.2 -> v2.3: Himeko Hair Diffuse Hash'),   (upgrade_hash, {'to': 'd4634d6f'})],
	'9adcae2d': [('info', 'v2.2 -> v2.3: Himeko Hair LightMap Hash'),  (upgrade_hash, {'to': 'a700d6b4'})],

	'1acfc83f': [('info', 'v2.2 -> v2.3: Himeko Head Diffuse Hash'),   (upgrade_hash, {'to': '832e3b54'})],

	'f4b0bd6d': [('info', 'v2.2 -> v2.3: Himeko Body Draw Hash'),      (upgrade_hash, {'to': '62d53b1f'})],
	'4747010d': [('info', 'v2.2 -> v2.3: Himeko Body Position Hash'),  (upgrade_hash, {'to': 'd122877f'})],
	'b9e9ae3b': [('info', 'v2.2 -> v2.3: Himeko Body Texcoord Hash'),  (upgrade_hash, {'to': '2bf29f1f'})],
	'e79e4018': [('info', 'v2.2 -> v2.3: Himeko Body IB Hash'),        (upgrade_hash, {'to': '2dc0061c'})],
	'e2f15a68': [('info', 'v2.2 -> v2.3: Himeko BodyA Diffuse Hash'),  (upgrade_hash, {'to': '6920fe29'})],
	'27bf0a6a': [('info', 'v2.2 -> v2.3: Himeko BodyA LightMap Hash'), (upgrade_hash, {'to': '520336ef'})],
	'24e4c5ad': [('info', 'v2.2 -> v2.3: Himeko BodyC Diffuse Hash'),  (upgrade_hash, {'to': 'a769be88'})],
	'ce965b0d': [('info', 'v2.2 -> v2.3: Himeko BodyC LightMap Hash'), (upgrade_hash, {'to': '094b77c6'})],


	'3cfb3645': [('info', 'v2.2 -> v2.3: Himeko Body Position Extra Hash'),  (upgrade_hash, {'to': '5212e2f9'})],
	'd122877f': [
		('info', 'v2.3: Himeko Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '5d98de11'}),
		(check_hash_not_in_ini, {'hash': '3cfb3645'}),
		(check_hash_not_in_ini, {'hash': '5212e2f9'}),
		(multiply_section, {
			'titles': ['HimekoBodyPosition', 'HimekoBodyPosition_Extra'],
			'hashes': ['d122877f', '5212e2f9']
		})
	],



	# MARK: Hook
	'0361b6bf': [('info', 'v1.6 -> v2.0: Hook Body Position Hash'), (upgrade_hash, {'to': '9d68704b'})],
	'f1788f95': [('info', 'v1.6 -> v2.0: Hook Body Texcoord Hash'), (upgrade_hash, {'to': '59ccb47b'})],
	'26276c57': [
		('info', 'v1.6 -> v2.0: Hook Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'HookBody',
			'hash': '0c614d18',
			'trg_indices': ['0', '42189'],
			'src_indices': ['0',    '-1'],
		})
	],

	'fcd7ee7b': [('info', 'v2.2 -> v2.3: Hook Hair Diffuse Hash'),  (upgrade_hash, {'to': 'f1ca01f3'})],
	'a8e81b3a': [('info', 'v2.2 -> v2.3: Hook Hair LightMap Hash'), (upgrade_hash, {'to': 'db6ff34c'})],

	'd76e33a6': [('info', 'v2.2 -> v2.3: Hook Head Diffuse Hash'),  (upgrade_hash, {'to': '9588db54'})],

	'b8d85743': [('info', 'v2.2 -> v2.3: Hook Body Diffuse Hash'),  (upgrade_hash, {'to': '8ab99329'})],
	'a49680b5': [('info', 'v2.2 -> v2.3: Hook Body LightMap Hash'), (upgrade_hash, {'to': '4a45ac95'})],



	# MARK: Huohuo
	'd9ac0987': [('info', 'v1.6 -> v2.0: Huohuo Body Draw Hash'), 	  (upgrade_hash, {'to': '67a078bd'})],
	'6a5bb5e7': [('info', 'v1.6 -> v2.0: Huohuo Body Position Hash'), (upgrade_hash, {'to': 'd457c4dd'})],
	'47dbd6aa': [('info', 'v1.6 -> v2.0: Huohuo Body Texcoord Hash'), (upgrade_hash, {'to': '2a306f9c'})],
	'f05d31fb': [
		('info', 'v1.6 -> v2.0: Huohuo Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'HuohuoBody',
			'hash': 'e9aecd0b',
			'trg_indices': ['0', '45165'],
			'src_indices': ['0',    '-1'],
		})
	],

	'f8d072c0': [('info', 'v2.2 -> v2.3: Huohuo Hair Diffuse Hash'),  (upgrade_hash, {'to': '057f648d'})],
	'c0f8d106': [('info', 'v2.2 -> v2.3: Huohuo Hair LightMap Hash'), (upgrade_hash, {'to': '772090fc'})],

	'7dbe20be': [('info', 'v2.2 -> v2.3: Huohuo Head Diffuse Hash'),  (upgrade_hash, {'to': '6f1e9080'})],

	'70d3fdb7': [('info', 'v2.2 -> v2.3: Huohuo Body Diffuse Hash'),  (upgrade_hash, {'to': '6598aacd'})],
	'6e5470a5': [('info', 'v2.2 -> v2.3: Huohuo Body LightMap Hash'), (upgrade_hash, {'to': 'afac01be'})],



	# MARK: Jingliu
	'33f9fe71': [('info', 'v1.4 -> v1.6: Jingliu BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'bdbc6dce'})],
	'67344bd9': [('info', 'v1.4 -> v1.6: Jingliu BodyA LightMap Hash'), (upgrade_hash, {'to': '5f55eaff'})],
	'81c023e7': [('info', 'v1.6 -> v2.0: Jingliu Body Texcoord Hash'),  (upgrade_hash, {'to': 'ba517fa0'})],
	'5564183c': [
		('info', 'v1.6 -> v2.0: Jingliu Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'JingliuBody',
			'hash': 'e8d31b6a',
			'trg_indices': ['0', '51096'],
			'src_indices': ['0',    '-1'],
		})
	],

	'1bc1cfa0': [('info', 'v2.2 -> v2.3: Jingliu Hair Diffuse Hash'),  (upgrade_hash, {'to': 'f73f74cb'})],
	'fbcefb7e': [('info', 'v2.2 -> v2.3: Jingliu Hair LightMap Hash'), (upgrade_hash, {'to': '70ae9680'})],

	'c36ab82e': [('info', 'v2.2 -> v2.3: Jingliu Head Diffuse Hash'),  (upgrade_hash, {'to': '25dd2c46'})],

	'bdbc6dce': [('info', 'v2.2 -> v2.3: Jingliu Body Diffuse Hash'),  (upgrade_hash, {'to': '74370924'})],
	'5f55eaff': [('info', 'v2.2 -> v2.3: Jingliu Body LightMap Hash'), (upgrade_hash, {'to': 'd3a91ee8'})],



	# MARK: JingYuan
	'8f1a29cf': [('info', 'v1.6 -> v2.0: JingYuan Body Texcoord Hash'), (upgrade_hash, {'to': '3423e10d'})],
	'1be11c4f': [
		('info', 'v1.6 -> v2.0: JingYuan Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'JingYuanBody',
			'hash': '1240ff30',
			'trg_indices': ['0', '11505', '17772', '53565'],
			'src_indices': ['0',    '-1', '17772',    '-1'],
		})
	],
	'3423e10d': [('info', 'v2.0 -> v2.1: JingYuan Body Texcoord Hash'), (upgrade_hash, {'to': 'ebde517e'})],
	'1240ff30': [
		('info', 'v2.0 -> v2.1: JingYuan Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'JingYuanBody',
			'hash': 'b2501828',
			'trg_indices': ['0', '11589', '17772', '53565'],
			'src_indices': ['0', '11505', '17772', '53565'],
		})
	],
	'061dd140': [('info', 'v2.0 -> v2.1: JingYuan Head Draw Hash'), 	(upgrade_hash, {'to': 'c8841602'})],
	'ee205a7b': [('info', 'v2.0 -> v2.1: JingYuan Head Position Hash'), (upgrade_hash, {'to': '9d60acea'})],
	'7c112f46': [('info', 'v2.0 -> v2.1: JingYuan Head Texcoord Hash'), (upgrade_hash, {'to': '20110b85'})],
	'22147cfe': [('info', 'v2.0 -> v2.1: JingYuan Head IB Hash'),	    (upgrade_hash, {'to': 'a0459b05'})],

	'1da0a14c': [('info', 'v2.2 -> v2.3: JingYuan Hair Diffuse Hash'),   (upgrade_hash, {'to': '1ac1a7fb'})],
	'97eb13d9': [('info', 'v2.2 -> v2.3: JingYuan Hair LightMap Hash'),  (upgrade_hash, {'to': '9f47fa33'})],

	'7dc71e05': [('info', 'v2.2 -> v2.3: JingYuan Head Diffuse Hash'),   (upgrade_hash, {'to': 'f585da62'})],

	'48c0277a': [('info', 'v2.2 -> v2.3: JingYuan BodyA Diffuse Hash'),  (upgrade_hash, {'to': '26735526'})],
	'7dfa92fa': [('info', 'v2.2 -> v2.3: JingYuan BodyA LightMap Hash'), (upgrade_hash, {'to': 'd5b2a23a'})],
	'fd74f596': [('info', 'v2.2 -> v2.3: JingYuan BodyC Diffuse Hash'),  (upgrade_hash, {'to': 'b1b4f581'})],
	'9fe0c156': [('info', 'v2.2 -> v2.3: JingYuan BodyC LightMap Hash'), (upgrade_hash, {'to': '16a2d8bb'})],

	'baaa1347': [('info', 'v2.4 -> v2.5: JingYuan Body Draw Hash'), 	(upgrade_hash, {'to': '0b529127'})],
	'095daf27': [('info', 'v2.4 -> v2.5: JingYuan Body Position Hash'), (upgrade_hash, {'to': 'b8a52d47'})],
	'ebde517e': [('info', 'v2.4 -> v2.5: JingYuan Body Texcoord Hash'), (upgrade_hash, {'to': '9f387461'})],
	'b2501828': [
		('info', 'v2.4 -> v2.5: JingYuan Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'JingYuanBody',
			'hash': 'b1191b83',
			'trg_indices': ['0', '11505', '17778', '53571'],
			'src_indices': ['0', '11589', '17772', '53565'],
		})
	],


	# MARK: Kafka
	'51abd7c9': [('info', 'v1.4 -> v1.6: Kafka Body Position Hash'), 	   (upgrade_hash, {'to': 'deb266a8'})],
	'38072744': [('info', 'v1.4 -> v1.6: Kafka Body Position Extra Hash'), (upgrade_hash, {'to': '17cb3b3e'})],
	'a6813fd5': [('info', 'v1.4 -> v1.6: Kafka Body Texcoord Hash'), 	   (upgrade_hash, {'to': '190e483a'})],
	'b7401039': [('info', 'v1.4 -> v1.6: Kafka Body IB Hash'), 			   (upgrade_hash, {'to': '8d847042'})],

	'17cb3b3e': [('info', 'v1.6 -> v2.0: Kafka Body Position Extra Hash'), (upgrade_hash, {'to': 'cd2222f8'})],
	'190e483a': [('info', 'v1.6 -> v2.0: Kafka Body Texcoord Hash'), 	   (upgrade_hash, {'to': '05ded7f7'})],
	'e25c6ba9': [('info', 'v1.6 -> v2.0: Kafka Body Draw Hash'), 		   (upgrade_hash, {'to': '6d45dac8'})],
	'8d847042': [
		('info', 'v1.6 -> v2.0: Kafka Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'KafkaBody',
			'hash': 'fa23099d',
			'trg_indices': ['0', '8787', '16083', '35439', '41406'],
			'src_indices': ['0',   '-1', '16083',    '-1', '41406'],
		})
	],
	'deb266a8': [
		('info', 'v2.1: Kafka Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': 'cd2222f8'}),
		(check_hash_not_in_ini, {'hash': '17cb3b3e'}),
		(check_hash_not_in_ini, {'hash': '38072744'}),
		(multiply_section, {
			'titles': ['KafkaBodyPosition', 'KafkaBodyPosition_Extra'],
			'hashes': ['deb266a8', 'cd2222f8']
		})
	],

	'cd60c900': [('info', 'v2.2 -> v2.3: Kafka Hair Texcoord Hash'),     (upgrade_hash, {'to': 'ddbe6ba2'})],
	'55d258a5': [('info', 'v2.2 -> v2.3: Kafka Hair Diffuse Hash'),      (upgrade_hash, {'to': 'cb354b6b'})],
	'dc6aaf17': [('info', 'v2.2 -> v2.3: Kafka Hair LightMap Hash'),     (upgrade_hash, {'to': 'e07efe45'})],

	'1d74e2f5': [('info', 'v2.2 -> v2.3: Kafka Head Diffuse Hash'),      (upgrade_hash, {'to': 'cf90e442'})],

	'05ded7f7': [('info', 'v2.2 -> v2.3: Kafka Body Texcoord Hash'),     (upgrade_hash, {'to': 'd14b435e'})],
	'0da4c671': [('info', 'v2.2 -> v2.3: Kafka BodyA Diffuse Hash'),     (upgrade_hash, {'to': '207c0559'})],
	'cc322c0f': [('info', 'v2.2 -> v2.3: Kafka BodyA LightMap Hash'),    (upgrade_hash, {'to': '32b5b281'})],
	'339785c4': [('info', 'v2.2 -> v2.3: Kafka BodyA StockingMap Hash'), (upgrade_hash, {'to': 'fd0ef162'})],

	'e8e2b6da': [('info', 'v2.2 -> v2.3: Kafka BodyC Diffuse Hash'),     (upgrade_hash, {'to': 'c00b55bc'})],
	'7bd0d180': [('info', 'v2.2 -> v2.3: Kafka BodyC LightMap Hash'),    (upgrade_hash, {'to': '45d15ffb'})],



	# MARK: Luka
	'e0c63ed8': [('info', 'v1.4 -> v1.6: Luka BodyA LightMap Hash'), (upgrade_hash, {'to': '31724118'})],
	'78d83281': [('info', 'v1.4 -> v1.6: Luka BodyB LightMap Hash'), (upgrade_hash, {'to': '58749091'})],

	'f7d86ef0': [('info', 'v1.6 -> v2.0: Luka Body Position Extra Hash'), (upgrade_hash, {'to': '3e55d897'})],
	'098a46fc': [('info', 'v1.6 -> v2.0: Luka Body Texcoord Hash'), 	  (upgrade_hash, {'to': '11dd3da1'})],
	'5cd5d088': [('info', 'v1.6 -> v2.0: Luka BodyA Diffuse Hash'), 	  (upgrade_hash, {'to': '3ba22ed5'})],
	'148d7790': [('info', 'v1.6 -> v2.0: Luka BodyB Diffuse Hash'), 	  (upgrade_hash, {'to': '73fa89cd'})],
	'5332e0c4': [
		('info', 'v1.6 -> v2.0: Luka Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'LukaBody',
			'hash': 'e0c9f7ec',
			'trg_indices': ['0', '25371', '49992', '52830'],
			'src_indices': ['0', '28209', 	 '-1',    '-1'],
		})
	],
	'03fba4b4': [
		('info', 'v2.1: Luka Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '3e55d897'}),
		(check_hash_not_in_ini, {'hash': 'f7d86ef0'}),
		(multiply_section, {
			'titles': ['LukaBodyPosition', 'LukaBodyPosition_Extra'],
			'hashes': ['03fba4b4', '3e55d897']
		})
	],

	'2427134f': [('info', 'v2.2 -> v2.3: Luka Hair Diffuse Hash'),      (upgrade_hash, {'to': '6e34ac83'})],
	'c6b43fae': [('info', 'v2.2 -> v2.3: Luka Hair LightMap Hash'),     (upgrade_hash, {'to': '6d784dff'})],

	'4d8ef1d8': [('info', 'v2.2 -> v2.3: Luka Head Diffuse Hash'),      (upgrade_hash, {'to': 'e8d263c3'})],

	'3ba22ed5': [('info', 'v2.2 -> v2.3: Luka BodyA Diffuse Hash'),     (upgrade_hash, {'to': 'a026c901'})],
	'31724118': [('info', 'v2.2 -> v2.3: Luka BodyA LightMap Hash'),    (upgrade_hash, {'to': '1762e62c'})],
	'73fa89cd': [('info', 'v2.2 -> v2.3: Luka BodyB Diffuse Hash'),     (upgrade_hash, {'to': '00970f33'})],
	'58749091': [('info', 'v2.2 -> v2.3: Luka BodyB LightMap Hash'),    (upgrade_hash, {'to': '31483729'})],



	# MARK: Luocha
	'b5c61afb': [('info', 'v1.6 -> v2.0: Luocha Body Draw Hash'),     (upgrade_hash, {'to': '194a6495'})],
	'0631a69b': [('info', 'v1.6 -> v2.0: Luocha Body Position Hash'), (upgrade_hash, {'to': 'aabdd8f5'})],
	'a67c4fed': [('info', 'v1.6 -> v2.0: Luocha Body Texcoord Hash'), (upgrade_hash, {'to': '80da6fb8'})],
	'6c659c20': [
		('info', 'v1.6 -> v2.0: Luocha Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'LuochaBody',
			'hash': '149a218b',
			'trg_indices': ['0', '4503', '34437', '45126'],
			'src_indices': ['0',   '-1', '34437',    '-1'],
		})
	],

	'17542aca': [('info', 'v2.2 -> v2.3: Luocha Hair Diffuse Hash'),      (upgrade_hash, {'to': '9420ae03'})],
	'dadf8929': [('info', 'v2.2 -> v2.3: Luocha Hair LightMap Hash'),     (upgrade_hash, {'to': 'a7e6fa4f'})],

	'8af54c5d': [('info', 'v2.2 -> v2.3: Luocha Head Diffuse Hash'),      (upgrade_hash, {'to': '664f2f29'})],

	'f9d9adb8': [('info', 'v2.2 -> v2.3: Luocha BodyA Diffuse Hash'),     (upgrade_hash, {'to': '7185fd68'})],
	'd8dd2b05': [('info', 'v2.2 -> v2.3: Luocha BodyA LightMap Hash'),    (upgrade_hash, {'to': 'eb99eb88'})],
	'a1fac228': [('info', 'v2.2 -> v2.3: Luocha BodyC Diffuse Hash'),     (upgrade_hash, {'to': '65dec275'})],
	'ff928485': [('info', 'v2.2 -> v2.3: Luocha BodyC LightMap Hash'),    (upgrade_hash, {'to': '45feb69d'})],



	# MARK: Lynx
	'8e595209': [('info', 'v1.6 -> v2.0: Lynx Body Texcoord Hash'), (upgrade_hash, {'to': '52a44eba'})],
	'b6019d61': [('info', 'v1.6 -> v2.0: Lynx BodyA Diffuse Hash'), (upgrade_hash, {'to': 'e2bad880'})],
	'e8c4b27f': [
		('info', 'v1.6 -> v2.0: Lynx Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'LynxBody',
			'hash': '71647b48',
			'trg_indices': ['0', '51510'],
			'src_indices': ['0',    '-1'],
		})
	],

	'6d27e7f2': [('info', 'v2.2 -> v2.3: Lynx Hair Diffuse Hash'),  (upgrade_hash, {'to': 'f4db275c'})],
	'a874888b': [('info', 'v2.2 -> v2.3: Lynx Hair LightMap Hash'), (upgrade_hash, {'to': '8dc79479'})],

	'3e2ad9b8': [('info', 'v2.2 -> v2.3: Lynx Head Diffuse Hash'),  (upgrade_hash, {'to': 'e5d8fa29'})],

	'52a44eba': [('info', 'v2.2 -> v2.3: Lynx Body Texcoord Hash'), (upgrade_hash, {'to': 'bffadc55'})],
	'e2bad880': [('info', 'v2.2 -> v2.3: Lynx Body Diffuse Hash'),  (upgrade_hash, {'to': '6c664cc4'})],
	'6cb92f15': [('info', 'v2.2 -> v2.3: Lynx Body LightMap Hash'), (upgrade_hash, {'to': '540bf4e4'})],

	'09667bf6': [
		('info', 'v2.3: Lynx Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '09667bf6'}),
		(check_hash_not_in_ini, {'hash': '7b23e3e6'}),
		(multiply_section, {
			'titles': ['LynxBodyPosition', 'LynxBodyPosition_Extra'],
			'hashes': ['09667bf6', '7b23e3e6']
		})
	],



	# MARK: March7th
	'fcef8885': [('info', 'v1.6 -> v2.0: March7th Body Texcoord Hash'), (upgrade_hash, {'to': 'ecf4648c'})],
 	'97ad7623': [
		('info', 'v1.6 -> v2.0: March7th Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'March7thBody',
			'hash': '5212ce68',
			'trg_indices': ['0', '30828', '41466', '53751'],
			'src_indices': ['0', '32502',    '-1',    '-1'],
		})
	],

	'1ed7e59d': [('info', 'v2.2 -> v2.3: March7th Hair Texcoord Hash'),  (upgrade_hash, {'to': '948c4e59'})],
	'6bd71ad9': [('info', 'v2.2 -> v2.3: March7th Hair Diffuse Hash'),   (upgrade_hash, {'to': 'e299099f'})],
	'371ca498': [('info', 'v2.2 -> v2.3: March7th Hair LightMap Hash'),  (upgrade_hash, {'to': '89cd27c7'})],

	'2d25d041': [('info', 'v2.2 -> v2.3: March7th Head Diffuse Hash'),   (upgrade_hash, {'to': 'dbbb9b12'})],

	'ecf4648c': [('info', 'v2.2 -> v2.3: March7th Body Texcoord Hash'),  (upgrade_hash, {'to': 'b950fe40'})],
	'e6b35ac0': [('info', 'v2.2 -> v2.3: March7th BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'a9101746'})],
	'8c584d30': [('info', 'v2.2 -> v2.3: March7th BodyA LightMap Hash'), (upgrade_hash, {'to': '87f4596d'})],
	'b57574b3': [('info', 'v2.2 -> v2.3: March7th BodyB Diffuse Hash'),  (upgrade_hash, {'to': 'cada1307'})],
	'2006cd6a': [('info', 'v2.2 -> v2.3: March7th BodyB LightMap Hash'), (upgrade_hash, {'to': '01f9dbb8'})],



	# MARK: Misha
	'0f570849': [('info', 'v2.0 -> v2.1: Misha Head Position Hash'), (upgrade_hash, {'to': 'be8ee647'})],
	'8aa3d867': [('info', 'v2.0 -> v2.1: Misha Head Texcoord Hash'), (upgrade_hash, {'to': 'ee650b42'})],

	'c49badcb': [('info', 'v2.2 -> v2.3: Misha Hair Draw Hash'),     (upgrade_hash, {'to': 'cdc4b6ac'})],
	'4b221f10': [('info', 'v2.2 -> v2.3: Misha Hair Position Hash'), (upgrade_hash, {'to': 'af206cba'})],
	'9980f41b': [('info', 'v2.2 -> v2.3: Misha Hair Texcoord Hash'), (upgrade_hash, {'to': 'e35c9a5a'})],
	'66e3518a': [('info', 'v2.2 -> v2.3: Misha Hair IB Hash'),       (upgrade_hash, {'to': '08e4fb11'})],
	'028905ee': [('info', 'v2.2 -> v2.3: Misha Hair Diffuse Hash'),  (upgrade_hash, {'to': '328e0604'})],
	'8e793185': [('info', 'v2.2 -> v2.3: Misha Hair LightMap Hash'), (upgrade_hash, {'to': 'f66cebd0'})],

	'ee650b42': [('info', 'v2.2 -> v2.3: Misha Head Texcoord Hash'), (upgrade_hash, {'to': '7abbb9e1'})],
	'958056b6': [('info', 'v2.2 -> v2.3: Misha Head Diffuse Hash'),  (upgrade_hash, {'to': '60707bff'})],

	'157dc503': [('info', 'v2.2 -> v2.3: Misha Body Diffuse Hash'),  (upgrade_hash, {'to': '2b17a6a5'})],
	'429f63a8': [('info', 'v2.2 -> v2.3: Misha Body LightMap Hash'), (upgrade_hash, {'to': 'ce79ee01'})],



	# MARK: Natasha
	'fc66ad46': [('info', 'v1.6 -> v2.0: Natasha Body Position Extra Hash'), (upgrade_hash, {'to': '4958a3f3'})],
	'9ac894b4': [('info', 'v1.6 -> v2.0: Natasha Body Texcoord Hash'),       (upgrade_hash, {'to': 'b9b8b2a1'})],
  	'005670d8': [
		('info', 'v1.6 -> v2.0: Natasha Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'NatashaBody',
			'hash': '68dd15e8',
			'trg_indices': [ '0', '3024', '38907', '45612'],
			'src_indices': ['-1',    '0',    '-1', '38907'],
		})
	],
	'0de1ff21': [
		('info', 'v2.1: Natasha Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '4958a3f3'}),
		(check_hash_not_in_ini, {'hash': 'fc66ad46'}),
		(multiply_section, {
			'titles': ['NatashaBodyPosition', 'NatashaBodyPosition_Extra'],
			'hashes': ['0de1ff21', '4958a3f3']
		})
	],

	'5f44fc0d': [('info', 'v2.2 -> v2.3: Natasha Hair Texcoord Hash'),     (upgrade_hash, {'to': 'a9728390'})],
	'595464a6': [('info', 'v2.2 -> v2.3: Natasha Hair Diffuse Hash'),      (upgrade_hash, {'to': '08ac31d1'})],
	'abcc21d1': [('info', 'v2.2 -> v2.3: Natasha Hair LightMap Hash'),     (upgrade_hash, {'to': '260f2286'})],

	'5a9597db': [('info', 'v2.2 -> v2.3: Natasha Head Diffuse Hash'),      (upgrade_hash, {'to': 'b719225a'})],

	'b9b8b2a1': [('info', 'v2.2 -> v2.3: Natasha Body Texcoord Hash'),     (upgrade_hash, {'to': 'f1668e08'})],
	'209f5c65': [('info', 'v2.2 -> v2.3: Natasha BodyB Diffuse Hash'),     (upgrade_hash, {'to': '6f4ab910'})],
	'bfd47fe8': [('info', 'v2.2 -> v2.3: Natasha BodyB LightMap Hash'),    (upgrade_hash, {'to': 'fe813491'})],
	'88be8df6': [('info', 'v2.2 -> v2.3: Natasha BodyB StockingMap Hash'), (upgrade_hash, {'to': 'defb30fc'})],
	'3bd51af4': [('info', 'v2.2 -> v2.3: Natasha BodyD Diffuse Hash'),     (upgrade_hash, {'to': '519ef69f'})],
	'2799f499': [('info', 'v2.2 -> v2.3: Natasha BodyD LightMap Hash'),    (upgrade_hash, {'to': '919da513'})],
	'de96634b': [('info', 'v2.2 -> v2.3: Natasha BodyD StockingMap Hash'), (upgrade_hash, {'to': '236df0fa'})],



	# MARK: Pela
	'6148b897': [('info', 'v1.6 -> v2.0: Pela Body Texcoord Hash'), (upgrade_hash, {'to': '77a2f3bf'})],
  	'f4eb23b2': [
		('info', 'v1.6 -> v2.0: Pela Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'PelaBody',
			'hash': '98dbd548',
			'trg_indices': ['0', '44043'],
			'src_indices': ['0',    '-1'],
		})
	],

	'934172e5': [('info', 'v2.2 -> v2.3: Pela Hair Diffuse Hash'),     (upgrade_hash, {'to': '7fcd70ea'})],
	'54a11a98': [('info', 'v2.2 -> v2.3: Pela Hair LightMap Hash'),    (upgrade_hash, {'to': '93279a4a'})],

	'0a50c14c': [('info', 'v2.2 -> v2.3: Pela Head Diffuse Hash'),     (upgrade_hash, {'to': '945d61df'})],

	'e02d100c': [('info', 'v2.2 -> v2.3: Pela Body Diffuse Hash'),     (upgrade_hash, {'to': '48fca7f8'})],
	'ffeb1d46': [('info', 'v2.2 -> v2.3: Pela Body LightMap Hash'),    (upgrade_hash, {'to': '21d34147'})],
	'8df14d0a': [('info', 'v2.2 -> v2.3: Pela Body StockingMap Hash'), (upgrade_hash, {'to': '883e4c54'})],



	# MARK: Qingque
	'3a305670': [('info', 'v1.6 -> v2.0: Qingque Body Texcoord Hash'), (upgrade_hash, {'to': 'cc2db614'})],
  	'daafea36': [
		('info', 'v1.6 -> v2.0: Qingque Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'QingqueBody',
			'hash': '0a82ceb7',
			'trg_indices': ['0', '23730', '27573', '45615'],
			'src_indices': ['0',    '-1',    '-1', '27765'],
		})
	],

	'73fbbace': [('info', 'v2.2 -> v2.3: Qingque Hair Diffuse Hash'),   (upgrade_hash, {'to': 'd9e91d27'})],
	'48829296': [('info', 'v2.2 -> v2.3: Qingque Hair LightMap Hash'),  (upgrade_hash, {'to': 'ddabcef6'})],

	'c2559faf': [('info', 'v2.2 -> v2.3: Qingque Head Diffuse Hash'),   (upgrade_hash, {'to': '5421f07d'})],


	'55e1b1f8': [('info', 'v2.2 -> v2.3: Qingque Body Draw Hash'),      (upgrade_hash, {'to': '311daa47'})],
	'e6160d98': [('info', 'v2.2 -> v2.3: Qingque Body Position Hash'),  (upgrade_hash, {'to': '82ea1627'})],
	'cc2db614': [('info', 'v2.2 -> v2.3: Qingque Body Texcoord Hash'),  (upgrade_hash, {'to': 'd97fd893'})],
	'0a82ceb7': [('info', 'v2.2 -> v2.3: Qingque Body IB Hash'),        (upgrade_hash, {'to': '21856dc2'})],

	'ff995bd0': [('info', 'v2.2 -> v2.3: Qingque BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'd92826b3'})],
	'2d563efe': [('info', 'v2.2 -> v2.3: Qingque BodyA LightMap Hash'), (upgrade_hash, {'to': 'a85d8219'})],
	'149c086c': [('info', 'v2.2 -> v2.3: Qingque BodyC Diffuse Hash'),  (upgrade_hash, {'to': '92c74827'})],
	'2b135afe': [('info', 'v2.2 -> v2.3: Qingque BodyC LightMap Hash'), (upgrade_hash, {'to': 'f57f3990'})],



	# MARK: Robin
	'490e6507': [('info', 'v2.2 -> v2.3: Robin HairA Diffuse Hash'),       (upgrade_hash, {'to': 'b7d76947'})],
	'63aafaed': [('info', 'v2.2 -> v2.3: Robin HairA LightMap Hash'),      (upgrade_hash, {'to': '445abbfc'})],
 
	'07fd3ce1': [('info', 'v2.2 -> v2.3: Robin HeadA Diffuse Hash'),       (upgrade_hash, {'to': '14116af5'})],
 
	'312e2c95': [('info', 'v2.2 -> v2.3: Robin BodyA Diffuse Hash'),       (upgrade_hash, {'to': 'de39f5f2'})],
	'4c249936': [('info', 'v2.2 -> v2.3: Robin BodyA LightMap Hash'),      (upgrade_hash, {'to': '57ba7e2a'})],
 
	'9e6b5969': [('info', 'v2.2 -> v2.3: Robin BodyB StarrySkyMask Hash'), (upgrade_hash, {'to': 'e5ed0f89'})],
 
	'ef273dac': [('info', 'v2.5 -> v2.6: Robin Body Position Hash'),      (upgrade_hash, {'to': '22e9e92a'})],
	'43c5c007': [('info', 'v2.5 -> v2.6: Robin Body Texcoord Hash'),      (upgrade_hash, {'to': 'a65193dc'})],


	# MARK: RuanMei
	'6f3b9090': [('info', 'v1.6 -> v2.0: RuanMei Body Texcoord Hash'),  (upgrade_hash, {'to': '803d3eda'})],
	'35bf6c19': [('info', 'v1.6 -> v2.0: RuanMei BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'fe8145b1'})],
	'c984b1e6': [('info', 'v1.6 -> v2.0: RuanMei BodyA LightMap Hash'), (upgrade_hash, {'to': '9b63577a'})],
	'ab4af2cb': [
		('info', 'v2.1: RuanMei Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '7e4f7890'}),
		(multiply_section, {
			'titles': ['RuanMeiBodyPosition', 'RuanMeiBodyPosition_Extra'],
			'hashes': ['ab4af2cb', '7e4f7890']
		})
	],

	'f6491dae': [('info', 'v2.2 -> v2.3: RuanMei HairA Diffuse Hash'),  (upgrade_hash, {'to': '22e8a12f'})],
	'45e0fe2c': [('info', 'v2.2 -> v2.3: RuanMei HairA LightMap Hash'), (upgrade_hash, {'to': '0198e0df'})],
 
	'b3ddcd02': [('info', 'v2.2 -> v2.3: RuanMei HeadA Diffuse Hash'),  (upgrade_hash, {'to': 'fd3d44f8'})],
	
	'fe8145b1': [('info', 'v2.2 -> v2.3: RuanMei BodyA Diffuse Hash'),  (upgrade_hash, {'to': '5387a03e'})],
	'9b63577a': [('info', 'v2.2 -> v2.3: RuanMei BodyA LightMap Hash'), (upgrade_hash, {'to': '93eec3ab'})],



	# MARK: Sampo
	'75824b32': [('info', 'v2.2 -> v2.3: Sampo Hair Draw Hash'),     (upgrade_hash, {'to': '31447b51'})],
	'e07731c5': [('info', 'v2.2 -> v2.3: Sampo Hair Position Hash'), (upgrade_hash, {'to': '3095786c'})],
	'529994b6': [('info', 'v2.2 -> v2.3: Sampo Hair Texcoord Hash'), (upgrade_hash, {'to': '5974af55'})],
	'd2e6ad9b': [('info', 'v2.2 -> v2.3: Sampo Hair IB Hash'),       (upgrade_hash, {'to': '96243edc'})],
	'ec28a787': [('info', 'v2.2 -> v2.3: Sampo Hair Diffuse Hash'),  (upgrade_hash, {'to': '36d62e76'})],
	'22c6ec2c': [('info', 'v2.2 -> v2.3: Sampo Hair LightMap Hash'), (upgrade_hash, {'to': '989a13bb'})],

	'3095d3d1': [('info', 'v2.2 -> v2.3: Sampo Head Diffuse Hash'),  (upgrade_hash, {'to': '4c904279'})],

	'a81589e4': [('info', 'v2.2 -> v2.3: Sampo Body Texcoord Hash'), (upgrade_hash, {'to': 'e0274b6f'})],
   	'3ac42f7d': [
		('info', 'v2.2 -> v2.3: Sampo Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'SampoBody',
			'hash': '15761df0',
			'trg_indices': ['0', '20655'],
			'src_indices': ['0', '20637'],
		})
	],
	'85c01194': [('info', 'v2.2 -> v2.3: Sampo BodyA Diffuse Hash'),  (upgrade_hash, {'to': '297b7f7c'})],
	'e15ccf04': [('info', 'v2.2 -> v2.3: Sampo BodyA LightMap Hash'), (upgrade_hash, {'to': '1251e25b'})],
	'92065503': [('info', 'v2.2 -> v2.3: Sampo BodyB Diffuse Hash'),  (upgrade_hash, {'to': '4fd99756'})],
	'333b2634': [('info', 'v2.2 -> v2.3: Sampo BodyB LightMap Hash'), (upgrade_hash, {'to': '992d119f'})],



	# MARK: Seele
	'41943cc6': [('info', 'v1.6 -> v2.0: Seele Body Texcoord Hash'), (upgrade_hash, {'to': 'fe54239f'})],
   	'eb699635': [
		('info', 'v1.6 -> v2.0: Seele Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'SeeleBody',
			'hash': '6a522a54',
			'trg_indices': ['0', '11550', '19968', '49764'],
			'src_indices': ['0',    '-1', '19968',    '-1'],
		})
	],

	'8f3bec58': [('info', 'v2.2 -> v2.3: Seele HairA Diffuse Hash'),  (upgrade_hash, {'to': 'ebc707dd'})],
	'4122931f': [('info', 'v2.2 -> v2.3: Seele HairA LightMap Hash'), (upgrade_hash, {'to': 'da303c25'})],
 
	'ef4ec36c': [('info', 'v2.2 -> v2.3: Seele HeadA Diffuse Hash'),  (upgrade_hash, {'to': '75263a6e'})],
	
 	'fe54239f': [('info', 'v2.2 -> v2.3: Seele Body Texcoord Hash'),  (upgrade_hash, {'to': '17cba38d'})],

	'8daeb19c': [('info', 'v2.2 -> v2.3: Seele BodyA Diffuse Hash'),  (upgrade_hash, {'to': '600c3a12'})],
	'b06965df': [('info', 'v2.2 -> v2.3: Seele BodyA LightMap Hash'), (upgrade_hash, {'to': '14bb544b'})],
	'1747ac60': [('info', 'v2.2 -> v2.3: Seele BodyC Diffuse Hash'),  (upgrade_hash, {'to': '8e550df4'})],
	'32df70e0': [('info', 'v2.2 -> v2.3: Seele BodyC LightMap Hash'), (upgrade_hash, {'to': 'c6db3a14'})],



	# MARK: Serval
	'c71fc0d0': [('info', 'v1.6 -> v2.0: Serval Body Position Extra Hash'), (upgrade_hash, {'to': '1bdfe263'})],
	'35e3d214': [('info', 'v1.6 -> v2.0: Serval Body Texcoord Hash'), 		(upgrade_hash, {'to': '86d77809'})],
	'44885792': [
		('info', 'v1.6 -> v2.0: Serval Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'ServalBody',
			'hash': 'f092876d',
			'trg_indices': [ '0', '13731', '30048', '58380'],
			'src_indices': ['-1',     '0', '30048',    '-1'],
		})
	],
	'383717ed': [
		('info', 'v2.1: Serval Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '1bdfe263'}),
		(check_hash_not_in_ini, {'hash': 'c71fc0d0'}),
		(multiply_section, {
			'titles': ['ServalBodyPosition', 'ServalBodyPosition_Extra'],
			'hashes': ['383717ed', '1bdfe263']
		})
	],

	'59d7157b': [('info', 'v2.2 -> v2.3: Serval HairA Diffuse Hash'),     (upgrade_hash, {'to': '21e4c3cd'})],
	'86144243': [('info', 'v2.2 -> v2.3: Serval HairA LightMap Hash'),    (upgrade_hash, {'to': '79709858'})],
 
	'd00782c7': [('info', 'v2.2 -> v2.3: Serval HeadA Diffuse Hash'),     (upgrade_hash, {'to': 'afd4f008'})],
	
 	'8d159053': [('info', 'v2.2 -> v2.3: Serval BodyB Diffuse Hash'),     (upgrade_hash, {'to': '1bc2fa5f'})],
 	'7e8fa12b': [('info', 'v2.2 -> v2.3: Serval BodyB LightMap Hash'),    (upgrade_hash, {'to': 'a05979e4'})],
 	'6efdb42c': [('info', 'v2.2 -> v2.3: Serval BodyB StockingMap Hash'), (upgrade_hash, {'to': 'c7358fb2'})],
 	'269745d0': [('info', 'v2.2 -> v2.3: Serval BodyC Diffuse Hash'),     (upgrade_hash, {'to': '5be64601'})],
 	'725d36ab': [('info', 'v2.2 -> v2.3: Serval BodyC LightMap Hash'),    (upgrade_hash, {'to': 'c7bd5694'})],


	# MARK: Sparkle
	# SCYLL SAID NOT TO TOUCH HER
	'28788045': [('info', 'v2.0 -> v2.1: Sparkle Body Texcoord Hash'), (upgrade_hash, {'to': 'd51f3972'})],
	'74660eca': [('info', 'v2.0 -> v2.1: Sparkle Body IB Hash'),	   (upgrade_hash, {'to': '68121fd3'})],
	
	'3c22971b': [('info', 'v2.1 -> v2.2: Sparkle BodyA Diffuse Hash'), (upgrade_hash, {'to': 'fac7d488'})],

	'1d7ed602': [('info', 'v2.2 -> v2.3: Sparkle Hair Diffuse Hash'),  (upgrade_hash, {'to': 'a4f91fac'})],
	'07b2e4b7': [('info', 'v2.2 -> v2.3: Sparkle Hair LightMap Hash'), (upgrade_hash, {'to': 'df96b015'})],

	'6594fbb2': [('info', 'v2.2 -> v2.3: Sparkle Head Diffuse Hash'),  (upgrade_hash, {'to': '09733ebc'})],

	'fac7d488': [('info', 'v2.2 -> v2.3: Sparkle Body Diffuse Hash'),  (upgrade_hash, {'to': '17999c91'})],
	'a4974a51': [('info', 'v2.2 -> v2.3: Sparkle Body LightMap Hash'), (upgrade_hash, {'to': 'f806d2e4'})],



	# MARK: SilverWolf
	'429574bd': [('info', 'v1.6 -> v2.0: SilverWolf Body Draw Hash'),	  (upgrade_hash, {'to': '6bb20ea8'})],
	'f162c8dd': [('info', 'v1.6 -> v2.0: SilverWolf Body Position Hash'), (upgrade_hash, {'to': 'd845b2c8'})],
	'2e053525': [('info', 'v1.6 -> v2.0: SilverWolf Body Texcoord Hash'), (upgrade_hash, {'to': 'ab13f8b8'})],
 	'729de5d2': [
		('info', 'v1.6 -> v2.0: SilverWolf Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'SilverWolfBody',
			'hash': 'e8f10ab3',
			'trg_indices': ['0', '63549', '63663'],
			'src_indices': ['0', '64392',    '-1'],
		})
	],
	'd28049f2': [('info', 'v2.2 -> v2.3: SilverWolf Hair Draw Hash'),     (upgrade_hash, {'to': '293abc6c'})],
	'b2d04673': [('info', 'v2.2 -> v2.3: SilverWolf Hair Position Hash'), (upgrade_hash, {'to': '520314e4'})],
	'6f9922fe': [('info', 'v2.2 -> v2.3: SilverWolf Hair Texcoord Hash'), (upgrade_hash, {'to': 'b9254611'})],
	'3608ba80': [('info', 'v2.2 -> v2.3: SilverWolf Hair IB Hash'),       (upgrade_hash, {'to': '91db78c2'})],
	'56893677': [('info', 'v2.2 -> v2.3: SilverWolf Hair Diffuse Hash'),  (upgrade_hash, {'to': '7c7065ae'})],
	'dd608b21': [('info', 'v2.2 -> v2.3: SilverWolf Hair LightMap Hash'), (upgrade_hash, {'to': 'cf2cb5b7'})],
	
	'd99747d7': [('info', 'v2.2 -> v2.3: SilverWolf Head Diffuse Hash'),  (upgrade_hash, {'to': 'a05a9801'})],
 
	'ab13f8b8': [('info', 'v2.2 -> v2.3: SilverWolf Body Texcoord Hash'), (upgrade_hash, {'to': '6c945131'})],
 	'e8f10ab3': [
		('info', 'v2.2 -> v2.3: SilverWolf Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'SilverWolfBody',
			'hash': '891ecaae',
			'trg_indices': ['0', '63429', '63543'],
			'src_indices': ['0', '63549', '63663'],
		})
	],
	'76d6dd31': [('info', 'v2.2 -> v2.3: SilverWolf Body Diffuse Hash'),  (upgrade_hash, {'to': 'b2f97e36'})],
	'84b3170b': [('info', 'v2.2 -> v2.3: SilverWolf Body LightMap Hash'), (upgrade_hash, {'to': '7b1eface'})],



	# MARK: Sushang
	'59a0b558': [('info', 'v1.6 -> v2.0: Sushang Body Texcoord Hash'), (upgrade_hash, {'to': '23dc010c'})],
 	'd765c517': [
		('info', 'v1.6 -> v2.0: Sushang Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'SushangBody',
			'hash': '4b22391b',
			'trg_indices': ['0', '3531', '30774', '44049'],
			'src_indices': ['0',   '-1', '30774',    '-1'],
		})
	],

	'95e614e5': [('info', 'v2.2 -> v2.3: Sushang Hair Diffuse Hash'),   (upgrade_hash, {'to': '636dc89e'})],
	'728565ee': [('info', 'v2.2 -> v2.3: Sushang Hair LightMap Hash'),  (upgrade_hash, {'to': '0e484aa5'})],

	'9d7ea82f': [('info', 'v2.2 -> v2.3: Sushang Head Diffuse Hash'),   (upgrade_hash, {'to': '1897cfee'})],
 
	'e4ccda3f': [('info', 'v2.2 -> v2.3: Sushang BodyA Diffuse Hash'),  (upgrade_hash, {'to': '98507746'})],
	'653b35cd': [('info', 'v2.2 -> v2.3: Sushang BodyA LightMap Hash'), (upgrade_hash, {'to': '3134e1e4'})],
	'4724e9c1': [('info', 'v2.2 -> v2.3: Sushang BodyC Diffuse Hash'),  (upgrade_hash, {'to': '79354f80'})],
	'd2e9d4dc': [('info', 'v2.2 -> v2.3: Sushang BodyC LightMap Hash'), (upgrade_hash, {'to': '1e9893b3'})],

 

	# MARK: Tingyun
	'1870a9cb': [('info', 'v1.4 -> v1.6: Tingyun BodyA LightMap Hash'), (upgrade_hash, {'to': '547497fb'})],
	'6e205d4e': [('info', 'v1.4 -> v1.6: Tingyun BodyB LightMap Hash'), (upgrade_hash, {'to': '73fad5f5'})],
	'9bf82eaa': [('info', 'v1.6 -> v2.0: Tingyun Body Texcoord Hash'),  (upgrade_hash, {'to': 'f83ec867'})],
 	'351d8570': [
		('info', 'v1.6 -> v2.0: Tingyun Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'TingyunBody',
			'hash': 'da59600b',
			'trg_indices': ['0', '10905', '53229', '54588', '59736'],
			'src_indices': ['0', '16053',    '-1',    '-1', '59736'],
		})
	],

	'02a81179': [('info', 'v2.2 -> v2.3: Tingyun Hair Diffuse Hash'),   (upgrade_hash, {'to': 'c4be701a'})],
	'fa9143b8': [('info', 'v2.2 -> v2.3: Tingyun Hair LightMap Hash'),  (upgrade_hash, {'to': 'f699e83b'})],

	'bdfd3d71': [('info', 'v2.2 -> v2.3: Tingyun Head Diffuse Hash'),   (upgrade_hash, {'to': 'fb95c111'})],
 
	'77ddf35c': [('info', 'v2.2 -> v2.3: Tingyun BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'ed473e73'})],
	'547497fb': [('info', 'v2.2 -> v2.3: Tingyun BodyA LightMap Hash'), (upgrade_hash, {'to': 'e0fa7d8e'})],
	'1cbf0500': [('info', 'v2.2 -> v2.3: Tingyun BodyC Diffuse Hash'),  (upgrade_hash, {'to': 'bf7501ab'})],
	'73fad5f5': [('info', 'v2.2 -> v2.3: Tingyun BodyC LightMap Hash'), (upgrade_hash, {'to': 'fa54a59b'})],



	# MARK: Topaz
	'6f354853': [('info', 'v1.6 -> v2.0: Topaz Body Position Extra Hash'), (upgrade_hash, {'to': '71d39d95'})],
	'24212bf6': [('info', 'v1.6 -> v2.0: Topaz Body Texcoord Hash'), 	   (upgrade_hash, {'to': '436288c9'})],
 	'ae42518c': [
		('info', 'v1.6 -> v2.0: Topaz Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'TopazBody',
			'hash': 'b52297bf',
			'trg_indices': ['0', '18327', '21645', '45078'],
			'src_indices': ['0',    '-1', '21645',    '-1'],
		})
	],
	'2eab6d2d': [
		('info', 'v2.1: Topaz Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '71d39d95'}),
		(check_hash_not_in_ini, {'hash': '6f354853'}),
		(multiply_section, {
			'titles': ['TopazBodyPosition', 'TopazBodyPosition_Extra'],
			'hashes': ['2eab6d2d', '71d39d95']
		})
	],

	'0dd40a0b': [('info', 'v2.2 -> v2.3: Topaz Hair Draw Hash'),      (upgrade_hash, {'to': 'cc870789'})],
	'7fac28de': [('info', 'v2.2 -> v2.3: Topaz Hair Position Hash'),  (upgrade_hash, {'to': 'a413be23'})],
	'b8ec605d': [('info', 'v2.2 -> v2.3: Topaz Hair Texcoord Hash'),  (upgrade_hash, {'to': 'b131f866'})],
	'f1a4401b': [('info', 'v2.2 -> v2.3: Topaz Hair IB Hash'),        (upgrade_hash, {'to': '32ef4b75'})],
	'943bf9d3': [('info', 'v2.2 -> v2.3: Topaz Hair Diffuse Hash'),   (upgrade_hash, {'to': '78059f75'})],
	'67df29ec': [('info', 'v2.2 -> v2.3: Topaz Hair LightMap Hash'),  (upgrade_hash, {'to': '39fd4ba7'})],
 
	'fea9fff4': [('info', 'v2.2 -> v2.3: Topaz Head Diffuse Hash'),   (upgrade_hash, {'to': 'fc521095'})],
 
 	'436288c9': [('info', 'v2.2 -> v2.3: Topaz Body Texcoord Hash'),  (upgrade_hash, {'to': '4be08333'})],
 	'96f5e350': [('info', 'v2.2 -> v2.3: Topaz BodyA Diffuse Hash'),  (upgrade_hash, {'to': '3dfd62b8'})],
	'6a0ee180': [('info', 'v2.2 -> v2.3: Topaz BodyA LightMap Hash'), (upgrade_hash, {'to': 'b8c954ef'})],
 	'68b887db': [('info', 'v2.2 -> v2.3: Topaz BodyC Diffuse Hash'),  (upgrade_hash, {'to': '13be2437'})],
	'924edd3e': [('info', 'v2.2 -> v2.3: Topaz BodyC LightMap Hash'), (upgrade_hash, {'to': '786f6565'})],



	# MARK: Welt
	'cb4839db': [('info', 'v1.6 -> v2.0: Welt HairA LightMap Hash'), (upgrade_hash, {'to': '2258cc03'})],
	'fef626ce': [('info', 'v1.6 -> v2.0: Welt Body Position Hash'),  (upgrade_hash, {'to': '31c9604b'})],
	'723e0365': [
		('info', 'v1.6 -> v2.0: Welt Body Texcoord Hash + Buffer add Texcoord1'),
		(modify_buffer, {
			'operation': 'add_texcoord1',
			'payload': {
				'format': '<BBBBee',
				'value': 'copy'
			}
		}),
		(upgrade_hash, {'to': '0ab3a636'})
	],
 	'374ac8a9': [
		('info', 'v1.6 -> v2.0: Welt Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'WeltBody',
			'hash': 'd15987b1',
			'trg_indices': ['0', '30588', '46620'],
			'src_indices': ['0', '30588',    '-1'],
		})
	],
	'1dea5b29': [('info', 'v2.0 -> v2.1: Welt Body Draw Hash'),  	 (upgrade_hash, {'to': 'ce076065'})],
	'31c9604b': [('info', 'v2.0 -> v2.1: Welt Body Position Hash'),  (upgrade_hash, {'to': '7df0dc05'})],
	'0ab3a636': [
		('info', 'v2.0 -> v2.1: Welt Body Texcoord Hash Upgrade + Buffer pad'),
		(modify_buffer, {
			'operation': 'convert_format',
			'payload': {
				'format_conversion': ('<BBBBeeee', '<BBBBffff')
			}
		}),
		(upgrade_hash, {'to': '381a994e'})
	],
	'd15987b1': [
		('info', 'v2.0 -> v2.1: Welt Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'WeltBody',
			'hash': 'e9f71838',
			'trg_indices': ['0', '30588', '48087'],
			'src_indices': ['0', '30588', '46620'],
		})
	],
	'7df0dc05': [
		('info', 'v2.1: Welt Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '5c4ca7f9'}),
		(multiply_section, {
			'titles': ['WeltBodyPosition', 'WeltBodyPosition_Extra'],
			'hashes': ['7df0dc05', '5c4ca7f9']
		})
	],

	'78ca8241': [('info', 'v2.2 -> v2.3: Welt Hair Texcoord Hash'),        (upgrade_hash, {'to': '8d2fdd4b'})],
	'6a8dcc20': [('info', 'v2.2 -> v2.3: Welt Hair Diffuse Hash'),         (upgrade_hash, {'to': '9dd3ae5d'})],
	'2258cc03': [('info', 'v2.2 -> v2.3: Welt Hair LightMap Hash'),        (upgrade_hash, {'to': 'c6f7c43c'})],
 
	'58db3a4d': [('info', 'v2.2 -> v2.3: Welt Head Diffuse Hash'),         (upgrade_hash, {'to': 'b4d6d5df'})],
 
	'c89a97aa': [('info', 'v2.2 -> v2.3: Welt BodyA Diffuse Hash'),        (upgrade_hash, {'to': 'd318fc3e'})],
	'b63f51eb': [('info', 'v2.2 -> v2.3: Welt BodyA LightMap Hash'),       (upgrade_hash, {'to': '8cd33bbc'})],
 	'5c9711f2': [('info', 'v2.2 -> v2.3: Welt BodyB Diffuse Hash'),        (upgrade_hash, {'to': '948e03bd'})],
	'3dbb2ae6': [('info', 'v2.2 -> v2.3: Welt BodyB LightMap Hash'),       (upgrade_hash, {'to': 'd77a2807'})],



	# MARK: Xueyi
	'77b78d33': [('info', 'v1.6 -> v2.0: Xueyi Body Position Extra Hash'), (upgrade_hash, {'to': '8936451b'})],
	'2c096545': [('info', 'v1.6 -> v2.0: Xueyi Body Texcoord Hash'), 	   (upgrade_hash, {'to': '03ff3d10'})],
	'9f040cd3': [
		('info', 'v1.6 -> v2.0: Xueyi Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'XueyiBody',
			'hash': 'af2983dd',
			'trg_indices': ['0', '31986', '39129', '54279'],
			'src_indices': ['0',    '-1', '39129',    '-1'],
		})
	],
	'206b86f0': [
		('info', 'v2.1: Xueyi Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '8936451b'}),
		(check_hash_not_in_ini, {'hash': '77b78d33'}),
		(multiply_section, {
			'titles': ['XueyiBodyPosition', 'XueyiBodyPosition_Extra'],
			'hashes': ['206b86f0', '8936451b']
		})
	],

	'952c20b8': [('info', 'v2.2 -> v2.3: Xueyi Hair Diffuse Hash'),   (upgrade_hash, {'to': '360ebd7f'})],
	'dbb181aa': [('info', 'v2.2 -> v2.3: Xueyi Hair LightMap Hash'),  (upgrade_hash, {'to': '4d5812b5'})],

	'3c0e2e71': [('info', 'v2.2 -> v2.3: Xueyi Head Diffuse Hash'),   (upgrade_hash, {'to': 'f927a99b'})],

	'ad22f871': [('info', 'v2.2 -> v2.3: Xueyi BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'e2284397'})],
	'2e328427': [('info', 'v2.2 -> v2.3: Xueyi BodyA LightMap Hash'), (upgrade_hash, {'to': 'a694c7ef'})],
	'957cf6d9': [('info', 'v2.2 -> v2.3: Xueyi BodyC Diffuse Hash'),  (upgrade_hash, {'to': '89724253'})],
	'76f171f5': [('info', 'v2.2 -> v2.3: Xueyi BodyC LightMap Hash'), (upgrade_hash, {'to': '91c7faef'})],



	# MARK: Yanqing
	'ef7a4f40': [('info', 'v1.6 -> v2.0: Yanqing Body Position Extra Hash'), (upgrade_hash, {'to': 'a09059a0'})],
	'6fc50cb8': [('info', 'v1.6 -> v2.0: Yanqing Texcoord Hash'),			 (upgrade_hash, {'to': '9801327a'})],
	'a3fe2b8f': [('info', 'v1.6 -> v2.0: Yanqing BodyA Diffuse Hash'), 		 (upgrade_hash, {'to': '4e8f9778'})],
	'e7e004ca': [('info', 'v1.6 -> v2.0: Yanqing BodyA LightMap Hash'), 	 (upgrade_hash, {'to': '035f0719'})],
	'c20cd648': [
		('info', 'v1.6 -> v2.0: Yanqing Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'YanqingBody',
			'hash': 'd03803e6',
			'trg_indices': ['0', '55983'],
			'src_indices': ['0',    '-1'],
		})
	],
	'5c21b25d': [
		('info', 'v2.1: Yanqing Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': 'a09059a0'}),
		(check_hash_not_in_ini, {'hash': 'ef7a4f40'}),
		(multiply_section, {
			'titles': ['YanqingBodyPosition', 'YanqingBodyPosition_Extra'],
			'hashes': ['5c21b25d', 'a09059a0']
		})
	],

	'ea81180d': [('info', 'v2.2 -> v2.3: Yanqing Hair Texcoord Hash'),  (upgrade_hash, {'to': 'e5457b98'})],
	'14629990': [('info', 'v2.2 -> v2.3: Yanqing Hair Diffuse Hash'),   (upgrade_hash, {'to': '541ba63d'})],
	'0519a715': [('info', 'v2.2 -> v2.3: Yanqing Hair LightMap Hash'),  (upgrade_hash, {'to': '9639c2cb'})],

	'af6f0aa8': [('info', 'v2.2 -> v2.3: Yanqing Head Diffuse Hash'),   (upgrade_hash, {'to': '80763bb9'})],

	'4e8f9778': [('info', 'v2.2 -> v2.3: Yanqing BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'a41345d3'})],
	'035f0719': [('info', 'v2.2 -> v2.3: Yanqing BodyA LightMap Hash'), (upgrade_hash, {'to': '2db9f1d6'})],

	'5b021ee9': [('info', 'v2.3 -> v2.4: Yanqing Hair Draw Hash'),      (upgrade_hash, {'to': '1534d13e'})],
	'e5457b98': [('info', 'v2.3 -> v2.4: Yanqing Hair Texcoord Hash'),  (upgrade_hash, {'to': '3ef427fd'})],
	'e0d7d970': [('info', 'v2.3 -> v2.4: Yanqing Hair Position Hash'),  (upgrade_hash, {'to': 'a2ee2b45'})],

	'994d55ab': [('info', 'v2.3 -> v2.4: Yanqing Head Position Hash'),  (upgrade_hash, {'to': '5bc1537b'})],
	'ed7ceec2': [('info', 'v2.3 -> v2.4: Yanqing Head Draw Hash'),      (upgrade_hash, {'to': '04782d92'})],
	'738ba58f': [('info', 'v2.3 -> v2.4: Yanqing Head Texcoord Hash'),  (upgrade_hash, {'to': '6d99c7e0'})],
	'6ae41f8f': [('info', 'v2.3 -> v2.4: Yanqing Head IB Hash'),        (upgrade_hash, {'to': '9e0449af'})],



	# MARK: Yukong
	'896a066e': [('info', 'v1.4 -> v1.6: Yukong BodyA LightMap Hash'),  (upgrade_hash, {'to': '052766cf'})],
	'1d185915': [('info', 'v1.6 -> v2.0: Yukong Body Texcoord Hash'),   (upgrade_hash, {'to': 'e5e376b8'})],
	'1df9540b': [
		('info', 'v1.6 -> v2.0: Yukong Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'YukongBody',
			'hash': '28bbd4ae',
			'trg_indices': ['0', '55551', '60498'],
			'src_indices': ['0',    '-1', '60498'],
		})
	],

	'08d184a7': [('info', 'v2.2 -> v2.3: Yukong Hair Diffuse Hash'),   (upgrade_hash, {'to': '6fa27e76'})],
	'11960703': [('info', 'v2.2 -> v2.3: Yukong Hair LightMap Hash'),  (upgrade_hash, {'to': '40baf876'})],

	'b111f58e': [('info', 'v2.2 -> v2.3: Yukong Head Diffuse Hash'),   (upgrade_hash, {'to': 'bbaa4fba'})],

	'b6457bdb': [('info', 'v2.2 -> v2.3: Yukong BodyA Diffuse Hash'),  (upgrade_hash, {'to': '9e0f6958'})],
	'052766cf': [('info', 'v2.2 -> v2.3: Yukong BodyA LightMap Hash'), (upgrade_hash, {'to': '220a5367'})],
 

	# MARK: Yunli
	'afb1f48c': [
		('info', 'v2.4: Yunli Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '8d5695b1'}),
		(multiply_section, {
			'titles': ['YunliBodyPosition', 'YunliBodyPosition_Extra'],
			'hashes': ['afb1f48c', '8d5695b1']
		})
	],


	# MARK: Caelus
	'0bbb3448': [
		('info', 'v1.5 -> v1.6: Body Texcoord Hash (Caelus)'),
		# certain mod kept outdated hash sections active with the uptodate hash sections
		# don't upgrade the hash if so
		(check_hash_not_in_ini, {'hash': '97c34928'}),
		(check_hash_not_in_ini, {'hash': '44da446d'}),
		(multiply_section, {
			'titles': ['CaelusBodyTexcoord_Destruction', 'CaelusBodyTexcoord_Preservation'],
			'hashes': ['97c34928', '44da446d']
		})
	],
	'97c34928': [
		('info', 'v2.2: Body Texcoord Hash (Destruction Caelus)'),
		(check_hash_not_in_ini, {'hash': '44da446d'}),
		(multiply_section, {
			'titles': ['CaelusBodyTexcoord_Destruction', 'CaelusBodyTexcoord_Preservation'],
			'hashes': ['97c34928', '44da446d']
		})
	],
	'44da446d': [
		('info', 'v2.2: Body Texcoord Hash (Preservation Caelus)'),
		(check_hash_not_in_ini, {'hash': '77933d6e'}),
		(multiply_section, {
			'titles': ['CaelusBodyTexcoord_Preservation', 'CaelusBodyTexcoord_Harmony'],
			'hashes': ['44da446d', '77933d6e']
		})
	],
	'77933d6e': [
		('info', 'v2.2: Body Texcoord Hash (Harmony Caelus)'),
		(check_hash_not_in_ini, {'hash': '97c34928'}),
		(multiply_section, {
			'titles': ['CaelusBodyTexcoord_Harmony', 'CaelusBodyTexcoord_Destruction'],
			'hashes': ['77933d6e', '97c34928']
		})
	],

	'fd65164c': [
		('info', 'v1.5 -> v1.6: Body IB Hash (Caelus)'),
		# see above comment :teriderp:
		(check_hash_not_in_ini, {'hash': 'e3ffef9a'}),
		(check_hash_not_in_ini, {'hash': 'a270e292'}),
		(remove_indexed_sections, {'capture_content': '🍰', 'capture_position': '🌲'}),
		(create_new_section, {
			'at_position': '🌲',
			'capture_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Destruction]
				hash = e3ffef9a
				🍰

				[TextureOverrideCaelusBodyA_Destruction]
				hash = e3ffef9a
				match_first_index = 0
				ib = null

				[TextureOverrideCaelusBodyB_Destruction]
				hash = e3ffef9a
				match_first_index = 38178
				🤍0🤍

			'''
		}),
		(create_new_section, {
			'at_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Preservation]
				hash = a270e292
				🍰

				[TextureOverrideCaelusBodyA_Preservation]
				hash = a270e292
				match_first_index = 0
				ib = null

				[TextureOverrideCaelusBodyB_Preservation]
				hash = a270e292
				match_first_index = 37674
				🤍0🤍
			'''
		}),
		(try_upgrade, {'e3ffef9a', 'a270e292'}),
	],

	# From Destruction hash: Add Preservation Path hashes if its missing
	'e3ffef9a': [
		('info', 'v2.2: Body IB Hash (Caelus Destruction)'),
		(check_hash_not_in_ini, {'hash': 'a270e292'}),
		(remove_indexed_sections, {'capture_content': '🍰', 'capture_position': '🌲'}),
		(create_new_section, {
			'at_position': '🌲',
			'capture_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Destruction]
				hash = e3ffef9a
				🍰

				[TextureOverrideCaelusBodyA_Destruction]
				hash = e3ffef9a
				match_first_index = 0
				🤍0🤍

				[TextureOverrideCaelusBodyB_Destruction]
				hash = e3ffef9a
				match_first_index = 38178
				🤍38178🤍

			'''
		}),
		(create_new_section, {
			'at_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Preservation]
				hash = a270e292
				🍰

				[TextureOverrideCaelusBodyA_Preservation]
				hash = a270e292
				match_first_index = 0
				🤍0🤍

				[TextureOverrideCaelusBodyB_Preservation]
				hash = a270e292
				match_first_index = 37674
				🤍38178🤍
			'''
		}),
		(try_upgrade, {'a270e292'}),
	],

	# From Preservation hash: Add Harmony Path hashes if its missing
	'a270e292': [
		('info', 'v2.2: Body IB Hash (Caelus Preservation)'),
		(check_hash_not_in_ini, {'hash': '89fcb592'}),
		(remove_indexed_sections, {'capture_content': '🍰', 'capture_position': '🌲'}),
		(create_new_section, {
			'at_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Preservation]
				hash = a270e292
				🍰

				[TextureOverrideCaelusBodyA_Preservation]
				hash = a270e292
				match_first_index = 0
				🤍0🤍

				[TextureOverrideCaelusBodyB_Preservation]
				hash = a270e292
				match_first_index = 37674
				🤍37674🤍

			'''
		}),
		(create_new_section, {
			'at_position': '🌲',
			'capture_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Harmony]
				hash = 89fcb592
				🍰

				[TextureOverrideCaelusBodyA_Harmony]
				hash = 89fcb592
				match_first_index = 0
				🤍0🤍

				[TextureOverrideCaelusBodyB_Harmony]
				hash = 89fcb592
				match_first_index = 39330
				🤍37674🤍
			'''
		}),
		(try_upgrade, {'89fcb592'}),
	],

	# From Harmony hash: Add Destruction Path hashes if its missing
	'89fcb592': [
		('info', 'v2.2: Body IB Hash (Caelus Preservation)'),
		(check_hash_not_in_ini, {'hash': 'e3ffef9a'}),
		(remove_indexed_sections, {'capture_content': '🍰', 'capture_position': '🌲'}),
		(create_new_section, {
			'at_position': '🌲',
			'capture_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Harmony]
				hash = 89fcb592
				🍰

				[TextureOverrideCaelusBodyA_Harmony]
				hash = 89fcb592
				match_first_index = 0
				🤍0🤍

				[TextureOverrideCaelusBodyB_Harmony]
				hash = 89fcb592
				match_first_index = 39330
				🤍39330🤍

			'''
		}),
		(create_new_section, {
			'at_position': '🌲',
			'content': '''
				[TextureOverrideCaelusBodyIB_Destruction]
				hash = e3ffef9a
				🍰

				[TextureOverrideCaelusBodyA_Destruction]
				hash = e3ffef9a
				match_first_index = 0
				🤍0🤍

				[TextureOverrideCaelusBodyB_Destruction]
				hash = e3ffef9a
				match_first_index = 38178
				🤍39330🤍
			'''
		}),
		(try_upgrade, {'e3ffef9a'}),
	],

	'3fc38f8a': [('info', 'v2.2 -> v2.3: Caelus Hair Texcoord Hash'), (upgrade_hash, {'to': 'f4f5c11d'})],
	'7de7f0c0': [('info', 'v2.2 -> v2.3: Caelus Hair Diffuse Hash'),  (upgrade_hash, {'to': 'fa0975b2'})],
	'c17e8830': [('info', 'v2.2 -> v2.3: Caelus Hair LightMap Hash'), (upgrade_hash, {'to': 'd75c3881'})],

	'd667a346': [
		('info', 'v2.3: Caelus Add Head Position Harmony Hash'),
		(check_hash_not_in_ini, {'hash': '7409246c'}),
		(multiply_section, {
			'titles': ['CaelusHeadPosition_DestrPreserv', 'CaelusHeadPosition_Harmony'],
			'hashes': ['d667a346', '7409246c']
		})
	],
	'7409246c': [
		('info', 'v2.3: Caelus Add Head Position DestrPreserv Hash'),
		(check_hash_not_in_ini, {'hash': 'd667a346'}),
		(multiply_section, {
			'titles': ['CaelusHeadPosition_Harmony', 'CaelusHeadPosition_DestrPreserv'],
			'hashes': ['7409246c', 'd667a346']
		})
	],
	'b193e6d8': [('info', 'v2.2 -> v2.3: Caelus Head Diffuse Hash'),  (upgrade_hash, {'to': '21b96557'})],


	'28d09106': [('info', 'v2.2 -> v2.3: Caelus Body Diffuse Hash'),  (upgrade_hash, {'to': '3e8e34d5'})],
	'0fe66c92': [('info', 'v2.2 -> v2.3: Caelus Body LightMap Hash'), (upgrade_hash, {'to': '6194fa1b'})],



	# MARK: Stelle
	# 	Skip adding extra sections for v1.6, v2.0, v2.1 Preservation hashes
	# 	because those extra sections are not needed in v2.2
	# 	Comment out the extra sections later
	'01df48a6': [('info', 'v1.5 -> v1.6: Body Texcoord Hash (Stelle)'), (upgrade_hash, {'to': 'a68ffeb1'})],
	'a68ffeb1': [
		('info', 'v2.1 -> v2.2: Body Texcoord Hash (Destruction Stelle)'),
		(upgrade_hash, {'to': 'f00b6ded'})
	],

	'85ad43b3': [
		('info', 'v1.5 -> v1.6: Body IB Hash (Stelle)'),
		(multiply_indexed_section, {
			'title': 'StelleBody',
			'hash': '174a08d4',
			'trg_indices': [ '0', '32967'],
			'src_indices': ['-1',     '0'],
		})
	],
	'174a08d4': [
		('info', 'v2.1 -> v2.2: Body IB Hash (Destruction Stelle)'),
		(multiply_indexed_section, {
			'title': 'StelleBody',
			'hash': 'fba309df',
			'trg_indices': ['0', '32946'],
			'src_indices': ['0', '32967'],
		})
	],

	'1a415a73': [('info', 'v2.1 -> v2.2: Stelle Hair Draw Hash'),	  (upgrade_hash, {'to': '00d0c31d'})],
	'938b9c8f': [('info', 'v2.1 -> v2.2: Stelle Hair Position Hash'), (upgrade_hash, {'to': '8c0c078f'})],
	'8680469b': [('info', 'v2.1 -> v2.2: Stelle Hair Texcoord Hash'), (upgrade_hash, {'to': 'fe9eaef0'})],
	'2d9adf2d': [('info', 'v2.1 -> v2.2: Stelle Hair IB Hash'), 	  (upgrade_hash, {'to': '1d62eafb'})],

	'fdb54553': [('info', 'v2.2 -> v2.3: Stelle Hair Diffuse Hash'),  (upgrade_hash, {'to': 'a04fcf6f'})],
	'ef5586c1': [('info', 'v2.2 -> v2.3: Stelle Hair LightMap Hash'), (upgrade_hash, {'to': '02a9b085'})],

	'1c0a8ff8': [('info', 'v2.2 -> v2.3: Stelle Head Diffuse Hash'),  (upgrade_hash, {'to': '4e98df53'})],

	'a19a8d2c': [('info', 'v2.2 -> v2.3: Stelle Body Diffuse Hash'),  (upgrade_hash, {'to': '78d10c03'})],
	'5d15eefe': [('info', 'v2.2 -> v2.3: Stelle Body LightMap Hash'), (upgrade_hash, {'to': '69014337'})],


	# Comment out the sections with hashes no longer used in v2.2
	'2dcd5dc0': [('info', 'v2.1: Comment Body Texcoord Hash (Preservation Stelle)'), (comment_sections, {})],
	'e0d86dc8': [('info', 'v2.1: Comment Body IB Hash (Preservation Stelle)'),		 (comment_sections, {})],

	

	# MARK: Other Entity Fixes





	# MARK: Svarog
	'ae587fb2': [('info', 'v2.2 -> v2.3: Svarog BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'ae37a552'})],
	'a3acad6f': [('info', 'v2.2 -> v2.3: Svarog BodyA LightMap Hash'), (upgrade_hash, {'to': 'd653a999'})],
	'10beb640': [('info', 'v2.2 -> v2.3: Svarog BodyA Diffuse Hash'),  (upgrade_hash, {'to': 'e3a7f3fd'})],
	'69840f72': [('info', 'v2.2 -> v2.3: Svarog BodyA LightMap Hash'), (upgrade_hash, {'to': '4090cc01'})],



	# MARK: Numby
	'85d1b3ce': [('info', 'v2.2 -> v2.3: Numby Body DiffuseChScreen Hash'),        (upgrade_hash, {'to': 'e22b4c5e'})],
	'dab1477d': [('info', 'v2.2 -> v2.3: Numby Body DiffuseOverworldCombat Hash'), (upgrade_hash, {'to': '6cad0819'})],
	'a313ad5f': [('info', 'v2.2 -> v2.3: Numby Body LightMapChScreen Hash'),       (upgrade_hash, {'to': '07471bf5'})],
	'807fb688': [('info', 'v2.2 -> v2.3: Numby Body LightMapOverworld Hash'),      (upgrade_hash, {'to': '02644fcc'})],
	'ef40ac05': [('info', 'v2.2 -> v2.3: Numby Body LightMapCombat Hash'),         (upgrade_hash, {'to': 'cd7acd1a'})],

	'9afaa7d9': [
		('info', 'v2.1: Numby Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '394111ad'}),
		(multiply_section, {
			'titles': ['NumbyBodyPosition', 'NumbyBodyPosition_Extra'],
			'hashes': ['9afaa7d9', '394111ad']
		})
	],


	# MARK: Weapons


	'7ae27f17': [('info', 'v2.2 -> v2.3: Jingliu Sword Diffuse Hash'),  (upgrade_hash, {'to': 'b71e3abe'})],
	'6acc5dd1': [('info', 'v2.2 -> v2.3: Jingliu Sword LightMap Hash'), (upgrade_hash, {'to': '12fde9bd'})],


	'52e8727a': [('info', 'v2.2 -> v2.3: March7th Bow Diffuse Hash'),  (upgrade_hash, {'to': '91804076'})],
	'f47e4ed8': [('info', 'v2.2 -> v2.3: March7th Bow LightMap Hash'), (upgrade_hash, {'to': 'e91ab48f'})],


	'c69a4a5f': [('info', 'v2.2 -> v2.3: Trailblazer Bat Diffuse Hash'),     (upgrade_hash, {'to': 'cac102b9'})],
	'bc86078f': [('info', 'v2.2 -> v2.3: Trailblazer Bat Diffuse Ult Hash'), (upgrade_hash, {'to': '4a638b94'})],
	'c7969478': [('info', 'v2.2 -> v2.3: Trailblazer Bat LightMap Hash'),    (upgrade_hash, {'to': 'ff6df1ec'})],

	'0a27a48e': [('info', 'v2.2 -> v2.3: Trailblazer Spear Diffuse Hash'),   (upgrade_hash, {'to': '4cd9ab1d'})],
	'7ce10d72': [('info', 'v2.2 -> v2.3: Trailblazer Spear LightMap Hash'),  (upgrade_hash, {'to': 'bdae2ad0'})],

	'685495d0': [('info', 'v2.2 -> v2.3: Seele Scythe Diffuse Hash'),        (upgrade_hash, {'to': 'ce802067'})],
	'910e8419': [('info', 'v2.2 -> v2.3: Seele Scythe LightMap Hash'),       (upgrade_hash, {'to': 'cb875574'})],

}

# MARK: RUN
if __name__ == '__main__':
	try: main()
	except Exception as x:
		print('\nError Occurred: {}\n'.format(x))
		print(traceback.format_exc())
	finally:
		input('\nPress "Enter" to quit...\n')
