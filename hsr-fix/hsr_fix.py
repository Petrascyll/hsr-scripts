# Written by petrascyll
# 	thanks to sora_ for help collecting the vertex explosion extra position hashes
# 	and AGMG discord and everone there for being helpful
# 
# HSR Version 2.2 Fix
# 	- Updates all outdated HSR character mods from HSRv1.6 up to HSRv2.2
# 	- Edits Caelus mods to work on both Destruction/Preservation paths.
# 	- Adds the extra position hash on the mods that need it.
# 	- Applies Yanqing Boss fix on the mods that need it.
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
		prog="HSR Fix v2.2",
		description=(
			"- Updates all outdated HSR character mods from HSRv1.6 up to HSRv2.2.\n"
			"- Edits Caelus mods to work on both Destruction/Preservation paths.\n"
			"- Adds the extra position hash on the mods that need it.\n"
			"- Applies Yanqing Boss fix on the mods that need it.\n"
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
		if filename.upper().startswith('DISABLED') or 'DESKTOP' in filename.upper():
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

	prev_j = 0
	section_matches = pattern.finditer(ini_content + '\n[')
	for section_match in section_matches:
		if 'match_first_index' not in section_match.group(1):
			if capture_content:
				jail[capture_content] = get_critical_content(section_match.group(1))[0]
		else:
			critical_content, _, match_first_index = get_critical_content(section_match.group(1))
			placeholder = '🤍{}🤍'.format(match_first_index)
			jail[placeholder] = critical_content

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
def create_new_section(ini_content, hash, jail, *, at_position=-1, capture_position=None, content):
	# Relatively slow but it doesn't matter
	if content[0] == '\n': content = content[1:]
	content = content.replace('\t', '')
	for placeholder, value in jail.items():
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
	content = f'''
		[TextureOverride{title}IB]
		hash = {hash}
		🍰

	'''

	alpha = [
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
		'U', 'V', 'W', 'X', 'Y', 'Z'
	]
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
		(try_upgrade, {hash})
	]


hash_commands = {
	# MARK: Acheron
	'ca948c6c': [('info', 'v2.1 -> v2.2: Acheron HairA Diffuse Hash'),  (upgrade_hash, {'to': '5ee5cc8d'})],
	'15cacc23': [('info', 'v2.1 -> v2.2: Acheron HairA LightMap Hash'), (upgrade_hash, {'to': 'ba560779'})],
	'214bd15a': [
		('info', 'v2.1: Acheron Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '7ffc98fa'}),
		(multiply_section, {
			'titles': ['AcheronBodyPosition', 'AcheronBodyPosition_Extra'],
			'hashes': ['214bd15a', '7ffc98fa']
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

	# MARK: Blade
	'b95b80ad': [('info', 'v1.5 -> v1.6: Blade BodyA LightMap Hash'), (upgrade_hash, {'to': '459ea4f3'})],
	'0b7675c2': [('info', 'v1.5 -> v1.6: Blade BodyB LightMap Hash'), (upgrade_hash, {'to': 'bdbde74c'})],
	'90237dd2': [('info', 'v1.6 -> v2.0: Blade Head Position Hash'),  (upgrade_hash, {'to': '9bc595ba'})],
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

	# MARK: DanHengIL
	'0ffb8233': [('info', 'v1.6 -> v2.0: DanHengIL Body Texcoord Hash'), (upgrade_hash, {'to': '0f8da6ba'})],
	'1a7ee87c': [
		('info', 'v1.6 -> v2.0: DanHengIL Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'DanHengILBody',
			'hash': '7cb75a5e',
			'trg_indices': ['0', '47133'],
			'src_indices': ['0',    '-1'],
		})
	],

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
			'src_indices': ['0', '52458',    '-1'],
		})
	],

	# MARK: Himeko
	'5d98de11': [('info', 'v1.6 -> v2.0: Himeko Body Position Extra Hash'), (upgrade_hash, {'to': '3cfb3645'})],
	'77cb214c': [('info', 'v1.6 -> v2.0: Himeko Body Texcoord Hash'),       (upgrade_hash, {'to': 'b9e9ae3b'})],
	'e4640c8c': [
		('info', 'v1.6 -> v2.0: Himeko Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'HimekoBody',
			'hash': 'e79e4018',
			'trg_indices': ['0', '27381', '37002', '47634'],
			'src_indices': ['0',    '-1', '37002',    '-1'],
		})
	],
	'4747010d': [
		('info', 'v2.1: Himeko Body Position: Apply Vertex Explosion Fix'),
		(check_hash_not_in_ini, {'hash': '3cfb3645'}),
		(check_hash_not_in_ini, {'hash': '5d98de11'}),
		(multiply_section, {
			'titles': ['HimekoBodyPosition', 'HimekoBodyPosition_Extra'],
			'hashes': ['4747010d', '3cfb3645']
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

	# MARK: Jingliu
	'81c023e7': [('info', 'v1.6 -> v2.0: Jingliu Body Texcoord Hash'), (upgrade_hash, {'to': 'ba517fa0'})],
	'5564183c': [
		('info', 'v1.6 -> v2.0: Jingliu Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'JingliuBody',
			'hash': 'e8d31b6a',
			'trg_indices': ['0', '51096'],
			'src_indices': ['0',    '-1'],
		})
	],

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

	# MARK: Misha
	'0f570849': [('info', 'v2.0 -> v2.1: Misha Head Position Hash'), (upgrade_hash, {'to': 'be8ee647'})],
	'8aa3d867': [('info', 'v2.0 -> v2.1: Misha Head Texcoord Hash'), (upgrade_hash, {'to': 'ee650b42'})],
 




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

	# XMARK: Sampo
	# Nothing

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


	# MARK: Sparkle
	'28788045': [('info', 'v2.0 -> v2.1: Sparkle Body Texcoord Hash'), (upgrade_hash, {'to': 'd51f3972'})],
	'74660eca': [('info', 'v2.0 -> v2.1: Sparkle Body IB Hash'),	   (upgrade_hash, {'to': '68121fd3'})],
	
	'3c22971b': [('info', 'v2.1 -> v2.2: Sparkle BodyA Diffuse Hash'), (upgrade_hash, {'to': 'fac7d488'})],




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

	'9801327a': [
		('info', 'v2.1: Yanqing Body Texcoord - Boss Fix'),
		(check_hash_not_in_ini, {'hash': '188ee3d0'}),
		(multiply_section, {
			'titles': ['YanqingBodyTexcoord', 'YanqingBodyTexcoord_Boss'],
			'hashes': ['9801327a', '188ee3d0']
		})
	],
	'd03803e6': [
		('info', 'v2.1: Yanqing Body IB - Boss Fix'),
		(check_hash_not_in_ini, {'hash': '614a27b5'}),
		(remove_indexed_sections, {'capture_content': '🍰', 'capture_position': '🌲'}),
		(create_new_section, {
			'at_position': '🌲',
			'capture_position': '🌲',
			'content': '''
				[TextureOverrideYanqingBodyIB]
				hash = d03803e6
				🍰

				[TextureOverrideYanqingBodyA]
				hash = d03803e6
				match_first_index = 0
				🤍0🤍

				[TextureOverrideYanqingBodyB]
				hash = d03803e6
				match_first_index = 55983
				🤍55983🤍

				[TextureOverrideYanqingBodyIB_Boss]
				hash = 614a27b5
				🍰

				[TextureOverrideYanqingBodyA_Boss]
				hash = 614a27b5
				match_first_index = 0
				🤍0🤍

				[TextureOverrideYanqingBodyB_Boss]
				hash = 614a27b5
				match_first_index = 58596
				🤍55983🤍
			'''
		}),
	],



	# MARK: Yukong
	'896a066e': [('info', 'v1.4 -> v1.6: Yukong BodyA LightMap Hash'), (upgrade_hash, {'to': '052766cf'})],
	'1d185915': [('info', 'v1.6 -> v2.0: Yukong Body Texcoord Hash'),  (upgrade_hash, {'to': 'e5e376b8'})],
	'1df9540b': [
		('info', 'v1.6 -> v2.0: Yukong Body IB Hash'),
		(multiply_indexed_section, {
			'title': 'YukongBody',
			'hash': '28bbd4ae',
			'trg_indices': ['0', '55551', '60498'],
			'src_indices': ['0',    '-1', '60498'],
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

	# Comment out the sections with hashes no longer used in v2.2
	'2dcd5dc0': [('info', 'v2.1: Comment Body Texcoord Hash (Preservation Stelle)'), (comment_sections, {})],
	'e0d86dc8': [('info', 'v2.1: Comment Body IB Hash (Preservation Stelle)'),		 (comment_sections, {})],
}

# MARK: RUN
if __name__ == '__main__':
	try: main()
	except Exception as x:
		print('\nError Occurred: {}\n'.format(x))
		print(traceback.format_exc())
	finally:
		input('\nPress "Enter" to quit...\n')
