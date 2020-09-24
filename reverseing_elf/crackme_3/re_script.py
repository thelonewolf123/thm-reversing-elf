from r2pipe import open

main_addr = None
password = []

r = open('./crackme3.bin',flags=['-d'])
r.cmd('e dbg.profile=profile.rr2')
r.cmd('aaa')
r.cmd('doo')
functions_json = r.cmdj('aflj')

for func in functions_json:
	if func['name'] == 'main':

		main_addr = func['offset']

print(f'Main function base address {hex(main_addr)}')

cmp_addr = main_addr+98

r.cmd(f'db {hex(cmp_addr)}')
r.cmd('dc')

for _ in range(0,3):

	al = r.cmd('dr eax')

	password.append(chr(int(al.rstrip(),16)))

	r.cmd(f'dr dl={al}')
	r.cmd('dc')

print(f'Password : ',"".join(password))