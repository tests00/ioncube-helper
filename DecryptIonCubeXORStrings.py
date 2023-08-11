# For decrypting the ionCube strings, and writing the value as a comment.
#@author tests 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

key = bytearray('REMOVED - BUT FIND IT YOURSELF :)')

def process_bytes(address):
	try:
		this_addr = toAddr(address.getAddressableWordOffset())

		length = getByte(this_addr) & 0xff
		encrypted_data = getBytes(toAddr(address.getAddressableWordOffset() + 1), length)

		ctr = 0
		ret = ""

		for char in encrypted_data:
			# char is an int, so need to make it unsigned ffs
			char = char & 0xff
    			offset = (length + ctr) & 0xf
    			ret += chr(char ^ key[offset])
    			ctr += 1
		
		print("\"{}\" at {:x}".format(ret, address.getAddressableWordOffset()))
		
		# Create comment at that address, as a pre-comment
		comment_str = "\"{}\"".format(ret)
		comment = ghidra.app.cmd.comments.SetCommentsCmd(this_addr, comment_str, "", "", "", "")
		comment.applyTo(currentProgram)

	except:
		return
	
dummy = ghidra.util.task.TaskMonitor.DUMMY

di = ghidra.app.decompiler.DecompInterface()
di.openProgram(currentProgram)

decrypt_func = "global_xor_string"
decrypt_func_addr = toAddr(decrypt_func)
refs = getReferencesTo(decrypt_func_addr)

done = []
done_globs = []

for ref in refs:
		address = ref.getFromAddress()
		function = getFunctionContaining(address)

		if (function is not None) and (function not in done):
			res = di.decompileFunction(function, 0, dummy)
			if res.decompileCompleted():
				done.append(res)
				high_func = res.getHighFunction()
				if high_func:
					opiter = high_func.getPcodeOps()
					while opiter.hasNext():
						op = opiter.next()
						mnemonic = str(op.getMnemonic())
						if mnemonic == "CALL":
							inputs = op.getInputs()
							
							addr = inputs[0].getAddress()
							args = inputs[1:]
							
							if addr == decrypt_func_addr:
								source_addr = op.getSeqnum().getTarget()
								
								if (args[0].isUnique()):
									abc = args[0].getDef()
									uniq_inputs = abc.getInputs()
									if len(uniq_inputs) == 2:
										add = uniq_inputs[1].getAddress()
										if (add not in done_globs):
											process_bytes(add)
											done_globs.append(add)
									else:
										print("UNEXPECTED! Call to {} at {} has {} arguments: {}".format(addr, source_addr, len(args), args))
								else:
									print("Call to {} at {} has {} arguments: {}".format(addr, source_addr, len(args), args))

