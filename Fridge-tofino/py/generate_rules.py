import argparse
import math

def corr(x,p,M):
	return 1.0/p*math.pow(1-1.0/M,-x)

def inv_corr(cnt,p,M):
	return -math.log(cnt*p)/math.log(1-1.0/M)

def print_rules(REG_SIZE,ENTRY_PROB_LOG2):
	p,M=0.5**ENTRY_PROB_LOG2, REG_SIZE
	print(f'// Auto-generated match-action rules for fridge correction factors, with REG_SIZE={REG_SIZE} and p={p}')
	print(f'''
	#if REG_SIZE != {REG_SIZE}
		#error REG_SIZE mismatch: The lookup table rules are generated using fridge size {REG_SIZE}.
	#endif
	#if ENTRY_PROB_LOG2 != {ENTRY_PROB_LOG2}
		#error ENTRY_PROB_LOG2 mismatch: The lookup table rules are generated using {ENTRY_PROB_LOG2} bits of entropy (entry probability {p}).
	#endif
	''')

	steps=list(sorted(set([
		int(round(1/p* (1.1)**i))-0.5
		for i in range(1000)
	])))
	aname='tally'
	for i in range(len(steps)):
		rleft,rright=inv_corr(steps[i],p,M),inv_corr(steps[i+1],p,M)
		rleft,rright=int(rleft),int(rright)
		if i==0:rleft=0
		xout=int(0.5*(steps[i]+steps[i+1]))
		if xout>2**24: break
		print(f'({rleft}..{rright}): {aname}({xout});')


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('REG_SIZE', type=int, choices=[2**i for i in range(2,17)],
					help='The number of entries in the fridge. Please use power-of-2.')
	parser.add_argument('ENTRY_PROB_LOG2', type=int, choices=range(20),
					help='The inverse of fridge entry probability, written under base-2 logarithm.')
	args = parser.parse_args()

	print_rules(args.REG_SIZE,args.ENTRY_PROB_LOG2)