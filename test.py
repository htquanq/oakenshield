rules = [lines.rstrip("\r\n") for lines in open("/data/capstone1/oakenshield/rules.txt")]

for rule in rules:
	print rule