import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--targets", nargs="+", default=[])
args = parser.parse_args(["-t", "target1", "-t", "target2"])
print(args.targets)

args2 = parser.parse_args(["-t", "target1", "target2"])
print(args2.targets)
