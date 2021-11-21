
#
# Lets describe the rules for start state relay, e.g: 0, 1, NO 
#

MAIN 			-> START_STATE

START_STATE		->	[0-1]
				| "NO"
					
