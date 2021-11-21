
#
# Lets describe the rules for port, e.g: 31132 
#

MAIN 			-> PORT

PORT			->	[1-9]					# 1..9
				| [1-9] [0-9]				# 10..99
				| [1-9] [0-9] [0-9]			# 100..999
				| [1-9] [0-9] [0-9] [0-9]		# 1000..9999
				| [1-5] [0-9] [0-9] [0-9] [0-9]		# 10000..59999
				| "6" [0-4] [0-9] [0-9] [0-9]		# 60000..64999
				| "6" "5" [0-4] [0-9] [0-9]		# 65000..65499
				| "6" "5" "5" [0-2] [0-9]		# 65500..65529
				| "6" "5" "5" "3" [0-5]			# 65530..65535
					