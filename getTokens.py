def getTokens(input):
	removeSlash = str(input).split('/')	#get tokens after splitting by slash
	allTokens = []
	for i in removeSlash:
		tokens = str(i).split('-')	#get tokens after splitting by dash
		removeDot = []
		for j in range(0,len(tokens)):
			tempTokens = str(tokens[j]).split('.')	#get tokens after splitting by dot
			removeDot = removeDot + tempTokens
		allTokens = allTokens + tokens + removeDot
	allTokens = list(set(allTokens))	#remove redundant tokens
	if 'com' in allTokens:
		allTokens.remove('com')	#removing .com since it occurs a lot of times and it should not be included in our features
	return allTokens