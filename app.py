from flask import Flask, jsonify, request
from flask_restplus import Resource, Api, fields
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import random
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.externals import joblib
from patterns import shortening_services

app = Flask(__name__)

api = Api(app, version='1.0', title='Malicious Url Detector API', description="Detects Malicious Urls")

namespace = api.namespace('', description='Main API  Routes')

url_fields = namespace.model("Url", {"url": fields.String })

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

# def TL():
# 	urlsdata = './newdata.csv'	#path to our all urls file
# 	allurlsdata = pd.read_csv(urlsdata)

# 	allurlsdata = np.array(allurlsdata)	#converting it into an array
# 	random.shuffle(allurlsdata)	#shuffling

# 	y = [d[1] for d in allurlsdata]	#all labels 
# 	urls = [d[0] for d in allurlsdata]	#all urls corresponding to a label (either good or bad)
# 	vectorizer = TfidfVectorizer(tokenizer=getTokens)	#get a vector for each url but use our customized tokenizer
# 	X = vectorizer.fit_transform(urls)	#get the X vector

# 	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)	#split into training and testing set 80/20 ratio

# 	lgs = LogisticRegression()	#using logistic regression
# 	lgs.fit(X_train, y_train)
# 	# print(lgs.score(X_test, y_test))	#pring the score. It comes out to be 98%
# 	joblib.dump(lgs, 'model.joblib')
# 	joblib.dump(vectorizer, 'vectorizer.joblib')
# 	return vectorizer, lgs

# # @app.route('/get/<path:path>')
# # def show(path):
# # 	res = getTokens(path)
# # 	return jsonify(res)
# vectorizer, lgs  = TL()


vectorizer = joblib.load("vectorizer.joblib")
lgs = joblib.load("model.joblib")
@namespace.route('/url')
class Url(Resource):
	@namespace.doc(description='detects malicious urls')
	@namespace.expect(url_fields)
	def post(self):
		req = request.get_json()
		path = req['url']
		if re.search(shortening_services, path):
			return {"msg":"normal"}
		if path.startswith("http://"):
			path = "".join(path.split("http://"))
		if path.startswith("https://"):
			path = "".join(path.split("https://"))
		if path.startswith("www."):
			path = "".join(path.split("www."))
		if path.endswith("/"):
			path = path[:-1]
		if path.endswith(".php"):
			path = "".join(path.split(".php"))
		if path.endswith(".htm"):
			path = "".join(path.split(".htm"))
		path = path.split("/")[0]
		X_predict = []
		X_predict.append(str(path))
		X_predict = vectorizer.transform(X_predict)
		y_Predict = lgs.predict(X_predict)
		if y_Predict.tolist()[0] == 1:
			return {"msg":"malicious"}
		else:
			return {"msg":"normal"}
		# return jsonify(y_Predict.tolist())	


if __name__ == "__main__":
	app.run(debug=True)

