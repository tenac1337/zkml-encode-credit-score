# app.py
from flask import Flask, render_template, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    user_input = {
        "age": float(request.form['age']),
        "income": float(request.form['income']),
        "children": int(request.form['children']),
        "education": request.form['education'],
        "gender": request.form['gender'],
        "marital_status": request.form['marital_status'],
        "home_ownership": request.form['home_ownership']
    }

    response = requests.post('http://localhost:8000/generate-proof', json=user_input)
    if response.status_code == 200:
        result = response.json()
        return render_template('result.html', result=result)
    else:
        return "Error occurred", 500

if __name__ == '__main__':
    app.run(debug=True, port=8080)