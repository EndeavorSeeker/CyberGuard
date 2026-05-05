from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')
@app.route('/safe')
def safe():
    return render_template('safe.html')
@app.route('/threat')
def threat():
    return render_template('threat.html')
@app.route('/img')
def image():
    return render_template('image.html')

if __name__ == '__main__':
    app.run(debug=True)
