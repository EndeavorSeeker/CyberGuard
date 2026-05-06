from flask import Flask, render_template, redirect, request
from url_analyse import url_analyse
from img_analyse import img_analyse

app = Flask(__name__)

@app.route('/', methods=["GET", "POST"])
def home():
    if request.method == "GET":
        return render_template('index.html')
    else:
        url = request.form.get("url_input")
        if url_analyse(url):
            return redirect("/safe")
        else:
            return redirect("threat")
@app.route('/safe')
def safe():
    return render_template('safe.html')
@app.route('/threat')
def threat():
    return render_template('threat.html')
@app.route('/img', methods=["GET", "POST"])
def image():
    if request.method == "GET":
        return render_template('image.html')
    else:
        file = request.files.get('file-upload')
        if img_analyse(file):
            return redirect("/safe")
        else:
            return redirect("threat")

if __name__ == '__main__':
    app.run(debug=True)
