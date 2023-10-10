from flask import Flask, render_template, redirect, url_for, request
from scan import *


##change

username = "sreerag"
passwd = "1234"

##change


app = Flask(__name__)

@app.route('/')
def index():
    return redirect(url_for("login"))



@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method=="POST":
        uname = request.form["username"]
        password = request.form["pswrd"]
        if (username == uname) and (passwd == password):
            return redirect(url_for("scan"))
        else:
            return render_template("login.html")
    else:
        return render_template("login.html")
    


@app.route('/scan', methods=["POST", "GET"])
def scan():
    if request.method == "POST":
        hostname = request.form["host"]
        
        # print(hostname)
        open_ports, whoisinfo = scanPorts(hostname)
        # print(open_ports)
        
        return render_template("result.html", portsh=open_ports, whoisinfo1=whoisinfo, hostname1=hostname)
    else:
        return render_template("scan.html")
    

# @app.route('/result')
# def result(ports):
#     return render_template("result.html", portsh=ports)


if __name__ == "__main__":
    app.run(host='127.0.0.1')