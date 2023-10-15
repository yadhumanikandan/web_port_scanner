from flask import Flask, render_template, redirect, url_for, request, session
from scan import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash




app = Flask(__name__)
app.secret_key = "laskdhflasdfhaklsdfj"  

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(1000))

    def __init__(self, name, password):
        self.name = name
        self.password = password

@app.route('/')
def index():
    return redirect(url_for("login"))


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method=="POST":
        exist = users.query.filter_by(name = request.form["username"]).first()
        if exist == None:
            rec = users(request.form["username"], generate_password_hash(request.form["pswrd"]))
            db.session.add(rec)
            db.session.commit()
            session["user"] = request.form["username"]
            return redirect(url_for("scan"))          
        else:
            return redirect(url_for("login"))
    else:
        return render_template("register.html")



@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method=="POST":
        obj = users.query.filter_by(name = request.form["username"]).first()
        if obj:
            if (obj.name == request.form["username"]) and (check_password_hash(obj.password, request.form["pswrd"])):
                session["user"] = request.form["username"]
                return redirect(url_for("scan"))
            else:
                return render_template("login.html")
        else:
            return redirect(url_for("register"))
    else:
        if "user" in session:
            return redirect(url_for("scan"))
        else:
            return render_template("login.html")
    


@app.route('/scan', methods=["POST", "GET"])
def scan():
    if request.method == "POST":
        hostname = request.form["host"]
        
        # print(hostname)
        open_ports, whoisinfo, nslookup1, nslookup2 = scanPorts(hostname)
        # print(open_ports)
        
        return render_template("result.html", portsh=open_ports, whoisinfo1=whoisinfo, hostname1=hostname, nsl1 = nslookup1, nsl2 = nslookup2)
    else:
        return render_template("scan.html")
    

@app.route('/logout')
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))
    


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run()
    