from flask import Flask, render_template, redirect, url_for, request, session, jsonify,flash
import requests
import unicodedata
import json, os

app = Flask(__name__)
app.config['SECRET_KEY'] = '\x17H\xb4\x1d\xa4\xa59VC\xc7\xe2d;O\xb1\xb9\xb4\x04\xdeM#\x8d\x9e\x03'


@app.route('/log')
def hell():
    session.clear()
    return render_template('firstview.html')


@app.route('/show')
def show():
    session.clear()
    return render_template('show.html')


@app.route('/')
def logout():
    message = " "

    session.clear()

    return render_template('login.html', message=message)


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route('/sign_out')
def sign_out():
    session.pop('dashboard', None)
    return redirect(url_for('dashboard'))


token_ = ''


def keep_token(gettoken, getname):
    global token_,username
    token_ = gettoken
    username = getname

    return gettoken


@app.route('/dashboard')
def dashboard_ww():
    session.clear()
    return redirect('/')


@app.route('/dashboard', methods=['POST'])
def dashboard():
    global ff
    email = None

    headers = {'Accept': 'application/json', 'Content-Type' : 'application/json'}

    # connect to API and log in
    info = requests.post('http://localhost:5000/login', data=json.dumps(request.form), headers=headers)

    ff = info.text
    ww = info.text

    #   checking if username and password is correct
    if ww != 'Could not verify':

            info = unicodedata.normalize('NFKD', info.text).encode('ascii','ignore')
            info = json.loads(info)
            name = info['admin']
            token = info['token']

            user_name = info['username']
            keep_token(gettoken=token,getname=user_name)

            if name == 1:
                #  for admin
                user_name = info['username']

                # get all client in the db
                info = requests.get('http://localhost:5000/allclients?token='+token_)

                info = unicodedata.normalize('NFKD', info.text).encode('ascii','ignore')
                data = json.loads(info)

                # get all users in the db
                info = requests.get('http://localhost:5000/user?token='+token_)

                info = unicodedata.normalize('NFKD', info.text).encode('ascii','ignore')
                data2 = json.loads(info)

                # session.clear()
                session['logged_in'] = True
                return render_template('show.html', info=data, info2=data2, mimetype='text/html', user=user_name)

            else:
                # for ordinary or sub users
                info = requests.get('http://localhost:5000/allclients?token='+token_)
                info = unicodedata.normalize('NFKD', info.text).encode('ascii', 'ignore')
                data = json.loads(info)

                # session.clear()
                session['logged_in'] = True
                flash('you were logged in')
                return render_template('otheruserspage.html', info=data, mimetype='text/html', user=username)

    else:
        #  return to this page if password is incorrect
        flash('Username or Password Incorrect, Check and Try Again')
        return render_template('login.html')


@app.route('/createuser', methods=['POST'])
def createuser():

    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    # create a user
    requests.post('http://localhost:5000/user?token='+token_, data=json.dumps(request.form), headers=headers)

    info = requests.get('http://localhost:5000/allclients?token='+token_)

    # if creating a user is successful
    if 'clients' in info.text:
        info = unicodedata.normalize('NFKD', info.text).encode('ascii', 'ignore')
        data = json.loads(info)

        info = requests.get('http://localhost:5000/user?token='+token_)
        info = unicodedata.normalize('NFKD', info.text).encode('ascii', 'ignore')
        data2 = json.loads(info)

        flash("User Created Successfully")

        # session.clear()

        return render_template('show.html', info=data, info2=data2, mimetype='text/html', user=username)
    else:
        # user creation is not successful
        message = "Token Has Expire, Please Login Again"
        return render_template('login.html', message2=message)


@app.route('/authuser', methods=['POST'])
def authuser():

    global ff
    email = None
    tt = json.dumps(request.form)
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    # get token and login
    info = requests.post('http://localhost:5000/login', data=json.dumps(request.form), headers=headers)

    ff = info.text
    ww = info.text

    # if username and password is correct and token is generated
    if ww != 'Could not verify':
        info = unicodedata.normalize('NFKD', info.text).encode('ascii', 'ignore')
        info = json.loads(info)
        name = info['admin']

        #  for admin
        if name == 1:
            token = info['token']
            user_name = info['username']
            keep_token(gettoken=token, getname=user_name)
            info = requests.get('http://localhost:5000/allclients?token='+token_)
            info = unicodedata.normalize('NFKD', info.text).encode('ascii', 'ignore')
            data = json.loads(info)

            # session.clear()
            return render_template('create.html', info=data, mimetype='text/html', user=user_name)

        else:
            session.clear()
            return render_template('loginpage.html')

    else:
        flash('Username or Password Incorrect, Check and Try Again')
        return render_template('login.html')


@app.route('/deleteuser/<public_id>')
def delete_one_user(public_id):
    info = requests.get('http://localhost:5000/allclients/<public_id>?token='+token_)

    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=67)