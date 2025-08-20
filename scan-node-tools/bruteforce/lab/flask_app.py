from flask import Flask,request,make_response
app=Flask(__name__)
CSRF='token123'
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='GET':
        return """<form method=post>
          <input name=username><input name=password>
          <input name=csrf value='%s'>
        </form>""" % CSRF, 200
    u=request.form.get('username',''); p=request.form.get('password',''); c=request.form.get('csrf','')
    if c!=CSRF: return 'invalid csrf',403
    if u=='dev' and p=='Summer2025!':
        resp=make_response('',302); resp.headers['Location']='/dashboard'; resp.set_cookie('session','ok'); return resp
    return 'Invalid',200
@app.route('/dashboard')
def dash(): return 'ok',200
app.run(host='0.0.0.0',port=8080)
