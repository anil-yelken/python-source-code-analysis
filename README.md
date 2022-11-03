# Python Source Code Analysis

You can access vulnerable web applications written in Python from the links below.

[OWASP Vulnerable Flask App](https://owasp.org/www-project-vulnerable-flask-app/)

[Vulnerable Flask App](https://github.com/anil-yelken/Vulnerable-Flask-App)

[Vulnerable SOAP Service](https://github.com/anil-yelken/Vulnerable-Soap-Service)

## SQL Injection

The SQL injection vulnerability occurred because the parametric query was not used:

cur.execute("select * from test where username = '%s'" % name)

## XSS/HTML Injection

XSS and HTML Injection vulnerability occurs as a result of screen suppression by combining the output with the "Welcome" statement without input control.

```python
@app.route("/welcome2/<string:name>")
def welcome2(name):
    data="Welcome "+name
    return data
```

## SSTI

The SSTI vulnerability occurred because the person did not check the input in the template he wrote:

```python
@app.route("/welcome2/<string:name>")
def welcome2(name):
    data="Welcome "+name
    return data
```

```python
@app.route("/hello")
def hello_ssti():
    if request.args.get('name'):
        name = request.args.get('name')
        template = f'''<div>
        <h1>Hello</h1>
        {name}
</div>
'''
		return render_template_string(template)
```
    
## Command Injection

In the command injection vulnerability, the input received from the user is run with the subprocess module without any control.

```python
@app.route("/get_users")
def get_users():
    try:
        hostname = request.args.get('hostname')
        command = "dig " + hostname
        data = subprocess.check_output(command, shell=True)
        return data
    except:
        data = str(hostname) + " username didn't found"
        return data
```

```python
    @rpc( _returns=String)
    def get_log(ctx):
        try:
            command="cat soap_server.log"
            data=subprocess.check_output(command,shell=True)
            return(str(data))
        except:
            return("Command didn't run")
```

## Information Disclosure

Since every transaction made in the application is logged, critical information will occur in the logs.

```python
@app.route("/get_log/")
def get_log():
    try:
        command="cat restapi.log"
        data=subprocess.check_output(command,shell=True)
        return data
    except:
    	pass
```

```python
    @rpc( _returns=String)
    def get_log(ctx):
        try:
            command="cat soap_server.log"
            data=subprocess.check_output(command,shell=True)
            return(str(data))
        except:
            return("Command didn't run")
```

## LFI

Since the control of the input received with the filename parameter with the GET method is not provided, the files in the system are read, thus LFI vulnerability occurs.

```python
@app.route("/read_file")
def read_file():
    filename = request.args.get('filename')
    file = open(filename, "r")
    data = file.read()
    file.close()
    return jsonify(data=data),200
```

```python
    @rpc(String, _returns=String)
    def read_file(ctx,file):
        file = open(file, "r")
        data = file.read()
        file.close()
        return(data)
```
        
## Deserilization       

For deserialization vulnerability with Python, pickle.loads statement can be searched in the source code.

data=pickle.loads(received_data)

## DOS

DOS vulnerability occurs as a result of searching the username and password information obtained from the user with the GET method, with regex.

```python
@app.route("/user_pass_control")
def user_pass_control():
    import re
    username=request.form.get("username")
    password=request.form.get("password")
    if re.search(username,password):
        return jsonify(data="Password include username"), 200
    else:
        return jsonify(data="Password doesn't include username"), 200
```

## File Upload

Since the file received from the user does not have size, extension, Content-Type control, the selected file is uploaded directly to the system.

```python
@app.route('/upload', methods = ['GET','POST'])
def uploadfile():
   import os
   if request.method == 'POST':
      f = request.files['file']
      filename=secure_filename(f.filename)
      f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
      return 'File uploaded successfully'
   else:
      return '''
<html>
   <body>
      <form  method = "POST"  enctype = "multipart/form-data">
         <input type = "file" name = "file" />
         <input type = "submit"/>
      </form>   
   </body>
</html>
      '''
```
      
## Improper Output Neutralization for Logs

With the Improper Output Neutralization for Logs vulnerability, the attacker can understand that any data can be written to the logs and can inject malicious code or cause the logs to be displayed incorrectly.

```python
@app.route('/logs')
def ImproperOutputNeutralizationforLogs():
    data = request.args.get('data')
    import logging
    logging.basicConfig(filename="restapi.log", filemode='w', level=logging.DEBUG)
    logging.debug(data)
    return jsonify(data="Logging ok"), 200
```
