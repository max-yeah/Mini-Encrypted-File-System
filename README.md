# CMPT-785-miniEFS
Except for openssl, please also make sure jsoncpp is installed before you compile the code
```bash
sudo apt install libjsoncpp-dev
```


Compile and prepare the binary:

```bash
cd /your-path-to/CMPT-785-miniEFS

g++ main.cpp -o fileserver -lcrypto -ljsoncpp

chmod +x fileserver
```



Run the fileserver binary:

```bash
./fileserver key_name
```

<br>

Tree structure of the files and encrypted filesystem

(The random numbers appear in private keys are made up for demo purpose)

![Tree structure](https://user-images.githubusercontent.com/26541990/219998278-e29e85cb-1196-4f06-87dd-e1716cec621d.png)
