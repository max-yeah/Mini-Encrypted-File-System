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

Tree-structure overview of the files and encrypted filesystem

(The random numbers appear in private keys are made up for demonstration purpose)

![CleanShot 2023-02-26 at 10 05 12](https://user-images.githubusercontent.com/26541990/221428172-46d32f98-f0d5-498b-a119-b07e1ba3f388.png)


