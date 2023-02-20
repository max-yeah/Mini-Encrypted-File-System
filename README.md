# CMPT-785-miniEFS

Compile and prepare the binary:

```bash
cd /your-path-to/CMPT-785-miniEFS

g++ main.cpp -o fileserver -lcrypto

chmod +x fileserver
```



Run the fileserver binary:

```bash
./fileserver key_name
```

<br>

Tree structure of the files and encrypted filesystem

(The random numbers appear in private keys are made up for demo purpose)

![Tree structure](https://user-images.githubusercontent.com/26541990/219987892-ca6fe9d9-4531-42de-b08c-916c1a98e83f.png)
