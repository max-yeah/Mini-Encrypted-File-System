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

