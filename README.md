# sshflex
Kubernetes flexvolume driver allowing use of sshfs mounted volumes.
Optionally, it also can encrypt/decrypt the remote storage using [gocryptfs](https://github.com/rfjakob/gocryptfs).

## Status

Basic functionality is implemented and it's already used in testing scenarios, production-grade testing and unittests are missing yet, so use with caution.

## TODO

* Support for key auth
* Add way to provide host fingerprint

## Deploy
sshfs (and if encryption is used gocryptfs) have to be installed on the nodes. After that the flexvolume driver can be deployed using the daemonset resource:
```
$ kubectl create ns sshflex
$ kubectl apply -f ./sshflex-ds.yaml
```

## Example
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example
  namespace: sshflex
type: 'nect.com/sshflex'
stringData:
  password: 'SomeVerySecretSSHPassword'
  encryptionPassphrase: 'SomeEvenMoreSecretPassphraseUsedForEncryption' # Optional
---
apiVersion: v1
kind: Pod
metadata:
  name: example
  namespace: sshflex
spec:
  containers:
  - name: busybox
    image: busybox
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 60; done;" ]
    volumeMounts:
    - name: test
      mountPath: /data
      subPath: decrypted/ # Optional, when encrypt=true is set, the encrypted files are at encrypted/, the decrypted ones are at decrypted/
    ports:
    - containerPort: 80
  volumes:
  - name: test
    flexVolume:
      driver: "nect.com/sshflex"
      secretRef:
        name: example
      options:
        host: 'some-host.org'
        port: '22'
        path: './some/remote/path/'
        user: 'username'
        encrypt: 'true' # Optional, decrypts the remotehost using gocryptfs
```

## Acknowledgements

This project is kindly sponsored by [Nect](https://nect.com)

## License

Licensed under [MIT](./LICENSE).