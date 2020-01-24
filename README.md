# sshflex
Kubernetes flexvolume driver allowing use of sshfs mounted volumes.

## Status

Basic functionality is implemented and it's already used in testing scenarios, production-grade testing and unittests are missing yet, so use with caution.

## Deploy
```
$ kubectl create ns sshflex
$ kubectl apply -f ./sshflex-ds.yaml
```

## Acknowledgements

This project is kindly sponsored by [Nect](https://nect.com)

## License

Licensed under [MIT](./LICENSE).