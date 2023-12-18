# KDC Integration Test Instance for SUB.TEST.GOKRB5

DO NOT USE THIS CONTAINER FOR ANY PRODUCTION USE!!!

To run:
```bash
docker run -v /etc/localtime:/etc/localtime:ro -p 288:88 -p 188:88/udp --rm --name gokrb5-kdc-sub jcmturner/gokrb5:kdc-sub &
```

To build:
```bash
docker build -t jcmturner/gokrb5:kdc-sub --force-rm=true --rm=true .
docker push jcmturner/gokrb5:kdc-sub
```


