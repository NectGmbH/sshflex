FROM busybox
WORKDIR .

COPY ./sshflex /sshflex
COPY ./deploy.sh /deploy.sh

CMD /bin/sh /deploy.sh