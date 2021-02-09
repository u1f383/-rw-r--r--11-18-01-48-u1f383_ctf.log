FROM ubuntu:focal
MAINTAINER kruztw

RUN apt-get update
RUN apt-get install xinetd -y
RUN useradd -m bugggy
RUN chown -R root:root /home/bugggy
RUN chmod -R 755 /home/bugggy

CMD ["/usr/sbin/xinetd","-dontfork"]
