FROM centos 

VOLUME /dgt

WORKDIR /tmp

RUN yum update -y;yum clean all \
    && yum -y install gcc libffi-devel python-devel openssl-devel wget openssl telnet net-tools mail mailx postfix sudo cronie \
    && yum -y install java-1.8.0-openjdk \
    && wget -q https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py \
    && python /tmp/get-pip.py \
    && pip install --upgrade pip \
    && pip install docker docker-py cryptography pem \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /*.tgz \
    && echo "relayhost = relay.apple.com" >> /etc/postfix/main.cf \
    && rpm -ivh ftp://rpmfind.net/linux/centos/6.9/os/x86_64/Packages/nc-1.84-24.el6.x86_64.rpm \
    && rm -rf /tmp/*

RUN gpg --keyserver pool.sks-keyservers.net --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    && curl -o /usr/local/bin/gosu -SL "https://github.com/tianon/gosu/releases/download/1.2/gosu-amd64" \
    && curl -o /usr/local/bin/gosu.asc -SL "https://github.com/tianon/gosu/releases/download/1.2/gosu-amd64.asc" \
    && gpg --verify /usr/local/bin/gosu.asc \
    && rm /usr/local/bin/gosu.asc \
    && rm -r /root/.gnupg/ \
    && chmod +sx /usr/local/bin/gosu

WORKDIR /tmp
RUN  curl -sSL -O https://get.docker.com/builds/Linux/x86_64/docker-1.12.6.tgz; \
 tar zxf docker-1.12.6.tgz; \
 mkdir -p /usr/local/bin/; \
 mv $(find -name 'docker') /usr/local/bin/; \
 chmod +x /usr/local/bin/docker; \
 rm -rf /var/lib/apt/lists/*; \
 rm -rf /*.tgz


RUN echo "ALL	ALL=(ALL:ALL)	NOPASSWD:ALL " >> /etc/sudoers

ADD system.py /dgt
ADD config_verify.py /dgt
